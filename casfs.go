// Package casfs is a content-addressed file store on top of any S3-compatible
// bucket, with lazy chunked reads and a shared on-disk chunk cache.
//
// AN ARTIFACT IS SELF-AUTHENTICATING AT CHUNK GRANULARITY. Its name is
// sha256 of its own per-chunk hash list, which the stored object carries in a
// tail past the content (see chunked.go for the format). One small read proves
// the list against the name, and every 4MB chunk then verifies positionally
// against it BEFORE it is cached or served. That is what makes the bucket
// untrusted infrastructure whose only remaining move is to withhold bytes.
// The tail is casfs's metadata and is invisible above this package: a File is
// L logical bytes and nothing else.
//
// Uploads are idempotent and two writers racing on the same content write
// identical bytes, because both name it the same way.
//
// Durability lives entirely in the filesystem. A caller adds content by
// atomically renaming a file named after its hex sha256 into the store's spool
// directory. That rename is the registration; there is no handshake to lose and
// no other state anywhere. Sync scans the spool and uploads whatever the bucket
// does not already have. The durable copy is the spool file or the bucket,
// never the chunk cache, which is disposable by construction.
//
// WRITES NEVER TOUCH THE NETWORK. That holds for the one mutable name too:
// SetPointer writes the value under the spool and returns, and Sync reconciles
// it to the bucket after that pass's content. Reads are local first and only
// go to the bucket for what is genuinely not here, where a failure is an
// honest error rather than a guess.
//
// There is exactly one read path: the chunk cache, a shared directory of plain
// 4MB files in per-window subdirectories (see cache.go). ReadAt preads out of
// it and copies; View maps it, one mapping per chunk, for the ranges a
// consumer keeps forever. Nothing is pinned, nothing is punched, and no
// process has to agree with any other about what is cached.
//
// Linux only: the window cache uses statfs and mmap with no portable fallback.
package casfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

const (
	DefaultChunkSize = 4 << 20
	// pointerDir holds pointer values inside the spool directory. The leading
	// dot is what keeps it out of the content-address space: a hash name is 64
	// hex characters, so no artifact can ever be called this.
	pointerDir = ".pointers"
)

type Config struct {
	Endpoint  string // scheme://host[:port], path-style, no bucket
	Region    string // default: the AWS default chain's region, else "auto" (R2; MinIO ignores it)
	Bucket    string
	Prefix    string // optional key prefix, used verbatim (include a trailing "/")
	AccessKey string
	SecretKey string

	// Credentials, when set, resolves the keys for every request, so a
	// provider that refreshes (SSO, instance role) keeps working. It is only
	// consulted when AccessKey is empty: static keys win. With neither, casfs
	// falls back to the AWS SDK's default chain (env, shared config, SSO,
	// instance role), which also supplies Region when Region is empty.
	Credentials aws.CredentialsProvider

	SpoolDir  string // hash-named files awaiting upload, created if missing
	CacheDir  string // the window tree of chunk files, created if missing
	ChunkSize int64  // chunk granularity, default DefaultChunkSize

	// Namespace is this store's OWNER inside the cache tree
	// (<CacheDir>/<window>/<Namespace>/...). Several owners share one cache
	// root and one set of windows; the level exists so a human can see whose
	// chunks are whose, wipe one owner with `rm -r <CacheDir>/*/<Namespace>`,
	// and have the one-writer-per-owner invariant enforced by the tree rather
	// than by a convention. It must be a single path element. Default
	// "default".
	Namespace string

	// CacheMinFree is the ADMISSION WATERMARK in absolute bytes: while statfs
	// reports at least this much available, fills are cached; below it they
	// are served from memory and dropped. Zero means 5% of the filesystem,
	// i.e. cache up to 95% full.
	//
	// It is bytes and not a fraction because the cache does not own the
	// filesystem: what matters to everything else on the box is how much room
	// is left, not what share of it casfs took.
	CacheMinFree int64

	// CacheMaxAge expires whole windows by name regardless of disk fill. Zero
	// means DefaultMaxAge.
	CacheMaxAge time.Duration

	HTTPClient *http.Client // optional

	// free is the statfs seam, so a test can put the store over its watermark
	// without filling a disk.
	free func(string) (int64, error)
}

func nchunks(size, cs int64) int64 { return (size + cs - 1) / cs }

// chunkLen is the length of chunk i, short for the last one.
func chunkLen(size, cs, i int64) int64 { return min(cs, size-i*cs) }

type Store struct {
	cfg Config
	s3  *s3

	mu sync.Mutex
	// arts holds each opened artifact's IDENTITY: its hash list, its logical
	// length and its stored size. Resident for the store's life once read, at
	// 32 bytes per 4MB (76KB for a 9.5 GB epoch, ~5MB for a whole mainnet
	// corpus), because every chunk fill has to check against it.
	arts map[string]*artifact
	// confirmed is a cache, never the source of truth. Losing it costs a HEAD.
	confirmed map[string]bool
	// where is this process's chunk -> window hint, rebuilt by one name-only
	// walk at startup. A stale entry costs an ENOENT and a refetch.
	where  map[string]string
	flight map[string]*flight

	// ptrMu guards the pointer files and dirty together, so a SetPointer
	// racing a reconcile cannot have its value uploaded and then released
	// under it. It is separate from mu only to keep pointer IO off the lock
	// every chunk read takes.
	ptrMu sync.Mutex
	// dirty is the pointer names still spooled, i.e. whose value the bucket
	// may not have yet. Seeded from disk at New, added to by SetPointer,
	// drained by Sync as it uploads and releases each one.
	dirty map[string]bool

	stop chan struct{}
	done chan struct{}

	evictions   atomic.Uint64
	refusals    atomic.Uint64
	fillErrors  atomic.Uint64
	evictErrors atomic.Uint64
	lastErr     atomic.Value // string: the last cache-plane failure
	horizon     atomic.Value // string: the last window dropped
}

func New(cfg Config) (*Store, error) {
	switch {
	case cfg.Endpoint == "":
		return nil, errors.New("casfs: Endpoint is required")
	case cfg.Bucket == "":
		return nil, errors.New("casfs: Bucket is required")
	case cfg.SpoolDir == "":
		return nil, errors.New("casfs: SpoolDir is required")
	case cfg.CacheDir == "":
		return nil, errors.New("casfs: CacheDir is required")
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = DefaultChunkSize
	}
	if cfg.CacheMaxAge <= 0 {
		cfg.CacheMaxAge = DefaultMaxAge
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}
	// It names a directory this store creates and deletes inside, so it may
	// not be a path: a caller passing a data directory's name must not be able
	// to walk out of the cache root with it.
	switch clean := filepath.Clean(cfg.Namespace); {
	case clean != cfg.Namespace, clean == ".", clean == "..", clean == string(filepath.Separator),
		clean != filepath.Base(clean):
		return nil, fmt.Errorf("casfs: Namespace %q is not a single path element", cfg.Namespace)
	}
	if cfg.free == nil {
		cfg.free = freeBytes
	}
	switch {
	case cfg.AccessKey != "":
		cfg.Credentials = credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")
	case cfg.Credentials == nil:
		awscfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, fmt.Errorf("casfs: no AccessKey and no default AWS credentials: %w", err)
		}
		cfg.Credentials = awscfg.Credentials
		if cfg.Region == "" {
			cfg.Region = awscfg.Region
		}
	}
	if cfg.Region == "" {
		cfg.Region = "auto"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Minute}
	}
	for _, dir := range []string{cfg.SpoolDir, cfg.CacheDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	if cfg.CacheMinFree <= 0 {
		total, err := totalBytes(cfg.CacheDir)
		if err != nil {
			return nil, err
		}
		cfg.CacheMinFree = total * (100 - defaultFullPct) / 100
	}
	s := &Store{
		cfg: cfg,
		s3: &s3{
			endpoint: strings.TrimSuffix(cfg.Endpoint, "/"),
			region:   cfg.Region,
			bucket:   cfg.Bucket,
			creds:    cfg.Credentials,
			http:     cfg.HTTPClient,
		},
		arts:      map[string]*artifact{},
		confirmed: map[string]bool{},
		where:     map[string]string{},
		flight:    map[string]*flight{},
		dirty:     map[string]bool{},
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	if err := s.scanCache(); err != nil {
		return nil, err
	}
	if err := s.scanPointers(); err != nil {
		return nil, err
	}
	go s.worker()
	return s, nil
}

func validHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (s *Store) key(hash string) string { return s.cfg.Prefix + hash }

// SpoolPath is where a file named after hash must land to be registered.
// Callers that produce content themselves can write next to it and rename onto
// this path; that rename is all the registration there is.
func (s *Store) SpoolPath(hash string) string {
	return filepath.Join(s.cfg.SpoolDir, hash)
}

// Close stops the eviction worker. NOTHING ELSE: the cache is a directory of
// finished files, so there is no flush to lose and no clean marker to keep, and
// a process killed with -9 leaves a cache the next start reads as it stands.
// Views handed out stay valid; they own their own mappings.
func (s *Store) Close() error {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	<-s.done
	return nil
}

// Put turns a local file into an artifact: it streams the file to build the
// chunk hash list, APPENDS the list and trailer to it, and renames it into the
// spool under sha256(list). The rename is atomic and is the entire
// registration, so a kill at any instant leaves either an untouched (if now
// tail-bearing) original or a correctly named spool file that the next Sync
// uploads. path must be on the same filesystem as SpoolDir.
//
// NOTHING IS HELD IN MEMORY but the list itself. A caller that streams its own
// artifact should use NewHasher directly, write the tail it returns, and do the
// rename itself; this is the convenience wrapper around exactly that.
func (s *Store) Put(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := NewHasher(s.cfg.ChunkSize)
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	name, tail, err := h.Finish()
	if err != nil {
		return "", err
	}
	// io.Copy left the offset at the end of the content, which is exactly
	// where the tail belongs.
	if _, err := f.Write(tail); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := os.Rename(path, s.SpoolPath(name)); err != nil {
		return "", fmt.Errorf("casfs: spool %s: %w", name, err)
	}
	return name, nil
}

// Sync scans the spool and uploads every file the bucket does not already have,
// then returns the hashes now confirmed present in the bucket. Failures are
// collected per file, so one bad entry does not stall the rest.
//
// CONTENT FIRST, POINTERS LAST, and only when the content went up cleanly: a
// pointer names content, so publishing it before its content would hand a
// bucket reader a dangling name. A pass that could not upload some artifact
// leaves every dirty pointer local and tries again next time.
//
// Call it after Put, on a ticker, at startup, whenever. It is the only thing
// that moves bytes out, and it is driven purely by what the spool directory
// and the local pointers contain.
func (s *Store) Sync() ([]string, error) {
	ents, err := os.ReadDir(s.cfg.SpoolDir)
	if err != nil {
		return nil, err
	}
	var done []string
	var errs []error
	for _, e := range ents {
		hash := e.Name()
		if e.IsDir() || !validHash(hash) {
			continue
		}
		if err := s.upload(hash); err != nil {
			errs = append(errs, err)
			continue
		}
		s.mu.Lock()
		s.confirmed[hash] = true
		s.mu.Unlock()
		done = append(done, hash)
	}
	if len(errs) == 0 {
		errs = append(errs, s.syncPointers())
	}
	return done, errors.Join(errs...)
}

// upload pushes one spool file, after ONE PASS over it that computes two
// things at once: the object digest the request signature commits to through
// x-amz-content-sha256, and the chunk hash list the NAME commits to. A file
// whose name lies about its contents is refused here, before a byte goes out.
//
// THE PRE-PASS IS NOT OPTIONAL ANY MORE, and it is what retired an old trap
// (Fuji, 2026-08-04). The name is no longer the object's own sha256, so the
// signature needs a digest that has to be computed anyway; and hashing THROUGH
// the upload instead meant a put that died early (expired token, dropped
// connection) produced a digest over a prefix and reported a perfectly intact
// file as corrupt. One sequential read against an upload that takes minutes
// buys both paths, single-PUT and multipart, the same check.
func (s *Store) upload(hash string) error {
	if size, err := s.s3.head(s.key(hash)); err == nil {
		// The HEAD short-circuit is what lets Release unlink the local durable
		// copy, so it must be sure the bucket holds THIS content. head returns
		// the size for free, and a size that differs is proof it does not (a
		// prefix pointing into another store's key space, a truncated object
		// from a killed multipart).
		fi, serr := os.Stat(s.SpoolPath(hash))
		if errors.Is(serr, fs.ErrNotExist) {
			return nil // released underneath us; nothing left to upload
		}
		if serr != nil {
			return serr
		}
		if fi.Size() != size {
			return fmt.Errorf("casfs: %s is already in the bucket at %d bytes but the spool file is %d, refusing to treat it as uploaded",
				hash, size, fi.Size())
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	f, err := os.Open(s.SpoolPath(hash))
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	digest, err := s.checkSpool(hash, f, fi.Size())
	if err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// Over 5 GiB a single PUT is refused outright (EntityTooLarge), which is
	// where a big epoch lands. Both roads send exactly the bytes checkSpool
	// just read, so THE NAME IS THE SAME EITHER WAY: the name is a function of
	// the content, never of how it went up.
	// LimitReader, not f itself: net/http CLOSES a request body that is an
	// io.ReadCloser, and the descriptor is still needed afterwards to see how
	// much the endpoint actually read.
	src := io.LimitReader(f, fi.Size())
	if fi.Size() > multipartThreshold {
		err = s.s3.putMultipart(s.key(hash), src, fi.Size())
	} else {
		err = s.s3.put(s.key(hash), src, fi.Size(), digest)
	}
	if err != nil {
		return err
	}
	// f's offset is exactly what the request consumed. A success on a short
	// read is the endpoint's bug, not the file's.
	read, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if read != fi.Size() {
		return fmt.Errorf("casfs: upload %s: endpoint accepted the put after reading %d of %d bytes", hash, read, fi.Size())
	}
	return nil
}

// checkSpool reads the whole spool file once and returns the hex sha256 of the
// STORED OBJECT (what SigV4 signs). On the way past it rebuilds the chunk hash
// list from the content and requires the file's own tail to match it byte for
// byte, which is the "the name is the integrity check" claim enforced at the
// only moment it can still stop bad bytes from spreading.
func (s *Store) checkSpool(hash string, f *os.File, stored int64) (string, error) {
	want, err := tailLen(stored, s.cfg.ChunkSize)
	if err != nil {
		return "", fmt.Errorf("casfs: spool file %s: %w", hash, err)
	}
	obj := sha256.New()
	lst := NewHasher(s.cfg.ChunkSize)
	if _, err := io.Copy(io.MultiWriter(obj, lst), io.LimitReader(f, stored-want)); err != nil {
		return "", err
	}
	tail := make([]byte, want)
	if _, err := io.ReadFull(f, tail); err != nil {
		return "", err
	}
	obj.Write(tail)
	name, mine, err := lst.Finish()
	if err != nil {
		return "", err
	}
	if name != hash {
		return "", fmt.Errorf("casfs: spool file %s holds content naming %s, refusing it", hash, name)
	}
	if !bytes.Equal(mine, tail) {
		return "", fmt.Errorf("casfs: spool file %s carries a tail that does not match its own content, refusing it", hash)
	}
	return hex.EncodeToString(obj.Sum(nil)), nil
}

// Release drops the spool file for hash. It refuses until the bucket is
// confirmed to hold the content, so a hash is never left unreadable.
//
// It stays deliberately dumb: no pre-warming of the cache. Whatever real
// traffic touched while the file was spool-resident is already sitting in the
// chunk cache and keeps serving from there, so the transition is invisible for
// the ranges anyone actually reads. Ranges nobody ever read are by definition
// cold, and copying gigabytes of them into the cache would only push out hot
// chunks belonging to other files. Those fall to ranged GETs on demand, which
// is the intent, not a gap.
func (s *Store) Release(hash string) error {
	s.mu.Lock()
	ok := s.confirmed[hash]
	s.mu.Unlock()
	if !ok {
		if _, err := s.s3.head(s.key(hash)); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("casfs: release %s: not uploaded yet", hash)
			}
			return err
		}
		s.mu.Lock()
		s.confirmed[hash] = true
		s.mu.Unlock()
	}
	if err := os.Remove(s.SpoolPath(hash)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// artifact is one stored object's IDENTITY: the hash list its name commits to,
// the LOGICAL length of the content (what every consumer sees), and the stored
// size including the metadata tail (what the bucket reports).
type artifact struct {
	hash   string
	stored int64
	size   int64
	list   []byte
}

// artifact resolves and caches an artifact's identity. Resident once read, so
// the tail is fetched at most once per artifact per process.
func (s *Store) artifact(hash string) (*artifact, error) {
	s.mu.Lock()
	a := s.arts[hash]
	s.mu.Unlock()
	if a != nil {
		return a, nil
	}
	a, err := s.readIdentity(hash)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.arts[hash] = a
	s.mu.Unlock()
	return a, nil
}

// readIdentity reads an artifact's tail from wherever the artifact is.
//
// LOCALLY the file is this node's own durable copy, landed by fsync+rename, so
// the tail is parsed for its structure and the name is not re-derived: nothing
// untrusted has touched those bytes, and upload re-derives it anyway before
// they can spread.
//
// FROM THE BUCKET the name binding is the whole point, so sha256(list) must
// equal the name before anything else happens. That read costs ONE ranged GET,
// which fetches the metadata tail AND THE LAST CONTENT CHUNK TOGETHER: the
// first thing every consumer here reads is a footer at the end of the content,
// and that chunk is a read this path was going to pay for anyway.
func (s *Store) readIdentity(hash string) (*artifact, error) {
	cs := s.cfg.ChunkSize
	if size, list, err := ReadTail(s.SpoolPath(hash), cs); err == nil {
		fi, err := os.Stat(s.SpoolPath(hash))
		if err != nil {
			return nil, err
		}
		return &artifact{hash: hash, stored: fi.Size(), size: size, list: list}, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	stored, err := s.s3.head(s.key(hash))
	if err != nil {
		return nil, err
	}
	want, err := tailLen(stored, cs)
	if err != nil {
		return nil, fmt.Errorf("casfs: %s: %w", hash, err)
	}
	// The tail length is derivable from the stored size alone, so the logical
	// length and the last chunk's offset are known before the read.
	last := nchunks(stored-want, cs) - 1
	off := stored - want
	if last >= 0 {
		off = last * cs
	}
	body, total, err := s.s3.get(s.key(hash), off, stored-off)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, stored-off)
	_, rerr := io.ReadFull(body, buf)
	body.Close()
	if rerr != nil {
		return nil, rerr
	}
	if total != stored {
		return nil, fmt.Errorf("casfs: %s: the bucket's object is %d bytes, the HEAD said %d", hash, total, stored)
	}
	size, list, err := parseTail(stored, cs, buf[int64(len(buf))-want:])
	if err != nil {
		return nil, fmt.Errorf("casfs: %s: %w", hash, err)
	}
	if err := checkName(hash, list); err != nil {
		return nil, err
	}
	if last >= 0 {
		chunk := buf[:int64(len(buf))-want]
		if err := VerifyChunk(hash, list, last, chunk); err != nil {
			return nil, err
		}
		s.admit(chunkName(hash, last), chunk)
	}
	return &artifact{hash: hash, stored: stored, size: size, list: list}, nil
}

// Open returns a reader for hash. The content must be in the spool or in the
// bucket. Over the bucket the first open of an artifact costs a HEAD plus one
// ranged read of its tail (and the last content chunk that shares that read);
// after that its identity is resident and reads are chunk fetches only.
func (s *Store) Open(hash string) (*File, error) {
	if !validHash(hash) {
		return nil, fmt.Errorf("casfs: open %q: not a hex sha256", hash)
	}
	a, err := s.artifact(hash)
	if err != nil {
		return nil, err
	}
	if f, err := os.Open(s.SpoolPath(hash)); err == nil {
		// The descriptor is held for the File's life, so a Release that unlinks
		// the spool file underneath does not disturb reads already going
		// through it.
		return &File{s: s, a: a, spool: f}, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return &File{s: s, a: a}, nil
}

// SetPointer writes a small mutable value at name. It is LOCAL AND
// SYNCHRONOUS AND NOTHING ELSE: the value lands durably under the spool by
// tmp+rename and the call returns without a single network byte.
//
// A pointer has EXACTLY THE SPOOL SEMANTICS OF CONTENT: the local file is the
// durable copy until Sync uploads it, Sync uploads it after the content of
// that same pass, and once the bucket confirms it the local file is deleted,
// the same release an artifact gets. A value overwritten several times before
// a reconcile uploads once, as its newest.
//
// Pointer names may not look like a content hash, so they can never collide
// with stored content.
func (s *Store) SetPointer(name, value string) error {
	if err := checkPointer(name); err != nil {
		return err
	}
	s.ptrMu.Lock()
	defer s.ptrMu.Unlock()
	if err := s.writePointer(name, value); err != nil {
		return err
	}
	s.dirty[name] = true
	return nil
}

// GetPointer reads a pointer, LOCAL FIRST: while the value is still spooled it
// is the freshest there is and reading it costs nothing and cannot fail on
// credentials. Once Sync has uploaded and released it, or on a store that
// never wrote it at all, the read goes to the bucket and the value is written
// back to the spool, so the next read (and the next process) is local again.
// The write-back is CLEAN, never dirty: re-uploading a value this store did
// not author could only put a stale pointer over a newer one.
//
// A bucket read that fails bubbles exactly as it comes, and a missing pointer
// returns an error wrapping fs.ErrNotExist. Nothing here ever invents a value.
func (s *Store) GetPointer(name string) (string, error) {
	if err := checkPointer(name); err != nil {
		return "", err
	}
	b, err := os.ReadFile(s.pointerPath(name))
	if err == nil {
		return string(b), nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	v, err := s.s3.getAll(s.cfg.Prefix + name)
	if err != nil {
		return "", err
	}
	s.ptrMu.Lock()
	defer s.ptrMu.Unlock()
	// A SetPointer that landed while the GET was in flight is newer than what
	// the bucket just handed back, so it stays.
	if _, err := os.Stat(s.pointerPath(name)); errors.Is(err, fs.ErrNotExist) {
		if err := s.writePointer(name, string(v)); err != nil {
			return "", err
		}
	}
	return string(v), nil
}

// pointerPath is where name's value lives while it is spooled: under the spool
// directory, in one whose leading dot keeps it out of the content-address
// space (Sync only ever looks at hash-named entries) and out of the chunk
// cache, which is a separate tree entirely. A name with slashes in it is a
// nested file, which is why this is a directory of its own rather than the
// spool root: a flat sibling of the artifacts could not hold one.
func (s *Store) pointerPath(name string) string {
	return filepath.Join(s.cfg.SpoolDir, pointerDir, filepath.FromSlash(name))
}

// writePointer lands a value by tmp+fsync+rename, so a kill leaves either the
// old value or the new one. Callers hold ptrMu.
//
// THE FSYNC IS THE DURABILITY, not the rename. Without it power loss can leave
// a renamed but zero-length file, and an empty pointer value is not obviously
// invalid to a reader: epochdb decodes one as "this chain has no epochs".
func (s *Store) writePointer(name, value string) error {
	p := s.pointerPath(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(p+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = f.WriteString(value)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(p + ".tmp")
		return err
	}
	return os.Rename(p+".tmp", p)
}

// scanPointers marks every pointer still spooled dirty, so a process that died
// between a SetPointer and a Sync still gets that value to the bucket. A
// pointer already uploaded is not here to be found: Sync deleted it.
func (s *Store) scanPointers() error {
	root := filepath.Join(s.cfg.SpoolDir, pointerDir)
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // no pointer has ever been written here
			}
			return err
		}
		if d.IsDir() || strings.HasSuffix(p, ".tmp") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		s.dirty[filepath.ToSlash(rel)] = true
		return nil
	})
}

// syncPointers uploads every spooled pointer and releases it. Sync calls it
// LAST and only when the content of the same pass went up cleanly, which is
// the whole ordering guarantee: a pointer becomes visible in the bucket only
// once the content it names is, so a consumer following one never lands on a
// missing object.
func (s *Store) syncPointers() error {
	s.ptrMu.Lock()
	names := make([]string, 0, len(s.dirty))
	for n := range s.dirty {
		names = append(names, n)
	}
	s.ptrMu.Unlock()

	var errs []error
	for _, name := range names {
		p := s.pointerPath(name)
		v, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		sum := sha256.Sum256(v)
		if err := s.s3.put(s.cfg.Prefix+name, strings.NewReader(string(v)), int64(len(v)), hex.EncodeToString(sum[:])); err != nil {
			errs = append(errs, err)
			continue
		}
		// Release only what was just uploaded: a SetPointer racing this pass
		// leaves its newer value spooled and dirty for the next one.
		s.ptrMu.Lock()
		if cur, err := os.ReadFile(p); err == nil && string(cur) == string(v) {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			} else {
				delete(s.dirty, name)
			}
		}
		s.ptrMu.Unlock()
	}
	return errors.Join(errs...)
}

func checkPointer(name string) error {
	if name == "" || strings.Contains(name, "//") || strings.HasPrefix(name, "/") {
		return fmt.Errorf("casfs: bad pointer name %q", name)
	}
	if validHash(name) {
		return fmt.Errorf("casfs: pointer name %q collides with the content-address space", name)
	}
	return nil
}

// File reads one stored object: ReadAt for the query path, View for the ranges
// a consumer keeps for its whole life. Close releases the spool mapping, if
// this artifact was still local when it was opened.
type File struct {
	s     *Store
	a     *artifact
	spool *os.File // non-nil while the artifact is still spool-resident

	mu sync.Mutex
	mm []byte // mapping of the spool file's CONTENT, built by the first View
}

// Size is the artifact's LOGICAL length: the content, without the hash list and
// trailer casfs keeps past it. No consumer ever sees those, which is why a
// footer-last format seeks from Size rather than from the file's end.
func (f *File) Size() int64 { return f.a.size }

// Close releases the spool mapping and descriptor. CLOSE EVERY VIEW FIRST: a
// view of a spool-resident artifact is a window onto the mapping this owns, so
// touching one afterwards is a segfault rather than an error return. A view
// over the chunk cache owns its own mappings and does not care.
func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	unmap(f.mm)
	f.mm = nil
	if f.spool != nil {
		err := f.spool.Close()
		f.spool = nil
		return err
	}
	return nil
}

func (f *File) bounds(off, n int64) error {
	if off < 0 || n < 0 || off+n > f.a.size {
		return fmt.Errorf("casfs: range [%d,%d) outside a %d byte object", off, off+n, f.a.size)
	}
	return nil
}

// ReadAt is the QUERY PATH: open the chunk file, pread, copy, done. No mapping
// and no pinning, so a chunk evicted a microsecond later cannot turn bytes
// already handed back into zeros.
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("casfs: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.a.size {
		return 0, io.EOF
	}
	if f.spool != nil {
		// Clamped to the CONTENT: past it lies casfs's own metadata, which a
		// consumer must never be handed as if it were the file's bytes.
		if int64(len(p)) > f.a.size-off {
			n, err := f.spool.ReadAt(p[:f.a.size-off], off)
			if err == nil {
				err = io.EOF
			}
			return n, err
		}
		return f.spool.ReadAt(p, off)
	}
	cs := f.s.cfg.ChunkSize
	n := 0
	for n < len(p) && off+int64(n) < f.a.size {
		cur := off + int64(n)
		idx := cur / cs
		// Clamp to the chunk: past its end lies a different file.
		want := min(int64(len(p)-n), chunkLen(f.a.size, cs, idx)-cur%cs)
		m, err := f.s.readChunk(f.a, idx, p[n:n+int(want)], cur%cs)
		n += m
		if err != nil {
			return n, err
		}
		if m == 0 {
			return n, io.ErrUnexpectedEOF
		}
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// readChunk preads out of one cached chunk, fetching it first if it is not
// here. A cached file that reads short is treated as a miss and refetched: it
// cannot happen (fills fsync before the rename) and costs one GET if it does.
func (s *Store) readChunk(a *artifact, idx int64, p []byte, off int64) (int, error) {
	name := chunkName(a.hash, idx)
	cf, err := s.openChunk(name)
	if err != nil {
		return 0, err
	}
	if cf != nil {
		n, err := cf.ReadAt(p, off)
		cf.Close()
		if err == nil {
			return n, nil
		}
	}
	b, err := s.fetch(a, idx)
	if err != nil {
		return 0, err
	}
	if off >= int64(len(b)) {
		return 0, io.ErrUnexpectedEOF
	}
	return copy(p, b[off:]), nil
}

// View returns a long-lived read-only window onto [off, off+n), one mapping per
// chunk it covers, filling whatever is missing first. Hold it only for ranges
// that are read for the process's life: an unlinked-but-mapped chunk keeps its
// blocks allocated, so the ghost disk a consumer can hold is exactly the size
// of its resident set.
//
// Everything else should use ReadAt.
func (f *File) View(off, n int64) (*View, error) {
	if err := f.bounds(off, n); err != nil {
		return nil, err
	}
	if n == 0 {
		return &View{}, nil
	}
	if f.spool != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.mm == nil {
			// The CONTENT only: the tail is not part of the logical file.
			b, err := mapFile(f.spool, f.a.size)
			if err != nil {
				return nil, err
			}
			f.mm = b
		}
		// One mapping of the spool file serves every view of it, and Close
		// owns it, so ViewOf is handed a window it must not unmap.
		return ViewOf(f.mm[off : off+n]), nil
	}
	cs := f.s.cfg.ChunkSize
	v := &View{first: off % cs, n: n, cs: cs}
	for i := off / cs; i <= (off+n-1)/cs; i++ {
		b, mapped, err := f.s.chunkView(f.a, i)
		if err != nil {
			v.Close()
			return nil, err
		}
		v.parts = append(v.parts, b)
		if mapped {
			v.mmaps = append(v.mmaps, b)
		}
	}
	return v, nil
}

// chunkView hands back one chunk's bytes for the life of a View: a mapping of
// the cache file when it is there, and the fetched bytes on the heap when the
// disk was over the watermark and refused them.
func (s *Store) chunkView(a *artifact, idx int64) ([]byte, bool, error) {
	name := chunkName(a.hash, idx)
	n := chunkLen(a.size, s.cfg.ChunkSize, idx)
	if cf, err := s.openChunk(name); err != nil {
		return nil, false, err
	} else if cf != nil {
		b, err := mapFile(cf, n)
		cf.Close()
		if err == nil {
			return b, true, nil
		}
	}
	b, err := s.fetch(a, idx)
	if err != nil {
		return nil, false, err
	}
	if cf, err := s.openChunk(name); err == nil && cf != nil {
		m, err := mapFile(cf, n)
		cf.Close()
		if err == nil {
			return m, true, nil
		}
	}
	return b, false, nil
}
