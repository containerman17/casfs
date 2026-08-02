// Package casfs is a content-addressed file store on top of any S3-compatible
// bucket, with lazy chunked reads and a byte-capped local disk cache.
//
// Objects are stored whole under their hex sha256, so uploads are idempotent
// and two writers racing on the same content write identical bytes.
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
// There is exactly one read path: the chunk cache. Each artifact is cached as
// ONE SPARSE FILE of its full size, and a chunk is filled by pwriting it at its
// true offset, from the spool file when it is still there or by a ranged GET
// when it is not. Presence is the kernel's extent map, read back with
// SEEK_DATA; eviction is FALLOC_FL_PUNCH_HOLE on one chunk's range. Because the
// file is whole and correctly sized, a consumer can mmap it and let the kernel
// tier RAM to SSD while casfs tiers SSD to S3, which is what File.View hands
// out.
//
// Linux only: the sparse layout has no portable analogue and no fallback.
package casfs

import (
	"container/list"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

const (
	DefaultChunkSize = 4 << 20
	// DefaultTouchInterval bounds how stale the restart LRU seed can be. See
	// Config.TouchInterval.
	DefaultTouchInterval = time.Hour
	// cleanMarker is written by Close and removed by New. Its absence means the
	// last process died without flushing, so the cache is wiped. See the crash
	// safety section of the README.
	cleanMarker = ".clean"
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

	SpoolDir   string // hash-named files awaiting upload, created if missing
	CacheDir   string // one sparse file per artifact, created if missing
	CacheBytes int64  // hard cap on cached chunk bytes on disk
	ChunkSize  int64  // chunk granularity, default DefaultChunkSize

	// TouchInterval throttles how often a cache hit refreshes an artifact's
	// mtime. The startup LRU seed reads mtime, so without this an artifact
	// fetched long ago but read constantly looks ancient after a restart and
	// gets evicted first. Zero means DefaultTouchInterval, negative disables
	// touching entirely.
	TouchInterval time.Duration

	HTTPClient *http.Client // optional
}

// chunk is one cache entry. The LRU stays keyed by (hash, index) even though
// the bytes now live inside a shared sparse file, because that is still the
// granularity of a fill and of a punch.
type chunk struct {
	hash  string
	idx   int64
	bytes int64
}

// artifact is the per-hash cache state: the sparse file, which chunks of it are
// present, and which chunks may not be punched right now.
type artifact struct {
	hash string
	size int64
	// f is assigned under Store.mu and never reassigned once set, so the read
	// and write paths may use it without holding the lock. Only Close clears
	// it, and using a Store after Close is a caller bug.
	f *os.File // O_RDWR on the sparse file, opened on demand

	present []uint64        // one bit per chunk
	pins    map[int64]int32 // chunk index -> live pins, absent means zero
	mtime   time.Time       // last mtime written to the file, not read back
}

func (a *artifact) has(i int64) bool    { return a.present[i/64]&(1<<(i%64)) != 0 }
func (a *artifact) set(i int64)         { a.present[i/64] |= 1 << (i % 64) }
func (a *artifact) clear(i int64)       { a.present[i/64] &^= 1 << (i % 64) }
func (a *artifact) pinned(i int64) bool { return a.pins[i] > 0 }

func nchunks(size, cs int64) int64 { return (size + cs - 1) / cs }

// chunkLen is the length of chunk i, short for the last one.
func chunkLen(size, cs, i int64) int64 { return min(cs, size-i*cs) }

type Store struct {
	cfg Config
	s3  *s3

	mu sync.Mutex
	// sizes and confirmed are caches, never the source of truth. Losing them
	// costs one HEAD each.
	sizes     map[string]int64
	confirmed map[string]bool
	arts      map[string]*artifact
	lru       *list.List // front = most recently used, values are *chunk
	idx       map[string]*list.Element
	used      int64
	// ptrMu guards the pointer files and dirty together, so a SetPointer
	// racing a reconcile cannot have its value uploaded and then released
	// under it. It is separate from mu only to keep pointer IO off the lock
	// every chunk read takes.
	ptrMu sync.Mutex
	// dirty is the pointer names still spooled, i.e. whose value the bucket
	// may not have yet. Seeded from disk at New, added to by SetPointer,
	// drained by Sync as it uploads and releases each one.
	dirty map[string]bool
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
	case cfg.CacheBytes <= 0:
		return nil, errors.New("casfs: CacheBytes must be positive")
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = DefaultChunkSize
	}
	if cfg.TouchInterval == 0 {
		cfg.TouchInterval = DefaultTouchInterval
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
	s := &Store{
		cfg: cfg,
		s3: &s3{
			endpoint: strings.TrimSuffix(cfg.Endpoint, "/"),
			region:   cfg.Region,
			bucket:   cfg.Bucket,
			creds:    cfg.Credentials,
			http:     cfg.HTTPClient,
		},
		sizes:     map[string]int64{},
		confirmed: map[string]bool{},
		arts:      map[string]*artifact{},
		lru:       list.New(),
		idx:       map[string]*list.Element{},
		dirty:     map[string]bool{},
	}
	if err := s.reclaim(); err != nil {
		return nil, err
	}
	if err := s.scanCache(); err != nil {
		return nil, err
	}
	if err := s.scanPointers(); err != nil {
		return nil, err
	}
	return s, nil
}

// reclaim decides whether the cache dir may be trusted at all. Close writes the
// clean marker after flushing every artifact; if it is missing, some pwrite may
// have been half-flushed when the process died, and a half-written extent still
// reads as present. There is no way to tell, so the whole cache goes. It is
// disposable by construction and this costs refills, never correctness.
func (s *Store) reclaim() error {
	marker := filepath.Join(s.cfg.CacheDir, cleanMarker)
	if _, err := os.Stat(marker); err == nil {
		return os.Remove(marker)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	ents, err := os.ReadDir(s.cfg.CacheDir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(s.cfg.CacheDir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// scanCache rebuilds the in-memory LRU from the cache directory. Presence comes
// from each sparse file's extent map, recency from its mtime, which is now one
// timestamp for the whole artifact. Anything that is not a hash-named artifact
// file is deleted, which is also how a pre-sparse cache directory is retired.
func (s *Store) scanCache() error {
	var all []*artifact
	err := filepath.WalkDir(s.cfg.CacheDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name := d.Name()
		if !validHash(name) || filepath.Base(filepath.Dir(p)) != name[:2] {
			return os.Remove(p)
		}
		fi, err := d.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		a, err := s.scanArtifact(name, fi)
		if err != nil {
			return err
		}
		all = append(all, a)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].mtime.Before(all[j].mtime) })
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range all { // oldest first, so PushFront leaves newest at the front
		s.arts[a.hash] = a
		// The cache file was created at the object's full size, so a restart
		// learns every cached object's size without a HEAD.
		s.sizes[a.hash] = a.size
		for i := int64(0); i < nchunks(a.size, s.cfg.ChunkSize); i++ {
			if a.has(i) {
				s.admitLocked(a.hash, i, chunkLen(a.size, s.cfg.ChunkSize, i))
			}
		}
	}
	s.evictLocked()
	return nil
}

// scanArtifact reads one sparse file's extent map into a presence bitmap. Only
// a chunk whose whole range is reported as data counts as present, so the
// kernel's licence to overstate data can only ever cost a refill.
func (s *Store) scanArtifact(hash string, fi fs.FileInfo) (*artifact, error) {
	f, err := os.Open(s.cachePath(hash))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cs := s.cfg.ChunkSize
	a := &artifact{
		hash:    hash,
		size:    fi.Size(),
		present: make([]uint64, (nchunks(fi.Size(), cs)+63)/64),
		pins:    map[int64]int32{},
		mtime:   fi.ModTime(),
	}
	n := nchunks(a.size, cs)
	err = dataRanges(f, a.size, func(off, end int64) {
		for i := off / cs; i < n && i*cs < end; i++ {
			if i*cs >= off && i*cs+chunkLen(a.size, cs, i) <= end {
				a.set(i)
			}
		}
	})
	if err != nil {
		return nil, err
	}
	return a, nil
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

// cachePath is the sparse file holding whatever of hash is cached.
func (s *Store) cachePath(hash string) string {
	return filepath.Join(s.cfg.CacheDir, hash[:2], hash)
}

func chunkKey(hash string, idx int64) string {
	return hash + "." + strconv.FormatInt(idx, 10)
}

// Put hashes a local file and renames it into the spool under its hash. The
// rename is atomic and is the entire registration, so a kill at any instant
// leaves either the untouched original or a correctly named spool file that the
// next Sync uploads. path must be on the same filesystem as SpoolDir.
//
// This is a convenience only. A caller that already knows the hash can do the
// rename itself and never call into casfs at all.
func (s *Store) Put(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	f.Close()
	if err != nil {
		return "", err
	}
	hash := hex.EncodeToString(h.Sum(nil))
	if err := os.Rename(path, s.SpoolPath(hash)); err != nil {
		return "", fmt.Errorf("casfs: spool %s: %w", hash, err)
	}
	s.mu.Lock()
	s.sizes[hash] = n
	s.mu.Unlock()
	return hash, nil
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

// upload pushes one spool file, hashing the bytes as they stream past so a file
// whose name lies about its contents is caught without a separate pass over it.
// That same digest is what the request signature commits to through
// x-amz-content-sha256, so a compliant endpoint rejects the mismatched bytes
// before storing them; the local check turns that into a legible error and
// covers endpoints that do not verify.
func (s *Store) upload(hash string) error {
	if size, err := s.s3.head(s.key(hash)); err == nil {
		s.mu.Lock()
		s.sizes[hash] = size
		s.mu.Unlock()
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
	h := sha256.New()
	putErr := s.s3.put(s.key(hash), io.TeeReader(f, h), fi.Size(), hash)
	if got := hex.EncodeToString(h.Sum(nil)); got != hash {
		return fmt.Errorf("casfs: spool file %s contains content hashing to %s, refusing it", hash, got)
	}
	if putErr != nil {
		return putErr
	}
	s.mu.Lock()
	s.sizes[hash] = fi.Size()
	s.mu.Unlock()
	return nil
}

// Release drops the spool file for hash. It refuses until the bucket is
// confirmed to hold the content, so a hash is never left unreadable.
//
// It stays deliberately dumb: no pre-warming of the cache. Whatever real
// traffic touched while the file was spool-resident is already sitting in the
// chunk cache and keeps serving from there, so the transition is invisible for
// the ranges anyone actually reads. Ranges nobody ever read are by definition
// cold, and copying gigabytes of them into the cache would only evict hot
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

// Close flushes every cached artifact and marks the cache clean, so the next
// New may trust it. Skipping it, or dying before it, costs the whole cache and
// nothing else. It does not invalidate open Files, but their Views are only
// stable while their ranges stay pinned, exactly as during normal operation.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for _, a := range s.arts {
		if a.f == nil {
			continue
		}
		// Order matters: the marker must not become visible before the data it
		// vouches for is on disk.
		errs = append(errs, a.f.Sync(), a.f.Close())
		a.f = nil
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.cfg.CacheDir, cleanMarker), nil, 0o644)
}

// Open returns a reader for hash. The content must be in the spool or in the
// bucket. The only network call Open itself may make is a HEAD to learn the size
// of an object that is neither spooled nor already known to this process.
func (s *Store) Open(hash string) (*File, error) {
	if !validHash(hash) {
		return nil, fmt.Errorf("casfs: open %q: not a hex sha256", hash)
	}
	if fi, err := os.Stat(s.SpoolPath(hash)); err == nil {
		return &File{s: s, hash: hash, size: fi.Size(), spooled: true}, nil
	}
	s.mu.Lock()
	size, known := s.sizes[hash]
	s.mu.Unlock()
	if !known {
		var err error
		if size, err = s.s3.head(s.key(hash)); err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.sizes[hash] = size
		s.mu.Unlock()
	}
	return &File{s: s, hash: hash, size: size}, nil
}

// artifact returns the cache state for hash, creating the sparse file at its
// full size if it is not there yet.
//
// ponytail: one descriptor per artifact read since startup, never closed until
// Close. Bounded by the number of distinct artifacts, not chunks, which is what
// this store is for; add an fd LRU if some caller ever opens thousands.
func (s *Store) artifact(hash string, size int64) (*artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.arts[hash]
	if a != nil && a.size != size {
		// Cannot happen from this code: the name is the content hash. Some
		// foreign file is squatting the path, so it is not a cache entry.
		s.forgetLocked(a)
		a = nil
	}
	if a == nil {
		a = &artifact{
			hash:    hash,
			size:    size,
			present: make([]uint64, (nchunks(size, s.cfg.ChunkSize)+63)/64),
			pins:    map[int64]int32{},
			mtime:   time.Now(),
		}
		s.arts[hash] = a
	}
	if a.f == nil {
		if err := os.MkdirAll(filepath.Dir(s.cachePath(hash)), 0o755); err != nil {
			return nil, err
		}
		f, err := s.fileLocked(a)
		if err != nil {
			return nil, err
		}
		if err := f.Truncate(size); err != nil { // the whole length, holes for the rest
			return nil, err
		}
	}
	return a, nil
}

// fileLocked returns the artifact's descriptor, opening the sparse file if this
// process has not needed it yet. Eviction needs one as much as a fill does: a
// punch is a write.
func (s *Store) fileLocked(a *artifact) (*os.File, error) {
	if a.f == nil {
		f, err := os.OpenFile(s.cachePath(a.hash), os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			return nil, err
		}
		a.f = f
	}
	return a.f, nil
}

// forgetLocked drops every trace of an artifact, cache file included.
func (s *Store) forgetLocked(a *artifact) {
	for el := s.lru.Front(); el != nil; {
		next := el.Next()
		if c := el.Value.(*chunk); c.hash == a.hash {
			s.lru.Remove(el)
			delete(s.idx, chunkKey(c.hash, c.idx))
			s.used -= c.bytes
		}
		el = next
	}
	if a.f != nil {
		a.f.Close()
	}
	delete(s.arts, a.hash)
	os.Remove(s.cachePath(a.hash))
}

// hold makes chunk idx present and pins it. The pin covers the fill as well as
// whatever the caller does next, which is what keeps a concurrent eviction from
// punching the range out from under either. Every hold needs a drop.
func (s *Store) hold(a *artifact, idx int64) error {
	s.mu.Lock()
	a.pins[idx]++
	have := a.has(idx)
	stale := have && s.hitLocked(a, idx)
	s.mu.Unlock()
	if stale {
		// Best effort. A failed utimes costs restart fidelity, nothing else.
		now := time.Now()
		os.Chtimes(s.cachePath(a.hash), now, now)
	}
	if have {
		return nil
	}
	if err := s.fill(a, idx); err != nil {
		s.drop(a, idx)
		return err
	}
	return nil
}

func (s *Store) drop(a *artifact, idx int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.pins[idx] <= 1 {
		delete(a.pins, idx)
	} else {
		a.pins[idx]--
	}
	if s.used > s.cfg.CacheBytes {
		// A pin outranks the cap, so eviction can leave the cache over it. Try
		// again as pins clear, or the cap only converges on the next fill.
		s.evictLocked()
	}
}

// fill pwrites one chunk into the sparse file at its true offset. The spool
// file is preferred when it is still present, which is the only respect in
// which spooled and remote content differ. Two goroutines filling the same
// chunk both write the same bytes to the same place, which is why there is no
// singleflight: a duplicate fill is correct, just wasteful.
func (s *Store) fill(a *artifact, idx int64) error {
	off := idx * s.cfg.ChunkSize
	n := chunkLen(a.size, s.cfg.ChunkSize, idx)
	var src io.Reader
	if sf, err := os.Open(s.SpoolPath(a.hash)); err == nil {
		defer sf.Close()
		src = io.NewSectionReader(sf, off, n)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	} else {
		body, _, err := s.s3.get(s.key(a.hash), off, n)
		if err != nil {
			return err
		}
		defer body.Close()
		src = body
	}
	w, err := io.Copy(io.NewOffsetWriter(a.f, off), io.LimitReader(src, n))
	if err == nil && w != n {
		err = fmt.Errorf("casfs: chunk %s.%d: got %d bytes, want %d: %w", a.hash, idx, w, n, io.ErrUnexpectedEOF)
	}
	if err != nil {
		// A short fill is garbage that nothing will ever account for, so give
		// the blocks back rather than leak them until some later refill.
		punch(a.f, off, n)
		return err
	}
	s.mu.Lock()
	a.set(idx)
	s.admitLocked(a.hash, idx, n)
	s.evictLocked()
	s.mu.Unlock()
	return nil
}

// admitLocked records a chunk that is now on disk.
func (s *Store) admitLocked(hash string, idx, n int64) {
	key := chunkKey(hash, idx)
	if el, ok := s.idx[key]; ok { // another goroutine filled it too
		s.lru.MoveToFront(el)
		return
	}
	s.idx[key] = s.lru.PushFront(&chunk{hash, idx, n})
	s.used += n
}

// hitLocked marks a chunk as recently used and reports whether the artifact's
// mtime is due for a refresh. The in-memory LRU is the live authority; the
// mtime write exists only so a restart reseeds sensibly, and is throttled to at
// most one utimes per artifact per TouchInterval.
func (s *Store) hitLocked(a *artifact, idx int64) bool {
	if el, ok := s.idx[chunkKey(a.hash, idx)]; ok {
		s.lru.MoveToFront(el)
	}
	now := time.Now()
	if s.cfg.TouchInterval > 0 && now.Sub(a.mtime) >= s.cfg.TouchInterval {
		a.mtime = now
		return true
	}
	return false
}

// evictLocked punches chunks, least recently used first, until the cache is
// back under its cap. Pinned chunks are skipped, never punched: a caller
// holding a live mmap of a range would silently start reading zeros, and there
// is no error and no fault to notice it by.
func (s *Store) evictLocked() {
	for el := s.lru.Back(); el != nil && s.used > s.cfg.CacheBytes; {
		prev := el.Prev()
		c := el.Value.(*chunk)
		a := s.arts[c.hash]
		if a != nil && a.pinned(c.idx) {
			el = prev
			continue
		}
		s.lru.Remove(el)
		delete(s.idx, chunkKey(c.hash, c.idx))
		s.used -= c.bytes
		if a != nil {
			a.clear(c.idx)
			// Best effort: a failed punch leaves blocks allocated that the
			// accounting no longer counts, and the next fill rewrites them.
			if f, err := s.fileLocked(a); err == nil {
				punch(f, c.idx*s.cfg.ChunkSize, c.bytes)
			}
		}
		el = prev
	}
}

// CacheUsage reports the chunk bytes currently accounted for on disk. Spool
// files are not counted: they are durable, not cache.
func (s *Store) CacheUsage() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.used
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
// cache, which is wiped on an unclean start. A name with slashes in it is a
// nested file, which is why this is a directory of its own rather than the
// spool root: a flat sibling of the artifacts could not hold one.
func (s *Store) pointerPath(name string) string {
	return filepath.Join(s.cfg.SpoolDir, pointerDir, filepath.FromSlash(name))
}

// writePointer lands a value by tmp+rename, so a kill leaves either the old
// value or the new one. Callers hold ptrMu.
func (s *Store) writePointer(name, value string) error {
	p := s.pointerPath(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p+".tmp", []byte(value), 0o644); err != nil {
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

// File reads one stored object, through the chunk cache with ReadAt or as a
// zero-copy mapping with View. Close releases the mapping and any pins this
// File still holds, and invalidates every View it handed out.
type File struct {
	s       *Store
	hash    string
	size    int64
	spooled bool // opened while the spool file was still there

	mu     sync.Mutex
	a      *artifact
	view   []byte          // whole-file PROT_READ mapping, created by View
	myPins map[int64]int32 // this File's share of the artifact's pins
}

func (f *File) Size() int64 { return f.size }

func (f *File) art() (*artifact, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.a == nil {
		a, err := f.s.artifact(f.hash, f.size)
		if err != nil {
			return nil, err
		}
		f.a = a
	}
	return f.a, nil
}

func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.a != nil {
		for i, n := range f.myPins {
			for ; n > 0; n-- {
				f.s.drop(f.a, i)
			}
		}
	}
	f.myPins = nil
	unmap(f.view)
	f.view = nil
	return nil
}

func (f *File) bounds(off, n int64) error {
	if off < 0 || n < 0 || off+n > f.size {
		return fmt.Errorf("casfs: range [%d,%d) outside a %d byte object", off, off+n, f.size)
	}
	return nil
}

// Pin declares that [off, off+n) must stay resident: eviction will not punch
// any chunk it touches until the matching Unpin. Hold a pin for as long as a
// View of that range is being read, because a punched page reads back as zeros
// with no error, and zeros are indistinguishable from content.
//
// Pins live in memory only, so they die with the process, which is correct: a
// mapping cannot outlive the process that holds it.
func (f *File) Pin(off, n int64) error {
	if err := f.bounds(off, n); err != nil || n == 0 {
		return err
	}
	a, err := f.art()
	if err != nil {
		return err
	}
	cs := f.s.cfg.ChunkSize
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if f.myPins == nil {
		f.myPins = map[int64]int32{}
	}
	for i := off / cs; i <= (off+n-1)/cs; i++ {
		a.pins[i]++
		f.myPins[i]++
	}
	return nil
}

// Unpin releases a range pinned by an earlier Pin on this same File. It reports
// an error, and changes nothing, if any chunk in the range is not pinned here.
func (f *File) Unpin(off, n int64) error {
	if err := f.bounds(off, n); err != nil || n == 0 {
		return err
	}
	cs := f.s.cfg.ChunkSize
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	for i := off / cs; i <= (off+n-1)/cs; i++ {
		if f.myPins[i] <= 0 {
			return fmt.Errorf("casfs: unpin of an unpinned range [%d,%d)", off, off+n)
		}
	}
	for i := off / cs; i <= (off+n-1)/cs; i++ {
		f.myPins[i]--
		if f.myPins[i] == 0 {
			delete(f.myPins, i)
		}
		if f.a.pins[i] <= 1 {
			delete(f.a.pins, i)
		} else {
			f.a.pins[i]--
		}
	}
	if f.s.used > f.s.cfg.CacheBytes {
		f.s.evictLocked() // a pin outranks the cap, so unpinning may owe blocks
	}
	return nil
}

// View returns a zero-copy read-only view of [off, off+n), filling any chunks
// the range needs first. The bytes are a window onto a shared mapping of the
// cache file, so the kernel tiers them between RAM and SSD by itself and
// nothing is copied onto the Go heap.
//
// The bytes are only guaranteed to be there while the covering range is pinned,
// and only until Close. An unpinned chunk can be evicted at any moment by a
// hole punch, after which the same slice silently reads zeros. Pin first, read,
// then Unpin.
//
// A spool-resident object is mapped straight from the spool file. Releasing it
// afterwards does not disturb an existing mapping, because unlinking never
// disturbs one.
func (f *File) View(off, n int64) ([]byte, error) {
	if err := f.bounds(off, n); err != nil {
		return nil, err
	}
	if n == 0 {
		return []byte{}, nil
	}
	f.mu.Lock()
	spooled := f.spooled
	if spooled && f.view == nil {
		b, err := mapWhole(f.s.SpoolPath(f.hash), f.size)
		switch {
		case err == nil:
			f.view = b
		case errors.Is(err, fs.ErrNotExist):
			f.spooled, spooled = false, false // released already, use the cache
		default:
			f.mu.Unlock()
			return nil, err
		}
	}
	if spooled {
		defer f.mu.Unlock()
		return f.view[off : off+n], nil
	}
	f.mu.Unlock()

	// Fill outside the File lock, so concurrent Views of one object do not
	// serialize behind each other's ranged GETs.
	a, err := f.art()
	if err != nil {
		return nil, err
	}
	cs := f.s.cfg.ChunkSize
	for i := off / cs; i <= (off+n-1)/cs; i++ {
		if err := f.s.hold(a, i); err != nil {
			return nil, err
		}
		f.s.drop(a, i) // the caller's own Pin is what keeps it, not this
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.view == nil {
		b, err := mapWhole(f.s.cachePath(f.hash), f.size)
		if err != nil {
			return nil, err
		}
		f.view = b
	}
	return f.view[off : off+n], nil
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("casfs: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.size {
		return 0, io.EOF
	}
	a, err := f.art()
	if err != nil {
		return 0, err
	}
	cs := f.s.cfg.ChunkSize
	n := 0
	for n < len(p) && off+int64(n) < f.size {
		cur := off + int64(n)
		m, err := f.s.readChunk(a, cur/cs, p[n:], cur%cs)
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

// readChunk preads out of one chunk, filling it first if it is missing. The
// chunk stays pinned for the whole read, so an eviction racing this read cannot
// turn it into a hole halfway through and hand back zeros.
func (s *Store) readChunk(a *artifact, idx int64, p []byte, off int64) (int, error) {
	if err := s.hold(a, idx); err != nil {
		return 0, err
	}
	defer s.drop(a, idx)
	// Clamp to the chunk: past its end lies the next chunk, which may be a
	// hole, and a hole reads as zeros rather than as a short read.
	want := min(int64(len(p)), chunkLen(a.size, s.cfg.ChunkSize, idx)-off)
	return a.f.ReadAt(p[:want], idx*s.cfg.ChunkSize+off)
}
