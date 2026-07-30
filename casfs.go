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
// There is exactly one read path: the chunk cache. A chunk miss is filled by
// pread from the spool file when it is still there, or by a ranged GET when it
// is not, and that is the only difference between the two. Either way the chunk
// is materialized as an ordinary cache file, counted against the cache cap and
// evicted like any other.
package casfs

import (
	"container/list"
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
)

const (
	DefaultChunkSize = 4 << 20
	// DefaultTouchInterval bounds how stale the restart LRU seed can be. See
	// Config.TouchInterval.
	DefaultTouchInterval = time.Hour
)

type Config struct {
	Endpoint  string // scheme://host[:port], path-style, no bucket
	Region    string // default "auto" (works for R2; MinIO ignores it)
	Bucket    string
	Prefix    string // optional key prefix, used verbatim (include a trailing "/")
	AccessKey string
	SecretKey string

	SpoolDir   string // hash-named files awaiting upload, created if missing
	CacheDir   string // chunk files, created if missing
	CacheBytes int64  // hard cap on chunk bytes on disk
	ChunkSize  int64  // chunk granularity, default DefaultChunkSize

	// TouchInterval throttles how often a cache hit refreshes a chunk file's
	// mtime. The startup LRU seed reads mtime, so without this a chunk fetched
	// long ago but read constantly looks ancient after a restart and gets
	// evicted first. Zero means DefaultTouchInterval, negative disables
	// touching entirely.
	TouchInterval time.Duration

	HTTPClient *http.Client // optional
}

type chunk struct {
	key   string // "<hash>.<index>"
	bytes int64
	mtime time.Time // last value written to the file, not necessarily read back
}

type Store struct {
	cfg Config
	s3  *s3

	mu sync.Mutex
	// sizes and confirmed are caches, never the source of truth. Losing them
	// costs one HEAD each.
	sizes     map[string]int64
	confirmed map[string]bool
	lru       *list.List // front = most recently used, values are *chunk
	idx       map[string]*list.Element
	used      int64
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
			ak:       cfg.AccessKey,
			sk:       cfg.SecretKey,
			http:     cfg.HTTPClient,
		},
		sizes:     map[string]int64{},
		confirmed: map[string]bool{},
		lru:       list.New(),
		idx:       map[string]*list.Element{},
	}
	if err := s.scanCache(); err != nil {
		return nil, err
	}
	return s, nil
}

// scanCache rebuilds the in-memory LRU from the cache directory, deleting torn
// tmp files left behind by a crash. Recency is seeded from mtime, which is
// approximate and good enough.
func (s *Store) scanCache() error {
	type found struct {
		key   string
		bytes int64
		mtime time.Time
	}
	var all []found
	err := filepath.WalkDir(s.cfg.CacheDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name := d.Name()
		if strings.Contains(name, ".tmp") {
			return os.Remove(p)
		}
		if !validChunkName(name) {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		all = append(all, found{name, fi.Size(), fi.ModTime()})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].mtime.Before(all[j].mtime) })
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range all { // oldest first, so PushFront leaves newest at the front
		s.idx[f.key] = s.lru.PushFront(&chunk{f.key, f.bytes, f.mtime})
		s.used += f.bytes
	}
	s.evictLocked()
	return nil
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

func validChunkName(name string) bool {
	i := strings.IndexByte(name, '.')
	if i < 0 || !validHash(name[:i]) {
		return false
	}
	_, err := strconv.ParseInt(name[i+1:], 10, 64)
	return err == nil
}

func (s *Store) key(hash string) string { return s.cfg.Prefix + hash }

// SpoolPath is where a file named after hash must land to be registered.
// Callers that produce content themselves can write next to it and rename onto
// this path; that rename is all the registration there is.
func (s *Store) SpoolPath(hash string) string {
	return filepath.Join(s.cfg.SpoolDir, hash)
}

func chunkKey(hash string, idx int64) string {
	return hash + "." + strconv.FormatInt(idx, 10)
}

func (s *Store) chunkPath(key string) string {
	return filepath.Join(s.cfg.CacheDir, key[:2], key)
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
// Call it after Put, on a ticker, at startup, whenever. It is the only thing
// that moves bytes out, and it is driven purely by what the spool directory
// contains.
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

// Open returns a reader for hash. The content must be in the spool or in the
// bucket. The only network call Open itself may make is a HEAD to learn the size
// of an object that is neither spooled nor already known to this process.
func (s *Store) Open(hash string) (*File, error) {
	if !validHash(hash) {
		return nil, fmt.Errorf("casfs: open %q: not a hex sha256", hash)
	}
	if fi, err := os.Stat(s.SpoolPath(hash)); err == nil {
		return &File{s: s, hash: hash, size: fi.Size()}, nil
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

// openChunk returns an open handle to chunk idx of hash, filling the cache if
// it is missing. The handle stays valid even if the chunk is evicted
// immediately afterwards, because a POSIX unlink does not disturb open files.
func (s *Store) openChunk(hash string, idx int64) (*os.File, error) {
	key := chunkKey(hash, idx)
	f, err := os.Open(s.chunkPath(key))
	if err == nil {
		s.touch(key)
		return f, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return s.fill(hash, idx, key)
}

// fill produces a missing chunk. The spool file is preferred when it is still
// present, which is the only respect in which spooled and remote content differ.
func (s *Store) fill(hash string, idx int64, key string) (*os.File, error) {
	if sf, err := os.Open(s.SpoolPath(hash)); err == nil {
		defer sf.Close()
		fi, err := sf.Stat()
		if err != nil {
			return nil, err
		}
		return s.materialize(hash, idx, key,
			io.NewSectionReader(sf, idx*s.cfg.ChunkSize, s.cfg.ChunkSize), fi.Size())
	}
	body, total, err := s.s3.get(s.key(hash), idx*s.cfg.ChunkSize, s.cfg.ChunkSize)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return s.materialize(hash, idx, key, body, total)
}

// materialize writes one chunk as tmp+rename and admits it to the cache. It
// returns a handle to the published chunk that survives the chunk's eviction.
func (s *Store) materialize(hash string, idx int64, key string, src io.Reader, total int64) (*os.File, error) {
	final := s.chunkPath(key)
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(final), key+".tmp")
	if err != nil {
		return nil, err
	}
	n, err := io.Copy(tmp, io.LimitReader(src, s.cfg.ChunkSize))
	if err == nil {
		err = os.Rename(tmp.Name(), final)
	}
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	s.admit(key, n, hash, total)
	return tmp, nil
}

// admit records a newly published chunk and evicts down to the byte cap.
func (s *Store) admit(key string, n int64, hash string, total int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sizes[hash] = total
	if el, ok := s.idx[key]; ok { // another goroutine filled it too
		s.lru.MoveToFront(el)
		return
	}
	s.idx[key] = s.lru.PushFront(&chunk{key, n, time.Now()})
	s.used += n
	s.evictLocked()
}

// touch marks a chunk as recently used. The in-memory LRU is the live
// authority; the mtime write exists only so a restart reseeds sensibly, and is
// throttled to at most one utimes per chunk per TouchInterval. The recorded
// mtime is kept in the LRU entry, so a hit never needs a stat.
func (s *Store) touch(key string) {
	now := time.Now()
	s.mu.Lock()
	el, ok := s.idx[key]
	if !ok {
		s.mu.Unlock()
		return
	}
	s.lru.MoveToFront(el)
	c := el.Value.(*chunk)
	stale := s.cfg.TouchInterval > 0 && now.Sub(c.mtime) >= s.cfg.TouchInterval
	if stale {
		c.mtime = now
	}
	s.mu.Unlock()
	if stale {
		// Best effort. A failed utimes costs restart fidelity, nothing else,
		// and the chunk may legitimately have been evicted a moment ago.
		os.Chtimes(s.chunkPath(key), now, now)
	}
}

func (s *Store) evictLocked() {
	for s.used > s.cfg.CacheBytes && s.lru.Len() > 0 {
		el := s.lru.Back()
		c := el.Value.(*chunk)
		s.lru.Remove(el)
		delete(s.idx, c.key)
		s.used -= c.bytes
		os.Remove(s.chunkPath(c.key))
	}
}

// CacheUsage reports the chunk bytes currently accounted for on disk. Spool
// files are not counted: they are durable, not cache.
func (s *Store) CacheUsage() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.used
}

// SetPointer writes a small mutable object at Prefix+name. Pointer names may
// not look like a content hash, so they can never collide with stored content.
func (s *Store) SetPointer(name, value string) error {
	if err := checkPointer(name); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(value))
	return s.s3.put(s.cfg.Prefix+name, strings.NewReader(value), int64(len(value)), hex.EncodeToString(sum[:]))
}

// GetPointer reads a pointer. A missing pointer returns an error wrapping
// fs.ErrNotExist.
func (s *Store) GetPointer(name string) (string, error) {
	if err := checkPointer(name); err != nil {
		return "", err
	}
	b, err := s.s3.getAll(s.cfg.Prefix + name)
	return string(b), err
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

// File reads one stored object. It holds no file descriptors, so Close is a
// formality and reads remain valid for the life of the Store.
type File struct {
	s    *Store
	hash string
	size int64
}

func (f *File) Size() int64  { return f.size }
func (f *File) Close() error { return nil }

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
	cs := f.s.cfg.ChunkSize
	n := 0
	for n < len(p) && off+int64(n) < f.size {
		cur := off + int64(n)
		cf, err := f.s.openChunk(f.hash, cur/cs)
		if err != nil {
			return n, err
		}
		m, err := cf.ReadAt(p[n:], cur%cs)
		cf.Close()
		n += m
		if err != nil && err != io.EOF {
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
