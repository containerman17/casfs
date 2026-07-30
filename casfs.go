// Package casfs is a content-addressed file store on top of any S3-compatible
// bucket, with lazy chunked reads and a byte-capped local disk cache.
//
// Objects are stored whole under their hex sha256, so uploads are idempotent
// and two writers racing on the same content write identical bytes. Reads are
// served from, in order: the original local file if it is still registered,
// cached chunk files on disk, and finally ranged GETs against the bucket.
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

const DefaultChunkSize = 4 << 20

type Config struct {
	Endpoint  string // scheme://host[:port], path-style, no bucket
	Region    string // default "auto" (works for R2; MinIO ignores it)
	Bucket    string
	Prefix    string // optional key prefix, used verbatim (include a trailing "/")
	AccessKey string
	SecretKey string

	CacheDir   string // directory for chunk files, created if missing
	CacheBytes int64  // hard cap on chunk bytes on disk
	ChunkSize  int64  // ranged GET granularity, default DefaultChunkSize

	HTTPClient *http.Client // optional
}

// entry is what the store knows about one hash.
type entry struct {
	size     int64
	path     string // original local file, "" once released or never registered
	uploaded bool
}

type chunk struct {
	key   string // "<hash>.<index>"
	bytes int64
}

type Store struct {
	cfg Config
	s3  *s3

	mu    sync.Mutex
	files map[string]*entry
	lru   *list.List // front = most recently used, values are *chunk
	idx   map[string]*list.Element
	used  int64
}

func New(cfg Config) (*Store, error) {
	switch {
	case cfg.Endpoint == "":
		return nil, errors.New("casfs: Endpoint is required")
	case cfg.Bucket == "":
		return nil, errors.New("casfs: Bucket is required")
	case cfg.CacheDir == "":
		return nil, errors.New("casfs: CacheDir is required")
	case cfg.CacheBytes <= 0:
		return nil, errors.New("casfs: CacheBytes must be positive")
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = DefaultChunkSize
	}
	if cfg.Region == "" {
		cfg.Region = "auto"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Minute}
	}
	if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
		return nil, err
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
		files: map[string]*entry{},
		lru:   list.New(),
		idx:   map[string]*list.Element{},
	}
	if err := s.scan(); err != nil {
		return nil, err
	}
	return s, nil
}

// scan rebuilds the in-memory LRU from the cache directory, deleting torn tmp
// files left behind by a crash. Recency is seeded from mtime, which is
// approximate and good enough.
func (s *Store) scan() error {
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
		s.idx[f.key] = s.lru.PushFront(&chunk{f.key, f.bytes})
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

func (s *Store) chunkPath(key string) string {
	return filepath.Join(s.cfg.CacheDir, key[:2], key)
}

// Register hashes a local file and makes it readable through Open immediately,
// served straight from that file. It performs no network I/O. The file must
// stay where it is until Release, or until it is uploaded and the caller
// removes it.
func (s *Store) Register(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", err
	}
	hash := hex.EncodeToString(h.Sum(nil))
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.files[hash]
	if e == nil {
		e = &entry{}
		s.files[hash] = e
	}
	e.size, e.path = n, abs
	return hash, nil
}

// Upload pushes a registered hash to the bucket if it is not already there.
// It is safe to call concurrently and repeatedly; racing writers store
// identical bytes.
func (s *Store) Upload(hash string) error {
	s.mu.Lock()
	e := s.files[hash]
	var path string
	var done bool
	if e != nil {
		path, done = e.path, e.uploaded
	}
	s.mu.Unlock()
	if done {
		return nil
	}
	if path == "" {
		return fmt.Errorf("casfs: upload %s: not registered", hash)
	}

	if _, err := s.s3.head(s.key(hash)); err == nil {
		s.markUploaded(hash)
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if err := s.s3.put(s.key(hash), f, fi.Size(), hash); err != nil {
		return err
	}
	s.markUploaded(hash)
	return nil
}

func (s *Store) markUploaded(hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.files[hash]; e != nil {
		e.uploaded = true
	}
}

// Put is Register followed by Upload. It is synchronous: when it returns, the
// content is in the bucket and Open(hash) works.
func (s *Store) Put(path string) (string, error) {
	hash, err := s.Register(path)
	if err != nil {
		return "", err
	}
	return hash, s.Upload(hash)
}

// Release deletes the original local file registered for hash and drops it
// from the read path. It refuses to touch the file until the upload is
// confirmed, so a hash is never left unreadable. Open keeps working afterwards
// through the chunk cache and ranged GETs.
func (s *Store) Release(hash string) error {
	s.mu.Lock()
	e := s.files[hash]
	if e == nil || e.path == "" {
		s.mu.Unlock()
		return nil
	}
	if !e.uploaded {
		s.mu.Unlock()
		return fmt.Errorf("casfs: release %s: upload not complete", hash)
	}
	path := e.path
	e.path = ""
	s.mu.Unlock()
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Open returns a reader for hash. The object must have been registered, put,
// or already exist in the bucket. The only network call Open itself may make is
// a HEAD to learn the size of an object this process has not seen before.
func (s *Store) Open(hash string) (*File, error) {
	if !validHash(hash) {
		return nil, fmt.Errorf("casfs: open %q: not a hex sha256", hash)
	}
	s.mu.Lock()
	e := s.files[hash]
	s.mu.Unlock()
	if e == nil {
		size, err := s.s3.head(s.key(hash))
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		if s.files[hash] == nil {
			s.files[hash] = &entry{size: size, uploaded: true}
		}
		e = s.files[hash]
		s.mu.Unlock()
	}
	return &File{s: s, hash: hash, size: e.size}, nil
}

// localPath returns the registered original file for hash, if any.
func (s *Store) localPath(hash string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.files[hash]; e != nil {
		return e.path
	}
	return ""
}

// openChunk returns an open handle to chunk idx of hash, fetching it if the
// cache does not have it. The handle stays valid even if the chunk is evicted
// immediately afterwards, because a POSIX unlink does not disturb open files.
func (s *Store) openChunk(hash string, idx int64) (*os.File, error) {
	key := hash + "." + strconv.FormatInt(idx, 10)
	f, err := os.Open(s.chunkPath(key))
	if err == nil {
		s.touch(key)
		return f, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return s.fetch(hash, idx, key)
}

func (s *Store) fetch(hash string, idx int64, key string) (*os.File, error) {
	final := s.chunkPath(key)
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return nil, err
	}
	body, total, err := s.s3.get(s.key(hash), idx*s.cfg.ChunkSize, s.cfg.ChunkSize)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	tmp, err := os.CreateTemp(filepath.Dir(final), key+".tmp")
	if err != nil {
		return nil, err
	}
	n, err := io.Copy(tmp, io.LimitReader(body, s.cfg.ChunkSize))
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	// Keep the handle: after the rename it refers to the published chunk, and
	// it survives eviction of that name.
	if err := os.Rename(tmp.Name(), final); err != nil {
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
	if e := s.files[hash]; e != nil {
		e.size = total
	} else {
		s.files[hash] = &entry{size: total, uploaded: true}
	}
	if el, ok := s.idx[key]; ok { // another goroutine fetched it too
		s.lru.MoveToFront(el)
		return
	}
	s.idx[key] = s.lru.PushFront(&chunk{key, n})
	s.used += n
	s.evictLocked()
}

func (s *Store) touch(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.idx[key]; ok {
		s.lru.MoveToFront(el)
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

// CacheUsage reports the chunk bytes currently accounted for on disk.
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
	// Tier zero: the original local file, whole and unchunked.
	if path := f.s.localPath(f.hash); path != "" {
		if lf, err := os.Open(path); err == nil {
			n, err := lf.ReadAt(p, off)
			lf.Close()
			return n, err
		}
		// Released underneath us; fall through to the chunk path.
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
