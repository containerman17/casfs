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
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// newStore builds a store over a fresh temp tree. CacheMinFree is pinned to
// one byte so a test never depends on how full the developer's disk is; the
// tests that care about the watermark install their own statfs.
func newStore(t *testing.T, f *fakeS3, prefix string, chunkSize int64, opts ...func(*Config)) *Store {
	t.Helper()
	root := t.TempDir()
	cfg := Config{
		Endpoint:     f.URL,
		Bucket:       f.bucket,
		Prefix:       prefix,
		AccessKey:    "minioadmin",
		SecretKey:    "minioadmin",
		SpoolDir:     filepath.Join(root, "spool"),
		CacheDir:     filepath.Join(root, "cache"),
		ChunkSize:    chunkSize,
		CacheMinFree: 1,
	}
	for _, o := range opts {
		o(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// fakeDisk installs a statfs a test can move, so the store can be put over its
// watermark without filling anything.
func fakeDisk(free *atomic.Int64, minFree int64) func(*Config) {
	return func(c *Config) {
		c.CacheMinFree = minFree
		c.free = func(string) (int64, error) { return free.Load(), nil }
	}
}

// reopen stops a Store's worker and builds a second one over the same spool
// and cache directories, standing in for a restart. The cache is a tree of
// finished files, so a restart trusts whatever is there: there is no marker
// and nothing to wipe.
func reopen(t *testing.T, s *Store) *Store {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := New(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s2.Close() })
	return s2
}

// stopped halts the eviction worker so a test can drive evictOne and sweep by
// hand. Everything else on the Store keeps working.
func stopped(t *testing.T, s *Store) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func randBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// writeFile drops data in a scratch dir on the same filesystem as the spool, so
// Put can rename it.
func writeFile(t *testing.T, s *Store, data []byte) string {
	t.Helper()
	dir := filepath.Join(filepath.Dir(s.cfg.SpoolDir), "incoming")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// spool writes data straight into the spool dir under a chosen name, with no
// library call at all. That rename is the whole registration protocol.
func spool(t *testing.T, s *Store, name string, data []byte) {
	t.Helper()
	tmp := filepath.Join(s.cfg.SpoolDir, ".staging")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, s.SpoolPath(name)); err != nil {
		t.Fatal(err)
	}
}

// seed drops content straight into the fake bucket, so the store has never seen
// it locally.
func (f *fakeS3) seed(prefix string, data []byte) string {
	sum := sha256.Sum256(data)
	h := hex.EncodeToString(sum[:])
	f.mu.Lock()
	f.objects[prefix+h] = data
	f.mu.Unlock()
	return h
}

func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readAll(t *testing.T, file *File) []byte {
	t.Helper()
	got, err := io.ReadAll(io.NewSectionReader(file, 0, file.Size()))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func mustSync(t *testing.T, s *Store) []string {
	t.Helper()
	done, err := s.Sync()
	if err != nil {
		t.Fatal(err)
	}
	return done
}

// cachedNames is every file in the window tree, mapped to the window it sits in.
func cachedNames(t *testing.T, s *Store) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, w := range s.windows() {
		ents, err := os.ReadDir(s.windowDir(w))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			out[e.Name()] = w
		}
	}
	return out
}

// plant puts a file straight into a chosen window, which is how a test makes
// the cache look old without waiting twenty minutes.
func plant(t *testing.T, s *Store, w int64, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(s.windowDir(w), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.windowDir(w), name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSigningKeyVector pins the SigV4 key derivation to the published AWS
// example, which is the part of the signature that is easy to get subtly wrong.
func TestSigningKeyVector(t *testing.T) {
	got := hex.EncodeToString(signingKey(
		"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam"))
	const want = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	if got != want {
		t.Fatalf("signing key = %s, want %s", got, want)
	}
}

// TestFillAndReadRoundTrip is the whole read path in one: put, upload, drop the
// local copy, read it back out of the bucket through the chunk cache, and find
// the chunk files sitting in the current window under their derivable names.
func TestFillAndReadRoundTrip(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "epoch/", 4096)

	data := randBytes(4096*7+123, 1)
	hash, err := s.Put(writeFile(t, s, data))
	if err != nil {
		t.Fatal(err)
	}
	if hash != hashOf(data) {
		t.Fatalf("Put returned %s, want %s", hash, hashOf(data))
	}
	if done := mustSync(t, s); len(done) != 1 || done[0] != hash {
		t.Fatalf("Sync confirmed %v, want [%s]", done, hash)
	}
	if err := s.Release(hash); err != nil {
		t.Fatal(err)
	}

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatalf("read back %d bytes, want %d identical", len(got), len(data))
	}

	names := cachedNames(t, s)
	cur := nowWindow()
	for i := int64(0); i < nchunks(int64(len(data)), 4096); i++ {
		name := chunkName(hash, i)
		w, ok := names[name]
		if !ok {
			t.Fatalf("chunk %s was not cached", name)
		}
		if w != cur {
			t.Fatalf("chunk %s landed in window %d, want the current one %d", name, w, cur)
		}
	}
}

func TestReadAtCrossesChunkBoundaries(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	data := randBytes(1024*5+7, 2)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, r := range [][2]int{{0, 1}, {1023, 2}, {1020, 1030}, {0, len(data)}, {len(data) - 3, 3}} {
		p := make([]byte, r[1])
		n, err := file.ReadAt(p, int64(r[0]))
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("ReadAt(%d,%d): %v", r[0], r[1], err)
		}
		if !bytes.Equal(p[:n], data[r[0]:r[0]+n]) {
			t.Fatalf("ReadAt(%d,%d) returned the wrong bytes", r[0], r[1])
		}
	}
	if _, err := file.ReadAt(make([]byte, 4), int64(len(data))); !errors.Is(err, io.EOF) {
		t.Fatalf("read past the end err=%v, want io.EOF", err)
	}
}

// TestCacheHitNeedsNoNetwork warms the cache, then kills the S3 endpoint
// entirely. Reads that hit cached chunks must still succeed.
func TestCacheHitNeedsNoNetwork(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	data := randBytes(1024*3, 3)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("warm read differed")
	}
	file.Close()

	f.Server.Close()
	file2, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file2.Close()
	if got := readAll(t, file2); !bytes.Equal(got, data) {
		t.Fatal("cached read differed with the endpoint gone")
	}
}

// TestStartupWalkRebuildsTheMap is the only thing a restart does: one
// name-only walk of the window tree, no journal, no marker, and every chunk
// still readable with the endpoint dead.
func TestStartupWalkRebuildsTheMap(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	data := randBytes(1024*4, 11)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, file)
	file.Close()
	before := cachedNames(t, s)
	if len(before) != 4 {
		t.Fatalf("cached %d chunks, want 4", len(before))
	}

	s2 := reopen(t, s)
	s2.mu.Lock()
	got := len(s2.where)
	s2.mu.Unlock()
	if got != len(before) {
		t.Fatalf("startup walk mapped %d chunks, want %d", got, len(before))
	}
	// Sizes are not persisted, so a restart pays one HEAD per artifact it
	// opens and nothing more: every byte after that comes off the walk.
	file2, err := s2.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file2.Close()
	f.Server.Close()
	if b := readAll(t, file2); !bytes.Equal(b, data) {
		t.Fatal("post-restart read differed")
	}
}

// TestAdmissionRefusesOverWatermark is the rule that replaced eviction on the
// write path: over the watermark a fill is served from memory and NOT written,
// and the moment there is room again fills resume. Nothing is ever deleted to
// make space for a fill.
func TestAdmissionRefusesOverWatermark(t *testing.T) {
	f := newFakeS3(t)
	var free atomic.Int64
	free.Store(0) // full
	s := newStore(t, f, "", 1024, fakeDisk(&free, 1<<20))
	data := randBytes(1024*3, 4)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("read over the watermark returned the wrong bytes")
	}
	if n := len(cachedNames(t, s)); n != 0 {
		t.Fatalf("%d chunks cached while over the watermark, want 0", n)
	}
	// Every read refetches, because nothing is allowed to land: that is the
	// degraded mode, and it is counted rather than hidden.
	if st := s.Stats(); st.Refusals < 3 {
		t.Fatalf("refusals = %d, want at least one per chunk", st.Refusals)
	}

	// A view is still complete over a disk that refuses everything: the bytes
	// come from the heap instead of a mapping.
	v, err := file.View(512, 2048)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if !bytes.Equal(v.Slice(0, 2048), data[512:512+2048]) {
		t.Fatal("view over an unwritable cache returned the wrong bytes")
	}

	free.Store(1 << 30) // room again
	file2, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file2.Close()
	readAll(t, file2)
	if n := len(cachedNames(t, s)); n != 3 {
		t.Fatalf("%d chunks cached once under the watermark, want 3", n)
	}
}

// TestWorkerDrainsOldestFirstAndStopsAtCurrent is the eviction contract: the
// oldest non-current window goes first, whole, and when only the current
// window is left the worker STOPS. A saturated cache freezes full rather than
// eating its own fresh fills, which is what admission control is there for.
func TestWorkerDrainsOldestFirstAndStopsAtCurrent(t *testing.T) {
	f := newFakeS3(t)
	var free atomic.Int64
	free.Store(0) // permanently over the watermark
	s := newStore(t, f, "", 1024, fakeDisk(&free, 1<<20))
	stopped(t, s)

	cur := nowWindow()
	h := strings.Repeat("a", 64)
	for i, w := range []int64{cur - 5, cur - 2, cur} {
		for j := 0; j < 3; j++ {
			plant(t, s, w, chunkName(h, int64(i*10+j)), []byte("x"))
		}
	}

	for i := 0; i < 6; i++ {
		if !s.evictOne() {
			t.Fatalf("worker stopped after %d deletes, want 6", i)
		}
		if i < 3 && len(cachedNames(t, s)) != 9-i-1 {
			t.Fatalf("delete %d did not remove exactly one file", i)
		}
	}
	if s.evictOne() {
		t.Fatal("worker deleted from the current window")
	}
	left := cachedNames(t, s)
	if len(left) != 3 {
		t.Fatalf("%d files left, want the current window's 3: %v", len(left), left)
	}
	for name, w := range left {
		if w != cur {
			t.Fatalf("%s survived in window %d, want only the current one", name, w)
		}
	}
	// The drained windows are gone, not left as empty directories.
	for _, w := range s.windows() {
		if w != cur {
			t.Fatalf("window %d was drained but not removed", w)
		}
	}
	// The horizon is the age of what it actually deleted, not a setting.
	if st := s.Stats(); st.Evictions != 6 || st.VictimAge != 2*windowMinutes*time.Minute {
		t.Fatalf("stats = %+v, want 6 evictions and a 40m victim age", st)
	}
}

// TestPromoteOnTouchFromAnyOlderWindow: reading a chunk in ANY older window
// renames it into the current one. Promote-only-when-far-behind degrades to
// FIFO under pressure, so the rule is deliberately greedy.
func TestPromoteOnTouchFromAnyOlderWindow(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	data := randBytes(1024*2, 5)
	hash := f.seed("", data)

	cur := nowWindow()
	// One chunk one window back, one chunk a day back: both must move.
	plant(t, s, cur-1, chunkName(hash, 0), data[:1024])
	plant(t, s, cur-72, chunkName(hash, 1), data[1024:])
	s2 := reopen(t, s)

	file, err := s2.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	f.Server.Close() // the reads must be served from the cache, not refetched
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("promoted read differed")
	}
	for name, w := range cachedNames(t, s2) {
		if w != nowWindow() {
			t.Fatalf("%s stayed in window %d after a read, want %d", name, w, nowWindow())
		}
	}
	s2.mu.Lock()
	defer s2.mu.Unlock()
	for name, w := range s2.where {
		if w != nowWindow() {
			t.Fatalf("map still says %s is in window %d", name, w)
		}
	}
}

// TestSingleflightCollapsesConcurrentMisses: N readers landing on one cold
// chunk together cost ONE ranged GET.
func TestSingleflightCollapsesConcurrentMisses(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1<<16)
	data := randBytes(1<<16, 6)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	const readers = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, readers)
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			p := make([]byte, 64)
			off := int64(i * 37)
			if _, err := file.ReadAt(p, off); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(p, data[off:off+64]) {
				errs <- fmt.Errorf("reader %d got the wrong bytes", i)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := f.count("GET"); n != 1 {
		t.Fatalf("%d GETs for one cold chunk, want 1", n)
	}
}

// TestWholeWindowExpiresByAge: the TTL deletes window DIRECTORIES by name,
// regardless of disk fill. It is safe because a promotion's target is always
// the current window, so nothing anyone still reads can be sitting in one
// named thirty days ago.
func TestWholeWindowExpiresByAge(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024, func(c *Config) { c.CacheMaxAge = time.Hour })
	stopped(t, s)

	cur := nowWindow()
	h := strings.Repeat("b", 64)
	plant(t, s, cur-10, chunkName(h, 0), []byte("old")) // 200 minutes back
	plant(t, s, cur-1, chunkName(h, 1), []byte("new"))
	s2 := reopen(t, s)
	stopped(t, s2)

	s2.sweep()
	left := cachedNames(t, s2)
	if _, ok := left[chunkName(h, 0)]; ok {
		t.Fatal("a window past the max age survived")
	}
	if _, ok := left[chunkName(h, 1)]; !ok {
		t.Fatal("a window inside the max age was expired")
	}
	s2.mu.Lock()
	_, mapped := s2.where[chunkName(h, 0)]
	s2.mu.Unlock()
	if mapped {
		t.Fatal("the expired window is still in the map")
	}
}

// TestStrayTmpIsCollected: a fill killed between CreateTemp and the rename
// leaves a tmp nothing will ever finish. It is never a chunk (the name is not
// one) and it is collected once it is stale.
func TestStrayTmpIsCollected(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	stopped(t, s)

	cur := nowWindow()
	h := strings.Repeat("c", 64)
	fresh := chunkName(h, 0) + ".111.tmp"
	stale := chunkName(h, 1) + ".222.tmp"
	plant(t, s, cur, fresh, []byte("half"))
	plant(t, s, cur, stale, []byte("half"))
	old := time.Now().Add(-2 * tmpMaxAge)
	if err := os.Chtimes(filepath.Join(s.windowDir(cur), stale), old, old); err != nil {
		t.Fatal(err)
	}

	s.sweep()
	left := cachedNames(t, s)
	if _, ok := left[stale]; ok {
		t.Fatal("a stale tmp was not collected")
	}
	if _, ok := left[fresh]; !ok {
		t.Fatal("a tmp younger than the grace period was collected")
	}
	// And neither was ever mapped as a chunk.
	s2 := reopen(t, s)
	s2.mu.Lock()
	defer s2.mu.Unlock()
	if len(s2.where) != 0 {
		t.Fatalf("tmp files were mapped as chunks: %v", s2.where)
	}
}

// TestTornWriteNeverBecomesAChunk is the reason the fill fsyncs before it
// renames. A half-written file only ever carries a tmp name, so a reader can
// never open a correctly named chunk holding torn bytes: the read falls to S3
// and comes back right.
func TestTornWriteNeverBecomesAChunk(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	stopped(t, s)
	data := randBytes(1024*2, 8)
	hash := f.seed("", data)

	cur := nowWindow()
	torn := chunkName(hash, 0) + ".999.tmp"
	plant(t, s, cur, torn, data[:100]) // the write died a tenth of the way in

	s2 := reopen(t, s)
	if _, ok := cachedNames(t, s2)[chunkName(hash, 0)]; ok {
		t.Fatal("a torn tmp became a named chunk")
	}
	file, err := s2.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("the read after a torn write did not come back correct")
	}
}

// TestReadsTolerateChunksVanishing is ENOENT tolerance end to end: a sibling
// process (here, a goroutine) deleting the whole cache under live readers
// costs refetches and nothing else. Every answer stays byte-correct.
func TestReadsTolerateChunksVanishing(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 4096)
	data := randBytes(4096*16, 9)
	hash := f.seed("", data)

	stop := make(chan struct{})
	var deleter sync.WaitGroup
	deleter.Add(1)
	go func() {
		defer deleter.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, w := range s.windows() {
				os.RemoveAll(s.windowDir(w))
			}
			time.Sleep(time.Millisecond)
		}
	}()

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			file, err := s.Open(hash)
			if err != nil {
				errs <- err
				return
			}
			defer file.Close()
			for r := 0; r < 20; r++ {
				off := int64((i*7 + r*131) % (len(data) - 900))
				p := make([]byte, 900)
				if _, err := file.ReadAt(p, off); err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(p, data[off:off+900]) {
					errs <- fmt.Errorf("reader %d round %d read the wrong bytes at %d", i, r, off)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(stop)
	deleter.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// TestPreWindowCacheIsWiped covers the one-way trip off the sparse per-artifact
// cache: those files are simply not ours, and the cache is disposable, so
// there is no migration, only a delete.
func TestPreWindowCacheIsWiped(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	stopped(t, s)

	h := strings.Repeat("d", 64)
	shard := filepath.Join(s.cfg.CacheDir, h[:2])
	if err := os.MkdirAll(shard, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shard, h), randBytes(4096, 10), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.cfg.CacheDir, ".clean"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	s2 := reopen(t, s)
	ents, err := os.ReadDir(s2.cfg.CacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("pre-window cache survived: %v", ents)
	}
}

// TestViewSpansChunksAndCopiesAtBoundary is the whole cost of chunk files not
// being contiguous. Inside a chunk a slice aliases the mapping; across a
// boundary it is a copy, and either way the bytes are right.
func TestViewSpansChunksAndCopiesAtBoundary(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	data := randBytes(1024*5, 12)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	v, err := file.View(500, 3000)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if v.Len() != 3000 {
		t.Fatalf("view length %d, want 3000", v.Len())
	}
	if !bytes.Equal(v.Slice(0, 3000), data[500:3500]) {
		t.Fatal("whole-view slice differed")
	}
	// Inside one chunk: the same memory, not a copy.
	a := v.Slice(0, 100)
	b := v.Slice(0, 100)
	if &a[0] != &b[0] {
		t.Fatal("an in-chunk slice was copied")
	}
	// Across the boundary at absolute 1024, i.e. view offset 524.
	straddle := v.Slice(520, 16)
	if !bytes.Equal(straddle, data[1020:1036]) {
		t.Fatal("straddling slice differed")
	}
	if &straddle[0] == &v.Slice(520, 16)[0] {
		t.Fatal("a straddling slice aliased a mapping, which cannot be contiguous")
	}
	// The mapping outlives the file it came from: eviction is an unlink, and
	// unlinking never disturbs a mapping.
	for _, w := range s.windows() {
		os.RemoveAll(s.windowDir(w))
	}
	if !bytes.Equal(v.Slice(0, 3000), data[500:3500]) {
		t.Fatal("view changed when its chunk files were unlinked")
	}
}

// TestViewFromSpoolSurvivesRelease maps the spool file directly and keeps
// working across the Release that unlinks it.
func TestViewFromSpoolSurvivesRelease(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	data := randBytes(1024*3, 13)
	hash := hashOf(data)
	spool(t, s, hash, data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	v, err := file.View(0, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	mustSync(t, s)
	if err := s.Release(hash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v.Slice(0, int64(len(data))), data) {
		t.Fatal("the spool mapping changed after Release")
	}
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("reads through a released spool descriptor differed")
	}
	// Nothing was cached: the artifact was local the whole time.
	if n := len(cachedNames(t, s)); n != 0 {
		t.Fatalf("%d chunks cached for a spool-resident artifact, want 0", n)
	}
}

// TestSpoolToRemoteTransition walks the lifecycle: while the file is local
// every read is a pread of the spool file, and only once it is released and
// reopened does anything reach S3, through the chunk cache.
func TestSpoolToRemoteTransition(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	data := randBytes(1024*6, 14)
	hash := hashOf(data)
	spool(t, s, hash, data)

	local, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, local); !bytes.Equal(got, data) {
		t.Fatal("spool-resident read differed")
	}
	local.Close()
	if n := f.count("GET"); n != 0 {
		t.Fatalf("%d GETs while the file was local, want 0", n)
	}

	mustSync(t, s)
	if err := s.Release(hash); err != nil {
		t.Fatal(err)
	}
	remote, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	if got := readAll(t, remote); !bytes.Equal(got, data) {
		t.Fatal("post-release read differed")
	}
	if n := f.count("GET"); n != 6 {
		t.Fatalf("%d GETs for 6 cold chunks, want 6", n)
	}
	// And now it is warm: reading it again touches nothing.
	again, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	readAll(t, again)
	if n := f.count("GET"); n != 6 {
		t.Fatalf("%d GETs after warming, want 6", n)
	}
}

// TestSpoolRenameSurvivesRestart is the durability contract: a hash-named file
// renamed into the spool with no library call whatsoever is readable, and the
// next process to start up uploads it. Nothing else is recorded anywhere, so
// there is no ack that a kill can lose.
func TestSpoolRenameSurvivesRestart(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "epoch/", 1024)
	data := randBytes(4000, 15)
	hash := hashOf(data)
	spool(t, s, hash, data)

	s2 := reopen(t, s)
	file, err := s2.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("read after restart differed")
	}
	file.Close()
	if done := mustSync(t, s2); len(done) != 1 || done[0] != hash {
		t.Fatalf("Sync confirmed %v, want [%s]", done, hash)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !bytes.Equal(f.objects["epoch/"+hash], data) {
		t.Fatal("the bucket does not hold the spooled bytes")
	}
}

// TestSpoolNameMismatchRejected proves the name is verified against the bytes
// as they stream, and that the endpoint refuses to store them.
func TestSpoolNameMismatchRejected(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	name := hashOf([]byte("one thing"))
	spool(t, s, name, []byte("quite another"))

	if _, err := s.Sync(); err == nil || !strings.Contains(err.Error(), "refusing it") {
		t.Fatalf("Sync err=%v, want the name/content mismatch", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.objects[name]; ok {
		t.Fatal("mismatched bytes were stored")
	}
}

// TestStatsReportWhatHappened: the numbers are observations, not settings, and
// the horizon is empty until something is actually evicted.
func TestStatsReportWhatHappened(t *testing.T) {
	f := newFakeS3(t)
	var free atomic.Int64
	free.Store(1 << 30)
	s := newStore(t, f, "", 1024, fakeDisk(&free, 1<<20))
	stopped(t, s)
	st := s.Stats()
	if st.MinFree != 1<<20 || st.FreeBytes != 1<<30 {
		t.Fatalf("stats = %+v, want the watermark and the free bytes reported back", st)
	}
	if st.VictimAge != 0 || st.Evictions != 0 || st.Refusals != 0 {
		t.Fatalf("stats = %+v before any traffic, want zeroes", st)
	}
}

// deadCreds is an expired SSO session: every request that needs a signature
// fails before a socket is opened. A store built on it is the node whose token
// went stale overnight.
type deadCreds struct{}

func (deadCreds) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, errors.New("InvalidGrantException")
}

// deadStore has an unusable credential provider and an endpoint nothing is
// listening on, so anything that reaches for the bucket is guaranteed to fail
// loudly.
func deadStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	s, err := New(Config{
		Endpoint:     "http://127.0.0.1:1",
		Bucket:       "epochs",
		Prefix:       "epoch/",
		Credentials:  deadCreds{},
		SpoolDir:     filepath.Join(root, "spool"),
		CacheDir:     filepath.Join(root, "cache"),
		CacheMinFree: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestPointersAreLocalFirst is the ruling of 2026-08-02: a producer whose
// credentials are gone keeps setting and reading its own pointers, forever,
// because neither call goes near the network. Only uploads stall.
func TestPointersAreLocalFirst(t *testing.T) {
	s := deadStore(t)
	if err := s.SetPointer("latest", "epoch abc\n"); err != nil {
		t.Fatalf("SetPointer with dead credentials: %v", err)
	}
	if v, err := s.GetPointer("latest"); err != nil || v != "epoch abc\n" {
		t.Fatalf("GetPointer = %q, %v", v, err)
	}
	// Overwriting before any reconcile is fine: the newest value is the one
	// on disk, and the only one that will ever be uploaded.
	if err := s.SetPointer("latest", "epoch def\n"); err != nil {
		t.Fatal(err)
	}
	// A nested name (epochdb publishes chunks/<hash>) is a nested file.
	if err := s.SetPointer("chunks/"+strings.Repeat("a", 63), "x"); err != nil {
		t.Fatal(err)
	}

	s2 := reopen(t, s)
	if v, err := s2.GetPointer("latest"); err != nil || v != "epoch def\n" {
		t.Fatalf("after reopen GetPointer = %q, %v", v, err)
	}
	if v, err := s2.GetPointer("chunks/" + strings.Repeat("a", 63)); err != nil || v != "x" {
		t.Fatalf("after reopen nested GetPointer = %q, %v", v, err)
	}
	// Nothing can be uploaded, so nothing is released: the values sit in the
	// spool and the node keeps working off them, forever.
	if done, err := s2.Sync(); len(done) != 0 || err == nil {
		t.Fatalf("Sync of pointers only: done=%v err=%v, want no content and a credentials error", done, err)
	}
	if _, err := os.Stat(s2.pointerPath("latest")); err != nil {
		t.Fatalf("an unuploadable pointer left the spool: %v", err)
	}
	if v, err := s2.GetPointer("latest"); err != nil || v != "epoch def\n" {
		t.Fatalf("after a failed reconcile GetPointer = %q, %v", v, err)
	}
}

// TestSyncUploadsContentBeforePointers pins the reconcile order. A pointer
// names content, so it may only become visible in the bucket after that
// content is there, and not at all while some artifact is still failing.
func TestSyncUploadsContentBeforePointers(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "epoch/", 1024)

	var hashes []string
	for i := 0; i < 3; i++ {
		data := randBytes(2000, int64(i))
		hashes = append(hashes, hashOf(data))
		spool(t, s, hashOf(data), data)
	}
	if err := s.SetPointer("latest", "epoch "+hashes[2]); err != nil {
		t.Fatal(err)
	}
	mustSync(t, s)

	f.mu.Lock()
	puts := append([]string(nil), f.puts...)
	f.mu.Unlock()
	if len(puts) != 4 || puts[3] != "epoch/latest" {
		t.Fatalf("PUT order %v, want the three artifacts then epoch/latest", puts)
	}

	// Confirmed in the bucket, so the local copy is released exactly like an
	// artifact's, and the next read re-materializes it from the bucket.
	if _, err := os.Stat(s.pointerPath("latest")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("an uploaded pointer stayed in the spool: %v", err)
	}
	if v, err := s.GetPointer("latest"); err != nil || v != "epoch "+hashes[2] {
		t.Fatalf("GetPointer after release = %q, %v", v, err)
	}
	if _, err := os.Stat(s.pointerPath("latest")); err != nil {
		t.Fatalf("the bucket read did not re-materialize the pointer: %v", err)
	}
	// Re-materialized clean: a store must not re-upload a value it read.
	before := f.count("PUT")
	mustSync(t, s)
	if n := f.count("PUT"); n != before {
		t.Fatalf("re-materialized pointer was re-uploaded: %d PUTs, want %d", n, before)
	}

	// A pass that cannot upload some artifact publishes NO pointer: the
	// pointer would name content the bucket does not have.
	spool(t, s, hashOf([]byte("lies")), []byte("different bytes entirely"))
	if err := s.SetPointer("latest", "epoch "+hashOf([]byte("lies"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sync(); err == nil {
		t.Fatal("Sync with a lying spool file reported success")
	}
	f.mu.Lock()
	got := string(f.objects["epoch/latest"])
	f.mu.Unlock()
	if got != "epoch "+hashes[2] {
		t.Fatalf("bucket pointer = %q after a failed pass, want the last cleanly synced value", got)
	}
}

// TestGetPointerFallsBackToBucket is the fresh consumer: it has never written
// this name, so the only copy is the bucket's, and a bucket that cannot be
// read is an error, never a guess.
func TestGetPointerFallsBackToBucket(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "epoch/", 1024)
	f.mu.Lock()
	f.objects["epoch/latest"] = []byte("epoch 1234\n")
	f.mu.Unlock()

	if v, err := s.GetPointer("latest"); err != nil || v != "epoch 1234\n" {
		t.Fatalf("consumer GetPointer = %q, %v", v, err)
	}
	if _, err := s.GetPointer("nothing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing pointer err=%v, want fs.ErrNotExist", err)
	}

	// The same read on a store that cannot reach the bucket bubbles the real
	// failure rather than inventing an answer.
	dead := deadStore(t)
	_, err := dead.GetPointer("latest")
	if err == nil || !strings.Contains(err.Error(), "InvalidGrantException") {
		t.Fatalf("unreadable bucket pointer err=%v, want the credential failure", err)
	}
}

func TestSyncIsIdempotent(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	data := randBytes(3000, 7)
	hash := hashOf(data)
	spool(t, s, hash, data)

	mustSync(t, s)
	if n := f.count("PUT"); n != 1 {
		t.Fatalf("first Sync issued %d PUTs, want 1", n)
	}
	mustSync(t, s) // spool file is still there, bucket already has it
	if n := f.count("PUT"); n != 1 {
		t.Fatalf("second Sync issued %d PUTs total, want 1", n)
	}

	// A second store, so no in-memory state can be doing the work.
	s2 := newStore(t, f, "", 1024)
	spool(t, s2, hash, data)
	if done := mustSync(t, s2); len(done) != 1 || done[0] != hash {
		t.Fatalf("Sync confirmed %v, want [%s]", done, hash)
	}
	if n := f.count("PUT"); n != 1 {
		t.Fatalf("re-Sync from a fresh store issued %d PUTs total, want 1", n)
	}

	// Release works off a HEAD alone, with no Sync in this process.
	s3 := newStore(t, f, "", 1024)
	spool(t, s3, hash, data)
	if err := s3.Release(hash); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s3.SpoolPath(hash)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Release left the spool file behind: %v", err)
	}
}

// TestValidChunkName is the name rule the whole layout rests on: a chunk is a
// hash, a dot and an index, and nothing else in the tree is ever mistaken for
// one.
func TestValidChunkName(t *testing.T) {
	h := strings.Repeat("a", 64)
	for _, ok := range []string{h + ".0", h + ".17", h + ".999999"} {
		if !validChunkName(ok) {
			t.Fatalf("%s was rejected", ok)
		}
	}
	for _, bad := range []string{h, h + ".", "." + h, h + ".0.1.tmp", h + ".0.tmp",
		h[:63] + ".0", strings.Repeat("g", 64) + ".0", h + ".x", ".clean", ""} {
		if validChunkName(bad) {
			t.Fatalf("%s was accepted", bad)
		}
	}
	// A generated tmp name is never a chunk name, whatever CreateTemp picks.
	f, err := os.CreateTemp(t.TempDir(), chunkName(h, 3)+".*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if validChunkName(filepath.Base(f.Name())) {
		t.Fatalf("%s was accepted as a chunk", filepath.Base(f.Name()))
	}
}

// TestWindowIsUTCTwentyMinutes pins the bucket arithmetic: integer
// unix_minutes/20, never local time.
func TestWindowIsUTCTwentyMinutes(t *testing.T) {
	base := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	if window(base) != window(base.Add(19*time.Minute)) {
		t.Fatal("19 minutes crossed a window")
	}
	if window(base)+1 != window(base.Add(20*time.Minute)) {
		t.Fatal("20 minutes did not advance the window by one")
	}
	// Same instant, different clock: same window.
	tokyo, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skip("no tzdata")
	}
	if window(base) != window(base.In(tokyo)) {
		t.Fatal("the window depended on the location of the clock")
	}
	if got := window(time.Unix(1200*1234, 0)); got != 1234 {
		t.Fatalf("window = %d, want 1234", got)
	}
}
