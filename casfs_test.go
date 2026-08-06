package casfs

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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
		Namespace:    "chainA",
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

// artifactOf builds a STORED OBJECT out of content the way a producer does:
// content, then the chunk hash list, then the trailer. Tests use it rather
// than the library's own writers so the format is exercised from the outside.
func artifactOf(t *testing.T, data []byte, cs int64) (string, []byte) {
	t.Helper()
	h := NewHasher(cs)
	h.Write(data)
	name, tail, err := h.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return name, append(append([]byte(nil), data...), tail...)
}

// spool writes an artifact straight into the spool dir under a CHOSEN name,
// with no library call at all. That rename is the whole registration protocol.
// The name is chosen rather than derived so a test can spool a file whose name
// lies about its contents.
func spool(t *testing.T, s *Store, name string, data []byte) {
	t.Helper()
	_, obj := artifactOf(t, data, s.cfg.ChunkSize)
	tmp := filepath.Join(s.cfg.SpoolDir, ".staging")
	if err := os.WriteFile(tmp, obj, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, s.SpoolPath(name)); err != nil {
		t.Fatal(err)
	}
}

// seed drops content straight into the fake bucket, so the store has never seen
// it locally.
func (f *fakeS3) seed(t *testing.T, s *Store, prefix string, data []byte) string {
	t.Helper()
	name, obj := artifactOf(t, data, s.cfg.ChunkSize)
	f.mu.Lock()
	f.objects[prefix+name] = obj
	f.mu.Unlock()
	return name
}

// hashOf is the artifact NAME of this content: sha256 of its chunk hash list.
func hashOf(t *testing.T, s *Store, data []byte) string {
	t.Helper()
	name, _ := artifactOf(t, data, s.cfg.ChunkSize)
	return name
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

// cachedNames is every file in this store's part of the window tree, mapped to
// the window it sits in.
func cachedNames(t *testing.T, s *Store) map[string]string {
	t.Helper()
	out := map[string]string{}
	ws, err := s.windows()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range ws {
		ents, err := os.ReadDir(s.chunkDir(w))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			t.Fatal(err)
		}
		for _, e := range ents {
			out[e.Name()] = w
		}
	}
	return out
}

// winBack is the window n buckets before the current one, which is how a test
// makes the cache look old without waiting twenty minutes.
func winBack(n int) string {
	return windowName(time.Now().Add(-time.Duration(n) * windowMinutes * time.Minute))
}

// plant puts a file straight into a chosen window, under an owner (empty means
// this store's own).
func plant(t *testing.T, s *Store, w, ns, name string, data []byte) {
	t.Helper()
	if ns == "" {
		ns = s.cfg.Namespace
	}
	dir := filepath.Join(s.windowDir(w), ns)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
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
	if hash != hashOf(t, s, data) {
		t.Fatalf("Put returned %s, want %s", hash, hashOf(t, s, data))
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
	cur := curWindow()
	for i := int64(0); i < nchunks(int64(len(data)), 4096); i++ {
		name := chunkName(hash, i)
		w, ok := names[name]
		if !ok {
			t.Fatalf("chunk %s was not cached", name)
		}
		if w != cur {
			t.Fatalf("chunk %s landed in window %s, want the current one %s", name, w, cur)
		}
	}
}

func TestReadAtCrossesChunkBoundaries(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	data := randBytes(1024*5+7, 2)
	hash := f.seed(t, s, "", data)

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
	hash := f.seed(t, s, "", data)

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
	hash := f.seed(t, s, "", data)

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
	hash := f.seed(t, s, "", data)

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

// TestWorkerDropsWholeWindowsOldestFirst is the eviction contract: the oldest
// window goes ENTIRELY, in one rm -r, oldest first, and when only the current
// window is left the worker STOPS. A saturated cache freezes full rather than
// eating its own fresh fills, which is what admission control is there for.
//
// A whole window is the unit because the names sort chronologically, so the
// first entry of a sorted readdir IS the oldest cohort: no victim selection,
// no cursor, no scan. Every owner sharing that window goes with it.
func TestWorkerDropsWholeWindowsOldestFirst(t *testing.T) {
	f := newFakeS3(t)
	var free atomic.Int64
	free.Store(0) // permanently over the watermark
	s := newStore(t, f, "", 1024, fakeDisk(&free, 1<<20))
	stopped(t, s)

	cur := curWindow()
	old, mid := winBack(5), winBack(2)
	h := strings.Repeat("a", 64)
	for i, w := range []string{old, mid, cur} {
		for j := 0; j < 3; j++ {
			plant(t, s, w, "", chunkName(h, int64(i*10+j)), []byte("x"))
		}
		// A second owner in the same window, to prove a drop is per COHORT and
		// not per owner.
		plant(t, s, w, "chainB", chunkName(h, int64(i*10+9)), []byte("y"))
	}
	// Rebuild the map by hand rather than reopening: a fresh store would start
	// its own worker, and over this watermark it would evict before the test
	// could look.
	s2 := s
	if err := s2.scanCache(); err != nil {
		t.Fatal(err)
	}

	if !s2.evictOldest() {
		t.Fatal("the worker found nothing to drop")
	}
	if got, _ := s2.windows(); len(got) != 2 || got[0] != mid {
		t.Fatalf("windows after one drop = %v, want [%s %s]", got, mid, cur)
	}
	if _, err := os.Stat(s2.windowDir(old)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the oldest window survived its drop: %v", err)
	}
	if len(cachedNames(t, s2)) != 6 {
		t.Fatalf("%d files left, want 6", len(cachedNames(t, s2)))
	}
	s2.mu.Lock()
	mapped := len(s2.where)
	s2.mu.Unlock()
	if mapped != 6 {
		t.Fatalf("the map still holds %d chunks, want 6", mapped)
	}

	if !s2.evictOldest() {
		t.Fatal("the worker stopped with a non-current window still there")
	}
	if s2.evictOldest() {
		t.Fatal("the worker dropped the current window")
	}
	if got, _ := s2.windows(); len(got) != 1 || got[0] != cur {
		t.Fatalf("windows = %v, want only the current one", got)
	}
	// The horizon is the age of what it actually dropped, not a setting.
	st := s2.Stats()
	if st.Evictions != 2 {
		t.Fatalf("evictions = %d, want 2 windows", st.Evictions)
	}
	if st.VictimAge < 40*time.Minute || st.VictimAge > 70*time.Minute {
		t.Fatalf("victim age = %v, want about 40m", st.VictimAge)
	}
}

// TestPromoteOnTouchFromAnyOlderWindow: reading a chunk in ANY older window
// renames it into the current one. Promote-only-when-far-behind degrades to
// FIFO under pressure, so the rule is deliberately greedy.
func TestPromoteOnTouchFromAnyOlderWindow(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	data := randBytes(1024*2, 5)
	hash := f.seed(t, s, "", data)

	// One chunk one window back, one chunk a day back: both must move.
	plant(t, s, winBack(1), "", chunkName(hash, 0), data[:1024])
	plant(t, s, winBack(72), "", chunkName(hash, 1), data[1024:])
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
		if w != curWindow() {
			t.Fatalf("%s stayed in window %s after a read, want %s", name, w, curWindow())
		}
	}
	s2.mu.Lock()
	defer s2.mu.Unlock()
	for name, w := range s2.where {
		if w != curWindow() {
			t.Fatalf("map still says %s is in window %s", name, w)
		}
	}
}

// TestSingleflightCollapsesConcurrentMisses: N readers landing on one cold
// chunk together cost ONE ranged GET.
func TestSingleflightCollapsesConcurrentMisses(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1<<16)
	data := randBytes(1<<16, 6)
	hash := f.seed(t, s, "", data)

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

	h := strings.Repeat("b", 64)
	plant(t, s, winBack(10), "", chunkName(h, 0), []byte("old")) // 200 minutes back
	plant(t, s, winBack(1), "", chunkName(h, 1), []byte("new"))
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

	cur := curWindow()
	h := strings.Repeat("c", 64)
	fresh := chunkName(h, 0) + ".111.tmp"
	stale := chunkName(h, 1) + ".222.tmp"
	plant(t, s, cur, "", fresh, []byte("half"))
	plant(t, s, cur, "", stale, []byte("half"))
	old := time.Now().Add(-2 * tmpMaxAge)
	if err := os.Chtimes(filepath.Join(s.chunkDir(cur), stale), old, old); err != nil {
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
	hash := f.seed(t, s, "", data)

	torn := chunkName(hash, 0) + ".999.tmp"
	plant(t, s, curWindow(), "", torn, data[:100]) // the write died a tenth in

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

// TestReadsTolerateChunksVanishing is ENOENT tolerance end to end, exercised
// the way the worker actually evicts: whole windows disappear from under live
// readers, which costs refetches and nothing else. Every answer stays
// byte-correct.
func TestReadsTolerateChunksVanishing(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 4096)
	data := randBytes(4096*16, 9)
	hash := f.seed(t, s, "", data)

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
			ws, _ := s.windows()
			for _, w := range ws {
				os.RemoveAll(s.windowDir(w)) // a cohort drop, the real operation
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
	hash := f.seed(t, s, "", data)

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
	ws, _ := s.windows()
	for _, w := range ws {
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
	hash := hashOf(t, s, data)
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
	hash := hashOf(t, s, data)
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
	hash := hashOf(t, s, data)
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
	_, obj := artifactOf(t, data, s2.cfg.ChunkSize)
	f.mu.Lock()
	defer f.mu.Unlock()
	if !bytes.Equal(f.objects["epoch/"+hash], obj) {
		t.Fatal("the bucket does not hold the spooled bytes")
	}
}

// TestSpoolNameMismatchRejected: a spool file whose name does not match the
// chunk list its own content produces is refused by the pre-pass, BEFORE a
// byte goes out. The endpoint's payload-hash check can no longer stand in for
// this, because the signed digest is now the stored object's sha256 and the
// name is sha256 of the hash list, so only casfs can tell the two apart.
func TestSpoolNameMismatchRejected(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	name := hashOf(t, s, []byte("one thing"))
	spool(t, s, name, []byte("quite another"))

	if _, err := s.Sync(); err == nil || !strings.Contains(err.Error(), "refusing it") {
		t.Fatalf("Sync err=%v, want the name/content mismatch", err)
	}
	if n := f.count("PUT"); n != 0 {
		t.Fatalf("%d PUTs for a file whose name lies, want 0", n)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.objects[name]; ok {
		t.Fatal("mismatched bytes were stored")
	}
}

// putTransport is a bucket that never runs. HEAD always misses, so the store
// goes on to upload; PUT either dies after failAfter bytes, or (failAfter < 0)
// accepts the body WITHOUT checking the signed payload hash, which is what an
// endpoint that does not verify looks like.
type putTransport struct{ failAfter int64 }

func (t putTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	reply := func(code int, body string) *http.Response {
		return &http.Response{
			StatusCode: code,
			Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    r,
		}
	}
	if r.Method != http.MethodPut {
		return reply(http.StatusNotFound, "<Error><Code>NoSuchKey</Code></Error>"), nil
	}
	defer r.Body.Close()
	if t.failAfter >= 0 {
		io.CopyN(io.Discard, r.Body, t.failAfter)
		return nil, errors.New("connection reset by peer")
	}
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		return nil, err
	}
	return reply(http.StatusOK, ""), nil
}

// transportStore is a store whose whole bucket is one RoundTripper.
func transportStore(t *testing.T, rt http.RoundTripper) *Store {
	t.Helper()
	root := t.TempDir()
	s, err := New(Config{
		Endpoint:     "http://bucket.invalid",
		Bucket:       "epochs",
		AccessKey:    "minioadmin",
		SecretKey:    "minioadmin",
		SpoolDir:     filepath.Join(root, "spool"),
		CacheDir:     filepath.Join(root, "cache"),
		CacheMinFree: 1,
		HTTPClient:   &http.Client{Transport: rt},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestUploadFailureIsNeverCalledCorruption is the Fuji publisher of 2026-08-04:
// four epochs failed to upload on an expired SSO token and the operator was
// told their sealed history hashed to something else, because the digest was
// judged over the prefix the dead PUT had consumed. An upload that failed says
// NOTHING about the file.
func TestUploadFailureIsNeverCalledCorruption(t *testing.T) {
	s := transportStore(t, putTransport{failAfter: 16})
	data := randBytes(4000, 21)
	hash := hashOf(t, s, data)
	spool(t, s, hash, data)

	_, err := s.Sync()
	if err == nil {
		t.Fatal("Sync succeeded against an endpoint that drops every PUT")
	}
	if !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("Sync err=%v, want the upload failure named", err)
	}
	if strings.Contains(err.Error(), "hashing to") || strings.Contains(err.Error(), "refusing it") {
		t.Fatalf("a failed upload was reported as corrupt content: %v", err)
	}
	// And the file it accused is exactly what it always was.
	_, want := artifactOf(t, data, s.cfg.ChunkSize)
	got, err := os.ReadFile(s.SpoolPath(hash))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("spool file changed under a failed upload: %v", err)
	}
}

// TestMultipartRoundTripOverTheThreshold: a spool file too big for one PUT
// (the real threshold is 5 GiB, here it is kilobytes) goes up in parts and comes
// back byte-identical through ordinary ranged GETs. The 8.85GB Fuji epoch that
// wedged the drain on 2026-08-04 is this case.
func TestMultipartRoundTripOverTheThreshold(t *testing.T) {
	defer func(th, ps int64) { multipartThreshold, partSize = th, ps }(multipartThreshold, partSize)
	multipartThreshold, partSize = 4096, 4096

	f := newFakeS3(t)
	s := newStore(t, f, "epoch/", 1024)
	data := randBytes(10_000, 31) // three parts, the last one short
	hash := hashOf(t, s, data)
	spool(t, s, hash, data)

	if done := mustSync(t, s); len(done) != 1 || done[0] != hash {
		t.Fatalf("Sync confirmed %v, want [%s]", done, hash)
	}
	f.mu.Lock()
	stored := f.objects["epoch/"+hash]
	f.mu.Unlock()
	// THE SAME BYTES AND THE SAME NAME AS A SINGLE PUT WOULD HAVE PRODUCED:
	// the name is a function of the content, never of how it went up.
	wantName, wantObj := artifactOf(t, data, s.cfg.ChunkSize)
	if wantName != hash {
		t.Fatalf("multipart named the artifact %s, a single PUT names it %s", hash, wantName)
	}
	if !bytes.Equal(stored, wantObj) {
		t.Fatalf("assembled object is %d bytes, want %d", len(stored), len(wantObj))
	}
	if f.count("PUT") != 3 {
		t.Fatalf("%d part PUTs, want 3", f.count("PUT"))
	}

	// And it reads back the way any other artifact does, from the bucket only.
	if err := s.Release(hash); err != nil {
		t.Fatal(err)
	}
	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("post-release read of a multipart object differed")
	}

	// A file under the threshold still goes up whole: one PUT, no upload id.
	small := randBytes(1000, 32)
	spool(t, s, hashOf(t, s, small), small)
	mustSync(t, s)
	if f.count("PUT") != 4 {
		t.Fatalf("%d PUTs after a small file, want 4 (3 parts + 1 whole)", f.count("PUT"))
	}
}

// TestMultipartNameLieIsRefusedBeforeAnythingIsStored: multipart signs parts,
// not the whole object, so the endpoint cannot catch a lying name for us. The
// pre-pass must, and nothing may reach the bucket.
func TestMultipartNameLieIsRefusedBeforeAnythingIsStored(t *testing.T) {
	defer func(th, ps int64) { multipartThreshold, partSize = th, ps }(multipartThreshold, partSize)
	multipartThreshold, partSize = 4096, 4096

	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	name := hashOf(t, s, randBytes(10_000, 34))
	spool(t, s, name, randBytes(10_000, 35))

	if _, err := s.Sync(); err == nil || !strings.Contains(err.Error(), "refusing it") {
		t.Fatalf("Sync err=%v, want the name/content mismatch", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.objects[name]; ok {
		t.Fatal("mismatched bytes were stored under a good name")
	}
	if f.counts["POST"] != 0 { // holding f.mu already, so not f.count
		t.Fatal("the upload was initiated before the name was checked")
	}
}

// TestMultipartCompletionErrorInA200IsAFailure: S3 answers
// CompleteMultipartUpload with 200 OK and an Error body, because the status
// line is written before it finishes assembling the object. Believing the
// status would report an upload that does not exist, and the caller would then
// release the only durable copy.
func TestMultipartCompletionErrorInA200IsAFailure(t *testing.T) {
	defer func(th, ps int64) { multipartThreshold, partSize = th, ps }(multipartThreshold, partSize)
	multipartThreshold, partSize = 4096, 4096

	f := newFakeS3(t)
	f.failComplete = true
	s := newStore(t, f, "", 1024)
	data := randBytes(10_000, 33)
	hash := hashOf(t, s, data)
	spool(t, s, hash, data)

	done, err := s.Sync()
	if err == nil || !strings.Contains(err.Error(), "InternalError") {
		t.Fatalf("Sync err=%v, want the completion error", err)
	}
	if len(done) != 0 {
		t.Fatalf("Sync confirmed %v after a failed completion", done)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.objects[hash]; ok {
		t.Fatal("a failed completion stored an object anyway")
	}
	if len(f.uploads) != 0 {
		t.Fatalf("%d uploads left dangling, want the abort to have cleaned up", len(f.uploads))
	}
}

// TestSpoolNameLieCaughtOnASuccessfulPut is the other half: once the put
// SUCCEEDED, the digest covers the whole file, so a mismatch really is a file
// lying about its name. This is the endpoint that does not verify the payload
// hash itself, which is the only reason the local check exists.
func TestSpoolNameLieCaughtOnASuccessfulPut(t *testing.T) {
	s := transportStore(t, putTransport{failAfter: -1})
	name := hashOf(t, s, []byte("one thing"))
	spool(t, s, name, []byte("quite another"))

	if _, err := s.Sync(); err == nil || !strings.Contains(err.Error(), "refusing it") {
		t.Fatalf("Sync err=%v, want the name/content mismatch", err)
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
		hashes = append(hashes, hashOf(t, s, data))
		spool(t, s, hashOf(t, s, data), data)
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
	spool(t, s, hashOf(t, s, []byte("lies")), []byte("different bytes entirely"))
	if err := s.SetPointer("latest", "epoch "+hashOf(t, s, []byte("lies"))); err != nil {
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

// TestSpoolPointerWrittenWithoutAStore is the offline producer: a process with
// no credentials has no Store at all, so the pointer it writes has to be
// findable by the credentialed process that comes later. WriteSpoolPointer puts
// it where New's scan looks, and the first Sync after that publishes it with
// the ordering intact, WITHOUT the producer authoring a new value.
func TestSpoolPointerWrittenWithoutAStore(t *testing.T) {
	f := newFakeS3(t)
	root := t.TempDir()
	spoolDir := filepath.Join(root, "spool")

	// No store exists yet: this is the no-credentials process.
	if err := WriteSpoolPointer(spoolDir, "latest-abc", "epoch deadbeef\n"); err != nil {
		t.Fatal(err)
	}
	// And a name that would collide with the content-address space is refused
	// here exactly as it is on a store.
	if err := WriteSpoolPointer(spoolDir, strings.Repeat("a", 64), "x"); err == nil {
		t.Fatal("a hash-shaped pointer name was accepted")
	}

	s := newStore(t, f, "epoch/", 1024, func(c *Config) { c.SpoolDir = spoolDir })
	data := randBytes(2000, 7)
	spool(t, s, hashOf(t, s, data), data)
	mustSync(t, s)

	f.mu.Lock()
	puts := append([]string(nil), f.puts...)
	got := string(f.objects["epoch/latest-abc"])
	f.mu.Unlock()
	if got != "epoch deadbeef\n" {
		t.Fatalf("bucket pointer = %q, want the value the offline process wrote", got)
	}
	if len(puts) != 2 || puts[1] != "epoch/latest-abc" {
		t.Fatalf("PUT order %v, want the artifact then the pointer", puts)
	}
}

// TestPrefixHasObjects: the one question that separates "nobody has published
// here" from "somebody has, and the pointer is missing".
func TestPrefixHasObjects(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "epoch/", 1024)
	if has, err := s.PrefixHasObjects(); err != nil || has {
		t.Fatalf("empty prefix: has=%v err=%v", has, err)
	}
	// A sibling prefix is not this one.
	f.mu.Lock()
	f.objects["other/thing"] = []byte("x")
	f.mu.Unlock()
	if has, err := s.PrefixHasObjects(); err != nil || has {
		t.Fatalf("another prefix's object counted: has=%v err=%v", has, err)
	}
	data := randBytes(2000, 3)
	spool(t, s, hashOf(t, s, data), data)
	mustSync(t, s)
	if has, err := s.PrefixHasObjects(); err != nil || !has {
		t.Fatalf("after an upload: has=%v err=%v", has, err)
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
	hash := hashOf(t, s, data)
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

// TestWindowNamesSortChronologically is the pin the whole layout rests on: the
// names are fixed-width UTC bucket starts, so ALPHABETICAL ORDER IS
// CHRONOLOGICAL ORDER, which is what lets eviction be "rm -r the first
// directory". A name must also parse back to exactly the instant it came from.
func TestWindowNamesSortChronologically(t *testing.T) {
	base := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	if got := windowName(base.Add(47 * time.Minute)); got != "2026-08-03T12-40" {
		t.Fatalf("windowName = %q, want 2026-08-03T12-40", got)
	}
	if windowName(base) != windowName(base.Add(19*time.Minute)) {
		t.Fatal("19 minutes crossed a window")
	}
	if windowName(base) == windowName(base.Add(20*time.Minute)) {
		t.Fatal("20 minutes did not advance the window")
	}

	// Increasing times must produce increasing names, across every boundary
	// that could break a fixed-width format: minute, hour, day, month, year.
	var prev string
	for _, at := range []time.Time{
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 0, 20, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 0, 40, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 9, 40, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 23, 40, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 9, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 31, 23, 40, 0, 0, time.UTC),
		time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 9, 30, 23, 40, 0, 0, time.UTC),
		time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 12, 31, 23, 40, 0, 0, time.UTC),
		time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		name := windowName(at)
		if name <= prev {
			t.Fatalf("%s does not sort after %s, so chronological order is not alphabetical order", name, prev)
		}
		got, ok := windowAt(name)
		if !ok || !got.Equal(at) {
			t.Fatalf("windowAt(%s) = %v, %v, want %v", name, got, ok, at)
		}
		prev = name
	}
	// And ReadDir's own sort has to agree, since that is what the worker uses.
	dir := t.TempDir()
	names := []string{"2026-10-01T00-00", "2026-02-01T00-00", "2027-01-01T00-00", "2026-01-01T00-20"}
	for _, n := range names {
		if err := os.MkdirAll(filepath.Join(dir, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2026-01-01T00-20", "2026-02-01T00-00", "2026-10-01T00-00", "2027-01-01T00-00"}
	for i, e := range ents {
		if e.Name() != want[i] {
			t.Fatalf("ReadDir order %d = %s, want %s", i, e.Name(), want[i])
		}
	}

	// Anything that does not round-trip is not one of ours, which is the whole
	// rejection rule: a minute field off the grid, a stray, a legacy layout.
	for _, bad := range []string{"2026-08-03T12-41", "2026-08-03T12", "2026-08-03",
		"1786132800", "ab", ".clean", "", "2026-13-03T12-00"} {
		if _, ok := windowAt(bad); ok {
			t.Fatalf("%q was accepted as a window", bad)
		}
	}
}

// TestNamespaceMustBeOnePathElement: the namespace names a directory this
// store creates and deletes inside, and epochdb feeds it a data directory's
// name, so it may never be a path that walks out of the cache root.
func TestNamespaceMustBeOnePathElement(t *testing.T) {
	f := newFakeS3(t)
	root := t.TempDir()
	for _, bad := range []string{"..", ".", "a/b", "/abs", "a/"} {
		_, err := New(Config{
			Endpoint: f.URL, Bucket: f.bucket, AccessKey: "a", SecretKey: "b",
			SpoolDir: filepath.Join(root, "spool"), CacheDir: filepath.Join(root, "cache"),
			Namespace: bad, CacheMinFree: 1,
		})
		if err == nil {
			t.Fatalf("namespace %q was accepted", bad)
		}
	}
}

// TestRangeAnsweredFromTheWrongOffsetIsRefused: a range answered from an
// offset nobody asked for is refused on the Content-Range start, before the
// bytes are even hashed. Since the chunk list went in this is a cheap early
// out rather than the integrity check (VerifyChunk would catch the same bytes
// a moment later), but it names the failure far better than a hash mismatch.
func TestRangeAnsweredFromTheWrongOffsetIsRefused(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	data := randBytes(1024*3, 9)
	hash := f.seed(t, s, "", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	f.setRangeShift(1024) // every range answered one chunk late
	if _, err := file.ReadAt(make([]byte, 1024), 0); err == nil {
		t.Fatal("a range answered from the wrong offset was accepted as content")
	}
	if _, ok := cachedNames(t, s)[chunkName(hash, 0)]; ok {
		t.Fatal("a chunk from a mis-answered range was cached")
	}

	// The same store reads fine the moment the bucket answers honestly, so the
	// check costs nothing on the good path.
	f.setRangeShift(0)
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("honest ranges returned the wrong bytes")
	}
}

// TestStatfsFailureNeverEvicts: an unreadable disk is not a full one. The
// worker used to read a statfs error as "not roomy" and drop one window per
// settleDelay until the whole cache was gone, while Stats reported zero free
// bytes, i.e. the one explanation that was certainly wrong.
func TestStatfsFailureNeverEvicts(t *testing.T) {
	f := newFakeS3(t)
	var (
		broken atomic.Bool
		free   atomic.Int64
	)
	free.Store(1 << 30)
	s := newStore(t, f, "", 1024, func(c *Config) {
		c.CacheMinFree = 1 << 20
		c.free = func(string) (int64, error) {
			if broken.Load() {
				return 0, errors.New("statfs: transport endpoint is not connected")
			}
			return free.Load(), nil
		}
	})
	stopped(t, s) // drive the worker's decision by hand

	data := randBytes(1024, 11)
	plant(t, s, winBack(3), "", chunkName(hashOf(t, s, data), 0), data)

	broken.Store(true)
	if s.step() {
		t.Fatal("a statfs failure evicted a window")
	}
	if n := len(cachedNames(t, s)); n != 1 {
		t.Fatalf("%d cached files after a statfs failure, want the window untouched", n)
	}
	st := s.Stats()
	if st.EvictErrors == 0 || st.LastError == "" {
		t.Fatalf("stats = %+v, want the statfs failure counted and named", st)
	}
	if st.FreeBytes != -1 {
		t.Fatalf("FreeBytes = %d on a failed statfs, want -1 rather than a fake 'disk full'", st.FreeBytes)
	}

	// A statfs that WORKS and says the disk is full still evicts: the fix is
	// about the unknown, not about eviction.
	broken.Store(false)
	free.Store(0)
	if !s.step() {
		t.Fatal("a genuinely full disk did not evict")
	}
	if n := len(cachedNames(t, s)); n != 0 {
		t.Fatalf("%d cached files after a real eviction, want 0", n)
	}
}

// TestFillFailuresAreCounted: a cache directory that cannot be written turns
// the node into an S3 passthrough. That is a legitimate degraded mode and it
// used to be completely silent, Refusals included, so nothing distinguished it
// from a healthy node.
func TestFillFailuresAreCounted(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to a mode 0500 directory anyway")
	}
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	stopped(t, s)
	if err := os.Chmod(s.cfg.CacheDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(s.cfg.CacheDir, 0o755) })

	data := randBytes(1024*2, 12)
	hash := f.seed(t, s, "", data)
	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("a read over an unwritable cache returned the wrong bytes")
	}
	st := s.Stats()
	if st.FillErrors == 0 || st.LastError == "" {
		t.Fatalf("stats = %+v, want the unwritable cache counted and named", st)
	}
	if st.Refusals != 0 {
		t.Fatalf("Refusals = %d, want 0: the disk was not over its watermark", st.Refusals)
	}
}

// ---------- parallel sub-range fetch ----------

// splitAt shrinks the sub-range unit for the duration of a test, so the split
// can be driven with kilobytes instead of megabytes.
func splitAt(t *testing.T, n int64) {
	t.Helper()
	old := subRangeSize
	t.Cleanup(func() { subRangeSize = old })
	subRangeSize = n
}

// subRanges is every range asked for AFTER the first, i.e. everything past the
// one ranged GET that Open spends on the tail and the last content chunk,
// sorted, because they are issued concurrently and arrive in any order.
func subRanges(f *fakeS3) [][2]int64 {
	got := f.rangesAsked()
	if len(got) > 0 {
		got = got[1:]
	}
	sort.Slice(got, func(i, j int) bool { return got[i][0] < got[j][0] })
	return got
}

// TestColdChunkIsFetchedAsSubRangesThatTileIt: a chunk comes down as several
// parallel ranged GETs that cover it exactly, with no gap and no overlap, and
// the assembled bytes are the same ones a single serial GET produced.
func TestColdChunkIsFetchedAsSubRangesThatTileIt(t *testing.T) {
	splitAt(t, 1024)
	const cs = 4096
	f := newFakeS3(t)
	s := newStore(t, f, "", cs)
	data := randBytes(cs*2, 91)
	hash := f.seed(t, s, "", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	p := make([]byte, cs)
	if _, err := file.ReadAt(p, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, data[:cs]) {
		t.Fatal("the assembled chunk is not the artifact's bytes")
	}
	got := subRanges(f)
	if len(got) != cs/1024 {
		t.Fatalf("a %d byte chunk was fetched as %d sub-ranges, want %d", cs, len(got), cs/1024)
	}
	for i, r := range got {
		want := [2]int64{int64(i) * 1024, int64(i)*1024 + 1023}
		if r != want {
			t.Fatalf("sub-range %d is %v, want %v: the sub-ranges must tile the chunk with no gap or overlap", i, r, want)
		}
	}

	// And the same content over a store that fetches serially, which is the
	// byte-identity claim: only the transport changed.
	subRangeSize = cs
	f2 := newFakeS3(t)
	s2 := newStore(t, f2, "", cs)
	if h2 := f2.seed(t, s2, "", data); h2 != hash {
		t.Fatalf("the same content named %s and %s", hash, h2)
	}
	file2, err := s2.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file2.Close()
	if serial := readAll(t, file2); !bytes.Equal(serial, readAll(t, file)) {
		t.Fatal("the parallel path and the serial path disagree about the bytes")
	}
}

// TestShortLastChunkStaysOneRequest: the tail is fetched with the last content
// chunk in ONE ranged GET, and a chunk smaller than the sub-range unit is one
// request, not several. The split must not cost extra round trips where there
// was only ever one.
func TestShortLastChunkStaysOneRequest(t *testing.T) {
	splitAt(t, 1024)
	const cs = 4096
	f := newFakeS3(t)
	s := newStore(t, f, "", cs)
	data := randBytes(cs+700, 92) // one full chunk and a 700 byte last one
	hash := f.seed(t, s, "", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if n := f.count("GET"); n != 1 {
		t.Fatalf("opening an artifact cost %d ranged GETs, want 1 for the tail and the last chunk", n)
	}
	// The last chunk came with the tail, so reading it costs nothing more.
	if _, err := file.ReadAt(make([]byte, 700), cs); err != nil {
		t.Fatal(err)
	}
	if n := f.count("GET"); n != 1 {
		t.Fatalf("reading the last chunk cost %d GETs, want it served from the open", n)
	}
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("read back differed")
	}
}

// TestSubRangeFromTheWrongOffsetFailsTheChunk: the Content-Range start check
// applies to EVERY sub-range, not just the first. A sub-range answered from
// somewhere else must fail the whole chunk and cache nothing, because a chunk
// assembled around a mis-answered range would be neither detectably wrong at
// the transport nor re-verified once it was on disk.
func TestSubRangeFromTheWrongOffsetFailsTheChunk(t *testing.T) {
	splitAt(t, 1024)
	const cs = 4096
	f := newFakeS3(t)
	s := newStore(t, f, "", cs)
	data := randBytes(cs*2, 93)
	hash := f.seed(t, s, "", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	// The THIRD sub-range of chunk 0 only: its siblings answer honestly.
	f.mu.Lock()
	f.shiftFrom, f.rangeShift = 2048, 1
	f.mu.Unlock()

	_, err = file.ReadAt(make([]byte, cs), 0)
	if err == nil {
		t.Fatal("a chunk assembled around a mis-answered sub-range was served")
	}
	if !strings.Contains(err.Error(), "asked for byte 2048") || !strings.Contains(err.Error(), "sub-range") {
		t.Fatalf("err = %v, want the offending sub-range named", err)
	}
	if _, ok := cachedNames(t, s)[chunkName(hash, 0)]; ok {
		t.Fatal("a chunk with a mis-answered sub-range in it was cached")
	}

	f.mu.Lock()
	f.shiftFrom, f.rangeShift = 0, 0
	f.mu.Unlock()
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("honest sub-ranges returned the wrong bytes")
	}
}

// TestOneFailedSubRangeFailsTheWholeChunk: a sub-range that never arrives is
// not a hole in the chunk, it is a failed fill, and the error says which chunk
// and which bytes.
func TestOneFailedSubRangeFailsTheWholeChunk(t *testing.T) {
	splitAt(t, 1024)
	const cs = 4096
	f := newFakeS3(t)
	s := newStore(t, f, "", cs)
	data := randBytes(cs*2, 94)
	hash := f.seed(t, s, "", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	f.mu.Lock()
	f.failAt = 3072 // the last sub-range of chunk 0
	f.mu.Unlock()

	_, err = file.ReadAt(make([]byte, cs), 0)
	if err == nil {
		t.Fatal("a chunk missing a sub-range was served")
	}
	if !strings.Contains(err.Error(), "chunk 0") || !strings.Contains(err.Error(), "[3072,4096)") {
		t.Fatalf("err = %v, want the chunk and the missing byte range named", err)
	}
	if _, ok := cachedNames(t, s)[chunkName(hash, 0)]; ok {
		t.Fatal("a chunk with a missing sub-range was cached")
	}

	f.mu.Lock()
	f.failAt = -1
	f.mu.Unlock()
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("the chunk did not read once the bucket answered")
	}
}

// TestSingleflightHoldsAcrossSubRanges: the per-chunk singleflight is what it
// always was. N readers landing on one cold chunk together still cause ONE
// fetch, now made of K sub-requests rather than K per reader.
func TestSingleflightHoldsAcrossSubRanges(t *testing.T) {
	splitAt(t, 1024)
	const cs = 4096
	f := newFakeS3(t)
	s := newStore(t, f, "", cs)
	data := randBytes(cs*2, 95)
	hash := f.seed(t, s, "", data)

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
			} else if !bytes.Equal(p, data[off:off+64]) {
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
	if got := subRanges(f); len(got) != cs/1024 {
		t.Fatalf("%d readers of one cold chunk cost %d sub-requests, want %d", readers, len(got), cs/1024)
	}
}

// TestFetchConcurrencyIsBoundedAcrossChunks: the bound is the STORE's, not the
// chunk's. Three cold chunks at four sub-ranges each are twelve requests
// waiting to be made, and the store must never have more than
// FetchConcurrency of them on the wire.
func TestFetchConcurrencyIsBoundedAcrossChunks(t *testing.T) {
	splitAt(t, 1024)
	const cs, bound = 4096, 3
	f := newFakeS3(t)
	s := newStore(t, f, "", cs, func(c *Config) { c.FetchConcurrency = bound })
	data := randBytes(cs*4, 96)
	hash := f.seed(t, s, "", data)

	file, err := s.Open(hash) // the tail read, before the gate goes up
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	gate := make(chan struct{})
	f.mu.Lock()
	f.gate = gate
	f.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ { // chunks 0, 1 and 2, all cold
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := make([]byte, cs)
			if _, err := file.ReadAt(p, int64(i)*cs); err != nil {
				t.Errorf("chunk %d: %v", i, err)
			} else if !bytes.Equal(p, data[i*cs:(i+1)*cs]) {
				t.Errorf("chunk %d read the wrong bytes", i)
			}
		}(i)
	}

	inflight := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.inflight
	}
	for deadline := time.Now().Add(5 * time.Second); inflight() < bound; {
		if time.Now().After(deadline) {
			t.Fatalf("only %d sub-requests ever in flight, want the store to use its whole bound of %d", inflight(), bound)
		}
		time.Sleep(time.Millisecond)
	}
	// A store that did not bound itself would have fired all twelve by now.
	time.Sleep(100 * time.Millisecond)
	f.mu.Lock()
	peak := f.peak
	f.mu.Unlock()
	if peak > bound {
		t.Fatalf("%d sub-requests in flight at once, over the bound of %d", peak, bound)
	}
	close(gate)
	wg.Wait()
}

// TestUnreadableCachedChunkIsCounted: a cached chunk that will not read (EIO,
// or here a name that is not a regular file) correctly falls through to the
// network and returns the right bytes. That silence was the problem: with
// every cached chunk unreadable the store is a pure S3 passthrough at full
// GET rates, and nothing in Stats said so.
func TestUnreadableCachedChunkIsCounted(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024)
	data := randBytes(1024*2, 21)
	hash := f.seed(t, s, "", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("the warming read returned the wrong bytes")
	}
	if st := s.Stats(); st.CacheReadErrors != 0 {
		t.Fatalf("CacheReadErrors = %d after a healthy read, want 0", st.CacheReadErrors)
	}

	// Turn every cached chunk into a directory of the same name: open still
	// succeeds, ReadAt and mmap do not.
	for name, w := range cachedNames(t, s) {
		p := filepath.Join(s.chunkDir(w), name)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("the fallthrough to the network returned the wrong bytes")
	}
	st := s.Stats()
	if st.CacheReadErrors == 0 || st.LastError == "" {
		t.Fatalf("stats = %+v, want the unreadable cached chunks counted and named", st)
	}

	// View maps rather than preads, and its fallthrough is the one that leaves
	// the chunk resident on the heap, so it counts too.
	before := s.Stats().CacheReadErrors
	v, err := file.View(0, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v.Slice(0, v.Len()), data) {
		t.Fatal("a view over unmappable cached chunks returned the wrong bytes")
	}
	v.Close()
	if got := s.Stats().CacheReadErrors; got <= before {
		t.Fatalf("CacheReadErrors = %d after a failed mapping, want more than %d", got, before)
	}
}
