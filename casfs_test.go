package casfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func newStore(t *testing.T, f *fakeS3, prefix string, chunkSize, cacheBytes int64) *Store {
	t.Helper()
	root := t.TempDir()
	s, err := New(Config{
		Endpoint:   f.URL,
		Bucket:     f.bucket,
		Prefix:     prefix,
		AccessKey:  "minioadmin",
		SecretKey:  "minioadmin",
		SpoolDir:   filepath.Join(root, "spool"),
		CacheDir:   filepath.Join(root, "cache"),
		CacheBytes: cacheBytes,
		ChunkSize:  chunkSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// reopen closes a Store and builds a second one over the same spool and cache
// directories, standing in for a clean restart. Without the Close the next New
// finds no clean marker and wipes the cache, which is what crash returns.
func reopen(t *testing.T, s *Store) *Store {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := New(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s2
}

// blocks reports the 512-byte blocks a file actually occupies, which is the
// only thing that answers whether a hole punch freed anything: the sparse
// file's length never changes.
func blocks(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Blocks
}

func cacheBlocks(t *testing.T, s *Store) int64 {
	t.Helper()
	var total int64
	filepath.WalkDir(s.cfg.CacheDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		total += blocks(t, p)
		return nil
	})
	return total
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

// wipeCache clears the cache and returns a restarted store, which is what full
// eviction of a hash's chunks looks like from the read path.
func wipeCache(t *testing.T, s *Store) *Store {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(s.cfg.CacheDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(s.cfg.CacheDir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	s2, err := New(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s2
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

func TestRoundTripMultiChunk(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "epoch/", 4096, 1<<20)

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
	if file.Size() != int64(len(data)) {
		t.Fatalf("Size = %d, want %d", file.Size(), len(data))
	}
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("round trip bytes differ")
	}

	// A fresh store with an empty spool and a cold cache must reproduce it.
	s2 := newStore(t, f, "epoch/", 4096, 1<<20)
	file2, err := s2.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file2.Close()
	if got := readAll(t, file2); !bytes.Equal(got, data) {
		t.Fatal("cold-cache round trip bytes differ")
	}
}

func TestReadAtCrossesChunkBoundaries(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024, 1<<20)
	data := randBytes(1024*9+7, 2)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	// Every offset that straddles a boundary, plus spans of several chunks.
	for _, span := range []int{1, 2, 1023, 1024, 1025, 2048, 4097} {
		for _, off := range []int{0, 1, 1023, 1024, 1025, 2047, 5000, len(data) - span, len(data) - 1} {
			if off < 0 {
				continue
			}
			p := make([]byte, span)
			n, err := file.ReadAt(p, int64(off))
			want := min(len(data)-off, span)
			if n != want {
				t.Fatalf("ReadAt(off=%d,len=%d) n=%d, want %d", off, span, n, want)
			}
			if n < span && !errors.Is(err, io.EOF) {
				t.Fatalf("ReadAt(off=%d,len=%d) short read err=%v, want io.EOF", off, span, err)
			}
			if n == span && err != nil {
				t.Fatalf("ReadAt(off=%d,len=%d) err=%v", off, span, err)
			}
			if !bytes.Equal(p[:n], data[off:off+n]) {
				t.Fatalf("ReadAt(off=%d,len=%d) bytes differ", off, span)
			}
		}
	}
	if _, err := file.ReadAt(make([]byte, 4), file.Size()); !errors.Is(err, io.EOF) {
		t.Fatalf("read past end err=%v, want io.EOF", err)
	}
}

// TestCacheHitNeedsNoNetwork warms the cache, then kills the S3 endpoint
// entirely. Reads that hit cached chunks must still succeed.
func TestCacheHitNeedsNoNetwork(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024, 1<<20)
	data := randBytes(1024*5, 3)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("warmup bytes differ")
	}
	file.Close()

	f.Server.Close() // any further network call now fails

	file2, err := s.Open(hash)
	if err != nil {
		t.Fatalf("Open after shutdown: %v", err)
	}
	defer file2.Close()
	if got := readAll(t, file2); !bytes.Equal(got, data) {
		t.Fatal("cache hit bytes differ")
	}
}

// TestSpoolRenameSurvivesRestart is the durability contract: a hash-named file
// renamed into the spool with no library call whatsoever is readable, and the
// next process to start up uploads it. Nothing else is recorded anywhere, so
// there is no ack that a kill can lose.
func TestSpoolRenameSurvivesRestart(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "v1/", 1024, 1<<20)
	data := randBytes(1024*4+9, 10)
	hash := hashOf(data)
	spool(t, s, hash, data)

	// The kill: this store never learns anything about the file.
	restarted := reopen(t, s)

	file, err := restarted.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	if f.count("HEAD")+f.count("GET") != 0 {
		t.Fatal("Open of a spooled hash touched the network")
	}
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("spooled bytes differ")
	}
	file.Close()
	if f.count("GET") != 0 {
		t.Fatalf("reading a spooled file issued %d GETs", f.count("GET"))
	}

	done := mustSync(t, restarted)
	if len(done) != 1 || done[0] != hash {
		t.Fatalf("Sync after restart confirmed %v, want [%s]", done, hash)
	}
	f.mu.Lock()
	stored := f.objects["v1/"+hash]
	f.mu.Unlock()
	if !bytes.Equal(stored, data) {
		t.Fatal("uploaded object differs from the spool file")
	}
}

// TestSpoolNameMismatchRejected proves the name is verified against the bytes
// as they stream, and that the endpoint refuses to store them.
func TestSpoolNameMismatchRejected(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024, 1<<20)

	honest := randBytes(2000, 11)
	liar := hashOf(randBytes(2000, 12)) // a name that does not describe the bytes
	spool(t, s, liar, honest)
	good := hashOf(honest)
	spool(t, s, good, honest)

	done, err := s.Sync()
	if err == nil {
		t.Fatal("Sync accepted a spool file whose name lies about its contents")
	}
	if !strings.Contains(err.Error(), liar) {
		t.Fatalf("error does not name the offending file: %v", err)
	}
	// The honest neighbour still went up: one bad entry must not stall the rest.
	if len(done) != 1 || done[0] != good {
		t.Fatalf("Sync confirmed %v, want [%s]", done, good)
	}
	f.mu.Lock()
	_, stored := f.objects[liar]
	f.mu.Unlock()
	if stored {
		t.Fatal("mismatched content was stored under the claimed hash")
	}
	if err := s.Release(liar); err == nil {
		t.Fatal("Release dropped a spool file that was never uploaded")
	}
	if _, err := os.Stat(s.SpoolPath(liar)); err != nil {
		t.Fatalf("rejected spool file was removed: %v", err)
	}
}

// TestSpoolToRemoteTransition walks the whole lifecycle through the single read
// path. Ranges read while the file is spool-resident are filled by pread and
// land in the chunk cache like any other chunk, so Release changes nothing for
// them. Only genuinely cold ranges, once the chunks are gone, reach S3.
func TestSpoolToRemoteTransition(t *testing.T) {
	f := newFakeS3(t)
	const cs = 4096
	s := newStore(t, f, "", cs, 1<<20)

	data := randBytes(cs*6+11, 4)
	path := writeFile(t, s, data)
	hash, err := s.Put(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Put left the original in place: %v", err)
	}
	if f.count("GET")+f.count("HEAD")+f.count("PUT") != 0 {
		t.Fatal("Put touched the network")
	}

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	const hotOff, hotSpan = cs*2 - 17, cs*2 + 33 // straddles three chunks
	hot := make([]byte, hotSpan)
	if _, err := file.ReadAt(hot, hotOff); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hot, data[hotOff:hotOff+hotSpan]) {
		t.Fatal("spool-resident read differs from source")
	}
	if f.count("GET") != 0 {
		t.Fatal("spool-resident read went to the network")
	}
	// The pread went through the chunk cache like everything else.
	if s.CacheUsage() == 0 {
		t.Fatal("spool-resident read did not populate the chunk cache")
	}

	// The spool file is the durable copy until the upload is confirmed.
	if err := s.Release(hash); err == nil {
		t.Fatal("Release succeeded before Sync")
	}
	if _, err := os.Stat(s.SpoolPath(hash)); err != nil {
		t.Fatalf("failed Release removed the spool file: %v", err)
	}

	mustSync(t, s)
	if err := s.Release(hash); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.SpoolPath(hash)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Release left the spool file behind: %v", err)
	}

	// Warm chunks survive Release, so the transition is invisible.
	before := f.count("GET")
	again := make([]byte, hotSpan)
	if _, err := file.ReadAt(again, hotOff); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, hot) {
		t.Fatal("post-release read of a warm range differs")
	}
	if f.count("GET") != before {
		t.Fatalf("warm range went to S3 after Release: %d GETs", f.count("GET")-before)
	}

	// Once those chunks are evicted, and only then, S3 serves the bytes.
	s2 := wipeCache(t, s)
	file2, err := s2.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file2.Close()
	cold := make([]byte, hotSpan)
	if _, err := file2.ReadAt(cold, hotOff); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cold, hot) {
		t.Fatal("post-eviction read differs")
	}
	if f.count("GET") <= before {
		t.Fatal("post-eviction read never reached S3")
	}
	if got := readAll(t, file2); !bytes.Equal(got, data) {
		t.Fatal("whole file differs after eviction")
	}
}

func TestEvictionUnderConcurrentReaders(t *testing.T) {
	f := newFakeS3(t)
	const chunkSize = 4096
	s := newStore(t, f, "", chunkSize, 3*chunkSize) // room for three chunks
	data := randBytes(chunkSize*20, 5)
	hash := f.seed("", data)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(g)))
			file, err := s.Open(hash)
			if err != nil {
				t.Error(err)
				return
			}
			defer file.Close()
			for i := 0; i < 150; i++ {
				off := rng.Intn(len(data))
				span := min(1+rng.Intn(3*chunkSize), len(data)-off)
				if i%2 == 0 { // half the traffic is pinned zero-copy views
					if err := file.Pin(int64(off), int64(span)); err != nil {
						t.Error(err)
						return
					}
					v, err := file.View(int64(off), int64(span))
					if err == nil && !bytes.Equal(v, data[off:off+span]) {
						err = errors.New("bytes differ")
					}
					if e := file.Unpin(int64(off), int64(span)); err == nil {
						err = e
					}
					if err != nil {
						t.Errorf("View(%d,%d): %v", off, span, err)
						return
					}
					continue
				}
				p := make([]byte, span)
				if _, err := file.ReadAt(p, int64(off)); err != nil {
					t.Errorf("ReadAt(%d,%d): %v", off, span, err)
					return
				}
				if !bytes.Equal(p, data[off:off+span]) {
					t.Errorf("ReadAt(%d,%d): bytes differ", off, span)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	if u := s.CacheUsage(); u > 3*chunkSize {
		t.Fatalf("cache usage %d over cap %d", u, 3*chunkSize)
	}
	// The sparse file still has the object's full length, so only allocated
	// blocks say anything. Allow one block of extent-tree overhead.
	if onDisk := cacheBlocks(t, s) * 512; onDisk > 4*chunkSize {
		t.Fatalf("allocated cache bytes %d over cap %d", onDisk, 3*chunkSize)
	}
	if fi, err := os.Stat(s.cachePath(hash)); err != nil || fi.Size() != int64(len(data)) {
		t.Fatalf("cache file size %v (%v), want %d", fi.Size(), err, len(data))
	}
}

// TestPresenceSurvivesCleanRestart is the SEEK_DATA contract: after a clean
// restart nothing but the sparse file's extent map says which chunks are
// cached, and it has to be right, chunk by chunk, with no index anywhere.
func TestPresenceSurvivesCleanRestart(t *testing.T) {
	f := newFakeS3(t)
	const cs = 4096
	s := newStore(t, f, "", cs, 1<<20)
	data := randBytes(cs*8+13, 6)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	// Fill an interleaved subset, so recovery has to distinguish real holes
	// from data rather than round a whole file up or down.
	want := []int64{0, 3, 4, 8}
	for _, i := range want {
		if _, err := file.ReadAt(make([]byte, 8), i*cs); err != nil {
			t.Fatal(err)
		}
	}
	file.Close()

	s2 := reopen(t, s)
	defer s2.Close()
	a, err := s2.artifact(hash, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var got []int64
	for i := int64(0); i < nchunks(a.size, cs); i++ {
		if a.has(i) {
			got = append(got, i)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("recovered chunks %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("recovered chunks %v, want %v", got, want)
		}
	}
	var wantBytes int64
	for _, i := range want {
		wantBytes += chunkLen(a.size, cs, i)
	}
	if s2.CacheUsage() != wantBytes {
		t.Fatalf("recovered cache usage %d, want %d", s2.CacheUsage(), wantBytes)
	}

	// Recovered means usable: those ranges must serve with no network at all.
	f.Server.Close()
	file2, err := s2.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file2.Close()
	for _, i := range want {
		p := make([]byte, min(int64(cs), int64(len(data))-i*cs))
		if _, err := file2.ReadAt(p, i*cs); err != nil {
			t.Fatalf("chunk %d after restart: %v", i, err)
		}
		if !bytes.Equal(p, data[i*cs:i*cs+int64(len(p))]) {
			t.Fatalf("chunk %d bytes differ after restart", i)
		}
	}
}

// TestUncleanShutdownWipesCache is the crash-safety choice, stated as a test.
// A chunk fill is one pwrite with no atomicity, so a process that dies with
// dirty pages can leave an extent that SEEK_DATA calls present and that reads
// back half zeros. The marker Close writes is the only evidence that did not
// happen; without it the whole cache goes, because it is disposable and a
// refill is one ranged GET.
func TestUncleanShutdownWipesCache(t *testing.T) {
	f := newFakeS3(t)
	const cs = 1024
	s := newStore(t, f, "", cs, 1<<20)
	data := randBytes(cs*4, 6)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("warmup bytes differ")
	}
	file.Close()
	if blocks(t, s.cachePath(hash)) == 0 {
		t.Fatal("warmup allocated nothing")
	}

	// The kill: no Close, so no clean marker. Plant a torn chunk to stand in
	// for the half-flushed pwrite that motivates all of this.
	torn, err := os.OpenFile(s.cachePath(hash), os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := torn.WriteAt(make([]byte, cs/2), cs); err != nil {
		t.Fatal(err)
	}
	torn.Close()

	s2, err := New(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.CacheUsage() != 0 {
		t.Fatalf("unclean restart kept %d cached bytes", s2.CacheUsage())
	}
	if _, err := os.Stat(s2.cachePath(hash)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unclean restart kept the cache file: %v", err)
	}
	file2, err := s2.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file2.Close()
	if got := readAll(t, file2); !bytes.Equal(got, data) {
		t.Fatal("bytes differ after the wipe")
	}
}

// TestOldChunkLayoutIsDeleted covers the one-way trip off the per-chunk cache:
// there is no compatibility, the files are simply not ours.
func TestOldChunkLayoutIsDeleted(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024, 1<<20)
	data := randBytes(2048, 30)
	hash := f.seed("", data)

	dir := filepath.Join(s.cfg.CacheDir, hash[:2])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := []string{hash + ".0", hash + ".1", hash + ".1.tmp12345"}
	for _, name := range old {
		if err := os.WriteFile(filepath.Join(dir, name), data[:1024], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s2 := reopen(t, s)
	defer s2.Close()
	for _, name := range old {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("old-layout file %s survived: %v", name, err)
		}
	}
	if s2.CacheUsage() != 0 {
		t.Fatalf("old-layout files were counted as cache: %d", s2.CacheUsage())
	}
}

func mtimeOf(t *testing.T, path string) time.Time {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime()
}

// TestTouchOnReadIsThrottled proves a cache hit refreshes the artifact's mtime
// at most once per TouchInterval, however hard it is read.
func TestTouchOnReadIsThrottled(t *testing.T) {
	f := newFakeS3(t)
	// The interval sits well clear of this filesystem's 4ms mtime granularity.
	const cs, interval = 1024, 50 * time.Millisecond
	s := newStore(t, f, "", cs, 1<<20)
	s.cfg.TouchInterval = interval // set before any concurrent use
	data := randBytes(cs*3, 20)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	p := make([]byte, 8)
	if _, err := file.ReadAt(p, 0); err != nil { // fills chunk 0
		t.Fatal(err)
	}
	path := s.cachePath(hash)
	first := mtimeOf(t, path)

	for i := 0; i < 50; i++ { // all inside the interval, all hits
		if _, err := file.ReadAt(p, int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := mtimeOf(t, path); !got.Equal(first) {
		t.Fatalf("mtime moved %v within the throttle interval", got.Sub(first))
	}

	time.Sleep(interval + interval/2)
	if _, err := file.ReadAt(p, 0); err != nil {
		t.Fatal(err)
	}
	second := mtimeOf(t, path)
	if !second.After(first) {
		t.Fatal("mtime did not advance after the throttle interval elapsed")
	}
	for i := 0; i < 50; i++ {
		if _, err := file.ReadAt(p, int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := mtimeOf(t, path); !got.Equal(second) {
		t.Fatalf("mtime moved again within the interval, by %v", got.Sub(second))
	}

	// Negative disables it outright.
	s.cfg.TouchInterval = -1
	time.Sleep(interval + interval/2)
	if _, err := file.ReadAt(p, 0); err != nil {
		t.Fatal(err)
	}
	if got := mtimeOf(t, path); !got.Equal(second) {
		t.Fatal("negative TouchInterval still touched the chunk")
	}
}

// TestTouchKeepsRestartSeedFresh is the reason touching exists: an artifact
// fetched long ago but read constantly must outrank a newer one nobody reads
// once the process restarts and the LRU is reseeded from mtime. Ages are
// planted rather than slept out, since mtime granularity here is 4ms.
//
// The seed is per artifact now, not per chunk, because there is one file per
// artifact to carry an mtime. Two artifacts, one chunk each.
func TestTouchKeepsRestartSeedFresh(t *testing.T) {
	f := newFakeS3(t)
	// Two filesystem blocks per chunk, so a punch has whole blocks to free and
	// the eviction is visible in st_blocks.
	const cs = 8192
	s := newStore(t, f, "", cs, 1<<20)
	hotHash := f.seed("", randBytes(cs, 21))
	coldHash := f.seed("", randBytes(cs, 22))

	p := make([]byte, 8)
	for _, h := range []string{hotHash, coldHash} {
		file, err := s.Open(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.ReadAt(p, 0); err != nil {
			t.Fatal(err)
		}
		file.Close()
	}

	// The hot artifact is the older of the two on disk, and is about to become
	// the hot one. The cold one is newer and never read again.
	hot, cold := s.cachePath(hotHash), s.cachePath(coldHash)
	now := time.Now()
	for path, age := range map[string]time.Duration{hot: 2 * time.Hour, cold: time.Hour} {
		if err := os.Chtimes(path, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}

	// Restart: the LRU is reseeded from those mtimes, so the hot artifact
	// starts last in line. One read is enough to lift it.
	s2 := reopen(t, s)
	file2, err := s2.Open(hotHash)
	if err != nil {
		t.Fatal(err)
	}
	defer file2.Close()
	if _, err := file2.ReadAt(p, 0); err != nil {
		t.Fatal(err)
	}
	if !mtimeOf(t, hot).After(mtimeOf(t, cold)) {
		t.Fatal("touch did not lift the hot artifact above the cold one")
	}

	// Restart again with room for exactly one chunk. The seed must keep the
	// touched one, which without touching would have been evicted first.
	cfg := s2.cfg
	cfg.CacheBytes = cs
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	s3, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if blocks(t, hot) == 0 {
		t.Fatal("restart evicted the touched artifact")
	}
	if blocks(t, cold) != 0 {
		t.Fatal("restart kept the untouched artifact")
	}
	if s3.CacheUsage() != cs {
		t.Fatalf("post-restart usage %d, want %d", s3.CacheUsage(), cs)
	}
}

// TestViewIsZeroCopy proves View hands back the mapping itself and not a copy:
// two Views of overlapping ranges are the same memory, and the whole object is
// readable through it.
func TestViewIsZeroCopy(t *testing.T) {
	f := newFakeS3(t)
	const cs = 4096
	s := newStore(t, f, "", cs, 1<<20)
	defer s.Close()
	data := randBytes(cs*5+77, 40)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	const off, n = cs + 7, cs * 2 // straddles three chunks
	v, err := file.View(off, n)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v, data[off:off+n]) {
		t.Fatal("View bytes differ")
	}
	v2, err := file.View(off, 16)
	if err != nil {
		t.Fatal(err)
	}
	if &v2[0] != &v[0] {
		t.Fatal("View copied instead of aliasing the mapping")
	}

	// A range nobody has touched yet is filled by the View itself.
	before := f.count("GET")
	whole, err := file.View(0, file.Size())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(whole, data) {
		t.Fatal("whole-object View differs")
	}
	if f.count("GET") <= before {
		t.Fatal("View of an uncached range fetched nothing")
	}
	if &whole[off] != &v[0] {
		t.Fatal("the second View is a different mapping")
	}
	if _, err := file.View(1, file.Size()); err == nil {
		t.Fatal("View past the end was accepted")
	}
}

// TestViewFromSpool maps the spool file directly, and keeps working across the
// Release that unlinks it, because unlinking never disturbs a mapping.
func TestViewFromSpool(t *testing.T) {
	f := newFakeS3(t)
	const cs = 1024
	s := newStore(t, f, "", cs, 1<<20)
	defer s.Close()
	data := randBytes(cs*3+5, 41)
	hash, err := s.Put(writeFile(t, s, data))
	if err != nil {
		t.Fatal(err)
	}

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	v, err := file.View(0, file.Size())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v, data) {
		t.Fatal("spool View differs")
	}
	if s.CacheUsage() != 0 {
		t.Fatal("a spool-resident View populated the chunk cache")
	}

	mustSync(t, s)
	if err := s.Release(hash); err != nil {
		t.Fatal(err)
	}
	f.Server.Close()
	if !bytes.Equal(v, data) {
		t.Fatal("spool View changed under Release")
	}
	v2, err := file.View(cs, cs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v2, data[cs:cs*2]) {
		t.Fatal("spool View after Release differs")
	}
}

// TestPunchFreesBlocks is the point of the sparse layout: eviction has to give
// the blocks back to the filesystem, and the file's length cannot say whether
// it did.
func TestPunchFreesBlocks(t *testing.T) {
	f := newFakeS3(t)
	const cs = 64 << 10 // a multiple of the 4K block size, so a punch frees whole blocks
	const cap = 4 * cs
	s := newStore(t, f, "", cs, cap)
	defer s.Close()
	data := randBytes(cs*8, 42)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	p := make([]byte, 8)
	for i := int64(0); i < 4; i++ { // fill up to the cap, nothing evicted yet
		if _, err := file.ReadAt(p, i*cs); err != nil {
			t.Fatal(err)
		}
	}
	full := blocks(t, s.cachePath(hash)) * 512
	if full < cap {
		t.Fatalf("four chunks allocated %d bytes, want at least %d", full, cap)
	}

	for i := int64(4); i < 8; i++ { // every one of these punches an older chunk
		if _, err := file.ReadAt(p, i*cs); err != nil {
			t.Fatal(err)
		}
	}
	after := blocks(t, s.cachePath(hash)) * 512
	t.Logf("8 chunks of %d bytes read under a %d byte cap: file length %d, allocated %d (peak resident %d)",
		cs, cap, file.Size(), after, full)
	if after > full+cs {
		t.Fatalf("allocated %d bytes after eviction, want about %d: punching freed nothing", after, cap)
	}
	if s.CacheUsage() != cap {
		t.Fatalf("cache usage %d, want %d", s.CacheUsage(), cap)
	}
	if fi, _ := os.Stat(s.cachePath(hash)); fi.Size() != int64(len(data)) {
		t.Fatalf("punching changed the file length to %d, want %d", fi.Size(), len(data))
	}
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("bytes differ after punching")
	}
}

// TestPinSurvivesEvictionPressure is the correctness piece the whole design
// hangs on. A punched page reads back as zeros with no error, so a consumer
// holding a live mmap of a range needs that range to be untouchable. It also
// shows the hazard directly: once unpinned, the same view goes to zeros.
func TestPinSurvivesEvictionPressure(t *testing.T) {
	f := newFakeS3(t)
	const cs = 4096
	s := newStore(t, f, "", cs, 3*cs)
	defer s.Close()
	data := randBytes(cs*20, 43)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if err := file.Pin(0, cs); err != nil {
		t.Fatal(err)
	}
	view, err := file.View(0, cs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(view, data[:cs]) {
		t.Fatal("pinned View differs")
	}

	pressure := func() {
		p := make([]byte, 8)
		for i := int64(1); i < 20; i++ {
			if _, err := file.ReadAt(p, i*cs); err != nil {
				t.Fatal(err)
			}
		}
	}
	pressure()
	pressure()

	a, err := s.artifact(hash, file.Size())
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	present := a.has(0)
	s.mu.Unlock()
	if !present {
		t.Fatal("the pinned chunk was evicted")
	}
	if !bytes.Equal(view, data[:cs]) {
		t.Fatal("the pinned View was punched out from under the reader")
	}

	// Unpin, and the same range becomes ordinary cache: the next round of
	// pressure punches it and the still-live view silently reads zeros. This
	// is exactly what Pin exists to prevent, so it is worth asserting.
	if err := file.Unpin(0, cs); err != nil {
		t.Fatal(err)
	}
	if err := file.Unpin(0, cs); err == nil {
		t.Fatal("Unpin of an unpinned range was accepted")
	}
	pressure()
	s.mu.Lock()
	present = a.has(0)
	s.mu.Unlock()
	if present {
		t.Fatal("the unpinned chunk was never evicted, so the test proves nothing")
	}
	if !bytes.Equal(view, make([]byte, cs)) {
		t.Fatal("a punched range did not read back as zeros, and the hazard is misdescribed")
	}
	// ReadAt still answers correctly, because it refills before reading.
	p := make([]byte, cs)
	if _, err := file.ReadAt(p, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, data[:cs]) {
		t.Fatal("refilled read differs")
	}
}

func TestPointers(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "epoch/", 1024, 1<<20)

	if _, err := s.GetPointer("latest"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing pointer err=%v, want fs.ErrNotExist", err)
	}
	if err := s.SetPointer("latest", "abc123"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.GetPointer("latest"); err != nil || v != "abc123" {
		t.Fatalf("GetPointer = %q, %v", v, err)
	}
	if err := s.SetPointer("latest", "def456"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.GetPointer("latest"); v != "def456" {
		t.Fatalf("GetPointer after overwrite = %q", v)
	}
	if err := s.SetPointer(strings.Repeat("a", 64), "x"); err == nil {
		t.Fatal("pointer name shaped like a hash was accepted")
	}
}

func TestSyncIsIdempotent(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024, 1<<20)
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
	s2 := newStore(t, f, "", 1024, 1<<20)
	spool(t, s2, hash, data)
	if done := mustSync(t, s2); len(done) != 1 || done[0] != hash {
		t.Fatalf("Sync confirmed %v, want [%s]", done, hash)
	}
	if n := f.count("PUT"); n != 1 {
		t.Fatalf("re-Sync from a fresh store issued %d PUTs total, want 1", n)
	}

	// Release works off a HEAD alone, with no Sync in this process.
	s3 := newStore(t, f, "", 1024, 1<<20)
	spool(t, s3, hash, data)
	if err := s3.Release(hash); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s3.SpoolPath(hash)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Release left the spool file behind: %v", err)
	}
}
