package casfs

import (
	"bytes"
	"context"
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
	"testing"
	"time"
)

func newStore(t *testing.T, f *fakeS3, prefix string, chunkSize, cacheBytes int64) *Store {
	t.Helper()
	s, err := New(Config{
		Endpoint:   f.URL,
		Bucket:     f.bucket,
		Prefix:     prefix,
		AccessKey:  "minioadmin",
		SecretKey:  "minioadmin",
		CacheDir:   filepath.Join(t.TempDir(), "cache"),
		CacheBytes: cacheBytes,
		ChunkSize:  chunkSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// reopen builds a second Store over the same cache directory, standing in for a
// process restart.
func reopen(t *testing.T, s *Store) *Store {
	t.Helper()
	cfg := s.cfg
	s2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s2
}

func randBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func writeFile(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
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

func readAll(t *testing.T, file *File) []byte {
	t.Helper()
	got, err := io.ReadAll(io.NewSectionReader(file, 0, file.Size()))
	if err != nil {
		t.Fatal(err)
	}
	return got
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
	hash, err := s.Put(writeFile(t, data))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hash != hex.EncodeToString(sum[:]) {
		t.Fatalf("Put returned %s, want %x", hash, sum)
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

	// A fresh Store over a cold cache must reproduce the same bytes.
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
			want := len(data) - off
			if want > span {
				want = span
			}
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

// TestTierZeroToChunkTransition is the contract: from Put onward the hash is
// readable, first straight off the original local file with no network at all,
// and after Release through the chunk cache, byte for byte the same.
func TestTierZeroToChunkTransition(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 4096, 1<<20)

	data := randBytes(4096*6+11, 4)
	path := writeFile(t, data)

	hash, err := s.Register(path)
	if err != nil {
		t.Fatal(err)
	}
	// Readable before the upload even starts, with zero network calls.
	if f.count("GET")+f.count("HEAD")+f.count("PUT") != 0 {
		t.Fatal("Register touched the network")
	}
	early, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, early); !bytes.Equal(got, data) {
		t.Fatal("pre-upload read differs")
	}
	early.Close()
	if f.count("GET") != 0 {
		t.Fatalf("pre-upload read issued %d GETs", f.count("GET"))
	}

	// The original may not be dropped before the upload is confirmed.
	if err := s.Release(hash); err == nil {
		t.Fatal("Release succeeded before Upload")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Release removed the original early: %v", err)
	}

	const off, span = 4096*2 - 17, 4096*2 + 33
	want := make([]byte, span)
	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.ReadAt(want, off); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, data[off:off+span]) {
		t.Fatal("tier zero read differs from source")
	}
	if f.count("GET") != 0 {
		t.Fatal("tier zero read went to the network")
	}

	if err := s.Upload(hash); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(hash); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Release left the original in place: %v", err)
	}

	got := make([]byte, span)
	if _, err := file.ReadAt(got, off); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("post-release read differs from tier zero read")
	}
	if f.count("GET") == 0 {
		t.Fatal("post-release read never reached S3")
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
				span := 1 + rng.Intn(3*chunkSize)
				if off+span > len(data) {
					span = len(data) - off
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
	var onDisk int64
	filepath.WalkDir(s.cfg.CacheDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			onDisk += fi.Size()
		}
		return nil
	})
	if onDisk > 3*chunkSize {
		t.Fatalf("on-disk chunk bytes %d over cap %d", onDisk, 3*chunkSize)
	}
}

// TestTornTmpRecovery plants the debris a crash mid-fetch would leave and
// proves a restart cleans it up and still reads correctly.
func TestTornTmpRecovery(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024, 1<<20)
	data := randBytes(1024*4, 6)
	hash := f.seed("", data)

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, file); !bytes.Equal(got, data) {
		t.Fatal("warmup bytes differ")
	}
	file.Close()

	dir := filepath.Join(s.cfg.CacheDir, hash[:2])
	torn := filepath.Join(dir, hash+".2.tmp918273")
	if err := os.WriteFile(torn, []byte("half a chunk, then the power went out"), 0o644); err != nil {
		t.Fatal(err)
	}

	s2 := reopen(t, s)
	if _, err := os.Stat(torn); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("torn tmp file survived restart: %v", err)
	}
	file2, err := s2.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file2.Close()
	if got := readAll(t, file2); !bytes.Equal(got, data) {
		t.Fatal("bytes differ after recovery")
	}
	if s2.CacheUsage() != int64(len(data)) {
		t.Fatalf("recovered cache usage %d, want %d", s2.CacheUsage(), len(data))
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

func TestUploadIsIdempotent(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024, 1<<20)
	path := writeFile(t, randBytes(3000, 7))

	h1, err := s.Put(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := f.count("PUT"); n != 1 {
		t.Fatalf("first Put issued %d PUTs, want 1", n)
	}
	// A second store, so the in-memory "already uploaded" flag cannot help.
	s2 := newStore(t, f, "", 1024, 1<<20)
	h2, err := s2.Put(path)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("hashes differ: %s vs %s", h1, h2)
	}
	if n := f.count("PUT"); n != 1 {
		t.Fatalf("re-Put issued %d PUTs total, want 1", n)
	}
}

func TestAdoptDir(t *testing.T) {
	f := newFakeS3(t)
	s := newStore(t, f, "", 1024, 1<<20)

	dir := t.TempDir()
	want := map[string][]byte{}
	for _, name := range []string{"a.bin", "b.bin", "sub/c.bin"} {
		data := randBytes(2500, int64(len(name)))
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		want[filepath.ToSlash(name)] = data
	}

	got := map[string]string{}
	err := s.AdoptDir(context.Background(), dir, time.Millisecond, true,
		func(rel, hash string) error {
			got[filepath.ToSlash(rel)] = hash
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("adopted %d files, want %d", len(got), len(want))
	}
	for rel, hash := range got {
		if _, err := os.Stat(filepath.Join(dir, rel)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s not released: %v", rel, err)
		}
		file, err := s.Open(hash)
		if err != nil {
			t.Fatal(err)
		}
		if b := readAll(t, file); !bytes.Equal(b, want[rel]) {
			t.Fatalf("%s bytes differ after adoption", rel)
		}
		file.Close()
	}
}
