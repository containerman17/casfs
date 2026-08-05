package casfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestNameIsTheHashOfTheHashList pins the naming rule itself, by hand, with no
// library help on the expected side: chunk the content at the chunk size,
// sha256 each chunk including the SHORT LAST ONE, concatenate, and sha256 that.
func TestNameIsTheHashOfTheHashList(t *testing.T) {
	const cs = 1024
	data := randBytes(cs*3+17, 41) // three full chunks and a 17 byte tail

	h := NewHasher(cs)
	// Written in awkward pieces on purpose: chunk boundaries are absolute
	// offsets and must not depend on how a producer split its writes.
	for off := 0; off < len(data); off += 97 {
		h.Write(data[off:min(off+97, len(data))])
	}
	name, tail, err := h.Finish()
	if err != nil {
		t.Fatal(err)
	}

	var list []byte
	for off := 0; off < len(data); off += cs {
		sum := sha256.Sum256(data[off:min(off+cs, len(data))])
		list = append(list, sum[:]...)
	}
	if len(list) != 4*sha256.Size {
		t.Fatalf("built a %d chunk list, want 4", len(list)/sha256.Size)
	}
	want := sha256.Sum256(list)
	if name != hex.EncodeToString(want[:]) {
		t.Fatalf("name %s, want sha256 of the hash list %x", name, want)
	}
	if !bytes.Equal(tail[:len(list)], list) {
		t.Fatal("the tail does not open with the hash list")
	}
	if len(tail) != len(list)+trailerSize {
		t.Fatalf("tail is %d bytes, want %d list + %d trailer", len(tail), len(list), trailerSize)
	}

	// And the tail is derivable from the stored size alone, which is what buys
	// the single ranged read.
	stored := int64(len(data) + len(tail))
	got, err := tailLen(stored, cs)
	if err != nil || got != int64(len(tail)) {
		t.Fatalf("tailLen(%d) = %d, %v, want %d", stored, got, err, len(tail))
	}
	size, back, err := parseTail(stored, cs, tail)
	if err != nil || size != int64(len(data)) || !bytes.Equal(back, list) {
		t.Fatalf("parseTail = %d, %v", size, err)
	}
}

// TestShortLastChunkRoundTrips: the last chunk is short, never padded, and
// every length around a boundary reads back byte for byte.
func TestShortLastChunkRoundTrips(t *testing.T) {
	const cs = 1024
	for _, n := range []int{0, 1, cs - 1, cs, cs + 1, cs*4 - 1, cs * 4, cs*4 + 7} {
		f := newFakeS3(t)
		s := newStore(t, f, "", cs)
		data := randBytes(n, int64(n))
		hash := f.seed(t, s, "", data)

		file, err := s.Open(hash)
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if file.Size() != int64(n) {
			t.Fatalf("%d bytes: Size() = %d, the logical length must exclude the tail", n, file.Size())
		}
		if got := readAll(t, file); !bytes.Equal(got, data) {
			t.Fatalf("%d bytes: read back differed", n)
		}
		file.Close()
	}
}

// TestSubstitutedChunkIsRejectedNotServed IS THE WHOLE POINT OF THE FORMAT.
// The bucket answers the right range of the right object with somebody else's
// bytes. Nothing about the offset, the size or the name is wrong, so only the
// per-chunk hash can catch it, and it must be an error rather than an answer.
func TestSubstitutedChunkIsRejectedNotServed(t *testing.T) {
	const cs = 1024
	f := newFakeS3(t)
	s := newStore(t, f, "", cs)
	data := randBytes(cs*4, 51)
	hash := f.seed(t, s, "", data)

	// Chunk 1's bytes, replaced in place: same length, same offset, same
	// object name, same tail.
	evil := randBytes(cs, 52)
	f.mu.Lock()
	copy(f.objects[hash][cs:2*cs], evil)
	f.mu.Unlock()

	file, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	_, err = file.ReadAt(make([]byte, cs), cs)
	if err == nil {
		t.Fatal("a substituted chunk was SERVED: the bucket can rewrite state answers")
	}
	if !strings.Contains(err.Error(), "chunk 1") || !strings.Contains(err.Error(), "REJECTED") {
		t.Fatalf("err = %v, want the artifact and chunk index named", err)
	}
	if _, ok := cachedNames(t, s)[chunkName(hash, 1)]; ok {
		t.Fatal("a substituted chunk was cached, so it would be served forever")
	}
	// The honest chunks around it still read.
	if _, err := file.ReadAt(make([]byte, cs), 0); err != nil {
		t.Fatalf("chunk 0 must still read: %v", err)
	}
}

// TestWrongObjectOfTheSameSizeIsRefused is the misconfigured-prefix case: a
// DIFFERENT artifact, byte-for-byte the same length, served under this name.
// The name binding catches it at open, before a single chunk is read.
func TestWrongObjectOfTheSameSizeIsRefused(t *testing.T) {
	const cs = 1024
	f := newFakeS3(t)
	s := newStore(t, f, "", cs)
	mine := randBytes(cs*3, 61)
	hash := f.seed(t, s, "", mine)
	_, other := artifactOf(t, randBytes(cs*3, 62), cs)

	f.mu.Lock()
	if len(f.objects[hash]) != len(other) {
		t.Fatal("the two artifacts are not the same size, so this proves nothing")
	}
	f.objects[hash] = other
	f.mu.Unlock()

	if _, err := s.Open(hash); err == nil || !strings.Contains(err.Error(), "REFUSING") {
		t.Fatalf("open of a substituted object err=%v, want the name binding to refuse it", err)
	}
}

// TestAlteredListFailsTheNameBinding: the list is the only thing the name
// commits to, so any edit to it, and any truncation of the tail, is caught.
func TestAlteredListFailsTheNameBinding(t *testing.T) {
	const cs = 1024
	data := randBytes(cs*3, 71)
	name, obj := artifactOf(t, data, cs)

	for _, tc := range []struct {
		what string
		mk   func() []byte
	}{
		{"one flipped bit in the list", func() []byte {
			b := append([]byte(nil), obj...)
			b[len(data)+5] ^= 0x01
			return b
		}},
		{"a truncated tail", func() []byte { return obj[:len(obj)-sha256.Size] }},
		{"no trailer at all", func() []byte { return append([]byte(nil), data...) }},
	} {
		f := newFakeS3(t)
		s := newStore(t, f, "", cs)
		f.mu.Lock()
		f.objects[name] = tc.mk()
		f.mu.Unlock()
		if _, err := s.Open(name); err == nil {
			t.Fatalf("%s: open succeeded", tc.what)
		}
	}
}

// TestOverTheChunkCeilingIsRefused: one hash list describes at most MaxChunks
// chunks, and the format REFUSES anything larger rather than growing a level
// nothing here would ever use. Driven at a one-byte chunk size, so the ceiling
// is reached with 128KB instead of 512GB.
func TestOverTheChunkCeilingIsRefused(t *testing.T) {
	h := NewHasher(1)
	h.Write(make([]byte, MaxChunks+1))
	if _, _, err := h.Finish(); err == nil || !strings.Contains(err.Error(), "refusing it") {
		t.Fatalf("Finish over the ceiling err=%v, want a refusal", err)
	}
	// Exactly at the ceiling is fine, which is what makes the refusal a
	// boundary rather than a general aversion to big files.
	ok := NewHasher(1)
	ok.Write(make([]byte, MaxChunks))
	if _, _, err := ok.Finish(); err != nil {
		t.Fatalf("Finish at exactly the ceiling: %v", err)
	}
	// And a READER refuses a stored size that implies more chunks than one
	// list can hold, without downloading anything.
	if _, err := tailLen(int64(MaxChunks+1)*(1+sha256.Size), 1); err == nil {
		t.Fatal("tailLen accepted an object over the ceiling")
	}
}

// TestReadTailMatchesTheWriter closes the loop on a local file: what Put wrote
// is what ReadTail reads back, with no bucket in the picture.
func TestReadTailMatchesTheWriter(t *testing.T) {
	const cs = 1024
	f := newFakeS3(t)
	s := newStore(t, f, "", cs)
	data := randBytes(cs*2+3, 81)
	hash, err := s.Put(writeFile(t, s, data))
	if err != nil {
		t.Fatal(err)
	}
	size, list, err := ReadTail(s.SpoolPath(hash), cs)
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(data)) {
		t.Fatalf("logical size %d, want %d", size, len(data))
	}
	if err := checkName(hash, list); err != nil {
		t.Fatal(err)
	}
	for i := int64(0); i < nchunks(size, cs); i++ {
		end := min((i+1)*cs, size)
		if err := VerifyChunk(hash, list, i, data[i*cs:end]); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyChunk(hash, list, nchunks(size, cs), nil); err == nil {
		t.Fatal("a chunk index past the end verified")
	}
}
