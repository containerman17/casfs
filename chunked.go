package casfs

// THE ARTIFACT FORMAT, AND THE WHOLE OF CASFS'S INTEGRITY CLAIM.
//
// This file knows nothing about S3, the chunk cache, or any consumer. Hand it
// bytes and it hands back a NAME; hand it a name, a chunk index and some bytes
// and it says yes or no. That is deliberate: the naming rule is the one thing
// every party has to agree on, so it is kept trivially extractable and has no
// coupling to anything that could drift.
//
// A stored object is three runs of bytes:
//
//	[ content: L ][ hash list: 32*N ][ trailer: 16 ]
//
// N = ceil(L / chunk size); chunk i is content[cs*i : min(cs*(i+1), L)]. THE
// LAST CHUNK IS SHORT, NEVER PADDED: padding would waste ~2MB per artifact,
// which is 3% of the 68MB epochs most chains produce, and a short final chunk
// is what casfs already reads everywhere. list[i] is sha256 of chunk i.
//
// The trailer is u64 LE of L followed by an 8-byte magic, magic LAST so the
// object's final eight bytes identify it to `tail -c8`.
//
// THE NAME IS sha256(hash list), NOT sha256 of anything else. One small read
// of the tail gives the list; sha256(list) == name proves the list came from
// the artifact that name asks for; and every chunk then verifies POSITIONALLY
// against list[i]. That is what makes an artifact self-authenticating at chunk
// granularity: a bucket serving the right offset of the WRONG OBJECT OF THE
// SAME SIZE (what a misconfigured prefix produces) is caught on the chunk that
// comes back, not on some later answer that happens to look wrong.
//
// TWO LEVELS, NO TREE, NO PROOFS. One list covers the whole artifact, so the
// ceiling is MaxChunks chunks, 512 GB at the 4MB default. The largest epoch
// anyone here produces is 9.5 GB, so a second level would be dead weight;
// anything over the ceiling is REFUSED rather than paid for with a level
// nothing uses.
//
// THE TAIL IS METADATA AND IS INVISIBLE ABOVE THIS PACKAGE. casfs presents a
// logical file of L bytes: File.Size() is L, every range is inside [0, L), and
// no consumer ever sees the list or the trailer.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
)

const (
	// MaxChunks is the ceiling ONE hash list can describe: 131072 chunks, i.e.
	// 512 GB at the default 4MB chunk. Over it the format refuses rather than
	// grows a level.
	MaxChunks = 128 << 10

	trailerSize = 16
	hashSize    = sha256.Size
)

// trailerMagic ends every stored object. Eight bytes, version in the name, so
// a future format is a different magic and an old file is refused at open
// rather than half-read.
var trailerMagic = [8]byte{'C', 'A', 'S', 'F', 'S', 'v', '1', '\n'}

// Hasher accumulates the chunk hash list as an artifact's CONTENT streams
// past. It holds one sha256 state plus 32 bytes per chunk, so a 9.5 GB epoch
// costs 76KB and a producer never has to hold its artifact in memory.
type Hasher struct {
	cs      int64
	chunk   hash.Hash
	inChunk int64
	list    []byte
	n       int64
	done    bool
}

// NewHasher starts a list at the given chunk size. THE CHUNK SIZE IS PART OF
// THE NAME: two producers that disagree about it produce different names for
// the same content, which is a loud mismatch rather than a silent one, but
// there is exactly one right answer in production and it is DefaultChunkSize.
func NewHasher(chunkSize int64) *Hasher {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	return &Hasher{cs: chunkSize, chunk: sha256.New()}
}

// Write feeds content. Chunk boundaries are absolute offsets, so they do not
// depend on how a producer happened to split its writes.
func (h *Hasher) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		take := min(int64(len(p)), h.cs-h.inChunk)
		h.chunk.Write(p[:take])
		h.inChunk += take
		h.n += take
		p = p[take:]
		if h.inChunk == h.cs {
			h.closeChunk()
		}
	}
	return n, nil
}

func (h *Hasher) closeChunk() {
	h.list = h.chunk.Sum(h.list)
	h.chunk.Reset()
	h.inChunk = 0
}

// Finish closes the short final chunk and returns the artifact's NAME and the
// TAIL a writer appends to the content to make the stored object. Call it once.
func (h *Hasher) Finish() (string, []byte, error) {
	if h.done {
		return "", nil, fmt.Errorf("casfs: Hasher.Finish called twice")
	}
	h.done = true
	if h.inChunk > 0 {
		h.closeChunk()
	}
	if n := int64(len(h.list)) / hashSize; n > MaxChunks {
		return "", nil, fmt.Errorf("casfs: %d bytes is %d chunks, over the %d this format describes with one hash list (%d bytes): refusing it",
			h.n, n, MaxChunks, MaxChunks*h.cs)
	}
	tail := make([]byte, 0, len(h.list)+trailerSize)
	tail = append(tail, h.list...)
	tail = binary.LittleEndian.AppendUint64(tail, uint64(h.n))
	tail = append(tail, trailerMagic[:]...)
	return nameOf(h.list), tail, nil
}

// nameOf is the naming rule, in full.
func nameOf(list []byte) string {
	sum := sha256.Sum256(list)
	return hex.EncodeToString(sum[:])
}

// tailLen is how many bytes of metadata sit past the content of an object
// whose STORED size is stored, derived from that size alone.
//
// It is derivable because stored = L + 32*ceil(L/cs) + 16 is strictly
// increasing in L, so one stored size admits exactly one L. That is what buys
// the ONE ranged read: without it a reader would need a round trip for the
// trailer and a second one for the list it points at.
func tailLen(stored, cs int64) (int64, error) {
	if stored < trailerSize {
		return 0, fmt.Errorf("a %d byte object is smaller than the %d byte casfs trailer", stored, trailerSize)
	}
	meta := stored - trailerSize // content + list
	n := (meta + cs + hashSize - 1) / (cs + hashSize)
	if n > MaxChunks {
		return 0, fmt.Errorf("a %d byte object is %d chunks, over the %d one hash list describes", stored, n, MaxChunks)
	}
	return n*hashSize + trailerSize, nil
}

// parseTail checks an object's metadata tail STRUCTURALLY and returns the
// logical content length and the hash list. It says nothing about whether
// these are the right bytes; that is checkName, and the two are separate
// because a LOCAL file is this node's own durable copy while a bucket is not.
func parseTail(stored, cs int64, tail []byte) (int64, []byte, error) {
	want, err := tailLen(stored, cs)
	if err != nil {
		return 0, nil, err
	}
	if int64(len(tail)) != want {
		return 0, nil, fmt.Errorf("casfs: a %d byte object has a %d byte tail, got %d bytes", stored, want, len(tail))
	}
	list, tr := tail[:want-trailerSize], tail[want-trailerSize:]
	if !bytes.Equal(tr[8:], trailerMagic[:]) {
		return 0, nil, fmt.Errorf("casfs: a %d byte object does not end in a casfs trailer: not an artifact of this format", stored)
	}
	size := int64(binary.LittleEndian.Uint64(tr[:8]))
	// The trailer's own L against the L the object's size implies. They can
	// only differ if the object was built by something that is not this
	// format.
	if size < 0 || size != stored-want {
		return 0, nil, fmt.Errorf("casfs: trailer claims %d bytes of content but a %d byte object with a %d chunk list holds %d",
			size, stored, len(list)/hashSize, stored-want)
	}
	if got := nchunks(size, cs); got*hashSize != int64(len(list)) {
		return 0, nil, fmt.Errorf("casfs: %d bytes of content is %d chunks, but the list holds %d", size, got, len(list)/hashSize)
	}
	return size, list, nil
}

// checkName is the binding between a name and the bytes served under it. It is
// what makes a bucket untrusted infrastructure: a wrong object of any size,
// including exactly the right size, fails here before a single chunk is read.
func checkName(name string, list []byte) error {
	if got := nameOf(list); got != name {
		return fmt.Errorf("casfs: %s: the object stored under this name carries a chunk list naming %s: REFUSING it (wrong object, wrong prefix, or a substituted artifact)", name, got)
	}
	return nil
}

// VerifyChunk checks chunk idx of an artifact against its own hash list. This
// is the check that runs on EVERY fill, before the bytes are cached or served.
func VerifyChunk(name string, list []byte, idx int64, b []byte) error {
	off := idx * hashSize
	if idx < 0 || off+hashSize > int64(len(list)) {
		return fmt.Errorf("casfs: %s: chunk %d is outside a %d chunk artifact", name, idx, len(list)/hashSize)
	}
	sum := sha256.Sum256(b)
	if want := list[off : off+hashSize]; !bytes.Equal(sum[:], want) {
		return fmt.Errorf("casfs: %s chunk %d: these %d bytes hash to %x but the artifact's own list says %x: REJECTED, not this artifact's content",
			name, idx, len(b), sum[:hashSize], want)
	}
	return nil
}

// ReadTail reads the metadata tail of the artifact file at path and returns its
// logical content length and its chunk hash list, in ONE pread of at most
// MaxChunks*32+16 bytes.
//
// STRUCTURE ONLY, no name binding: this is for a file the caller already owns
// (a spool file landed by fsync+rename), which is the durable copy rather than
// something an untrusted party served. Anything that came off a network goes
// through the Store, which binds the name.
func ReadTail(path string, chunkSize int64) (int64, []byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, nil, err
	}
	want, err := tailLen(fi.Size(), chunkSize)
	if err != nil {
		return 0, nil, fmt.Errorf("casfs: %s: %w", path, err)
	}
	tail := make([]byte, want)
	if _, err := f.ReadAt(tail, fi.Size()-want); err != nil {
		return 0, nil, err
	}
	return parseTail(fi.Size(), chunkSize, tail)
}
