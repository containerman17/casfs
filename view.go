package casfs

import (
	"os"
	"syscall"
)

// View is a long-lived read-only window onto an artifact's bytes, assembled
// from ONE MAPPING PER CHUNK. It exists for the ranges a consumer reads
// forever (indexes, dictionaries); everything transient goes through ReadAt,
// which preads and copies.
//
// The chunk files are separate inodes, so a view spanning more than one of
// them is not contiguous memory. Slice is zero-copy inside a chunk and COPIES
// ACROSS A CHUNK BOUNDARY, which is the entire price of the split: with 4MB
// chunks a 69-byte index entry straddles one boundary in ~60000, so the copy
// is noise and the common case allocates nothing.
//
// A chunk the disk refused to cache (admission control, see Store.admit) is
// held as heap bytes instead, so a view is always complete whatever the disk
// is doing.
type View struct {
	parts [][]byte // one per covered chunk, in order, whole chunks
	mmaps [][]byte // the subset of parts that must be munmap'd by Close
	first int64    // the view's first byte, as an offset inside parts[0]
	n     int64
	cs    int64
}

// ViewOf wraps bytes that are already mapped or already on the heap. Nothing
// in it can straddle, and Close is a no-op: the caller still owns b.
func ViewOf(b []byte) *View {
	if len(b) == 0 {
		return &View{}
	}
	return &View{parts: [][]byte{b}, n: int64(len(b)), cs: int64(len(b))}
}

// Len is the view's length in bytes.
func (v *View) Len() int64 { return v.n }

// Slice returns [off, off+n) of the view. The result aliases a mapping when
// the range lies inside one chunk and is a fresh copy when it crosses a chunk
// boundary, so callers must treat it as read-only and must not extend it past
// n. It is valid until Close.
func (v *View) Slice(off, n int64) []byte {
	if n == 0 {
		return nil
	}
	if off < 0 || n < 0 || off+n > v.n {
		panic("casfs: view slice out of range")
	}
	g := v.first + off
	i := g / v.cs
	o := g % v.cs
	if p := v.parts[i]; o+n <= int64(len(p)) {
		return p[o : o+n]
	}
	b := make([]byte, 0, n)
	for n > 0 {
		p := v.parts[i][o:]
		if int64(len(p)) > n {
			p = p[:n]
		}
		b = append(b, p...)
		n -= int64(len(p))
		i, o = i+1, 0
	}
	return b
}

// Close releases the mappings this view owns. Bytes it handed out are invalid
// afterwards.
func (v *View) Close() error {
	for _, m := range v.mmaps {
		unmap(m)
	}
	v.mmaps, v.parts = nil, nil
	return nil
}

// mapFile maps the first n bytes of an open file read-only and shared. The
// descriptor is not needed once the mapping exists, and unlinking the file
// does not disturb it, which is what makes an eviction racing a resident
// section harmless: the reader keeps the inode alive until it unmaps.
func mapFile(f *os.File, n int64) ([]byte, error) {
	if n == 0 {
		return []byte{}, nil
	}
	return syscall.Mmap(int(f.Fd()), 0, int(n), syscall.PROT_READ, syscall.MAP_SHARED)
}

func unmap(b []byte) {
	if len(b) > 0 {
		syscall.Munmap(b)
	}
}

// freeBytes is the filesystem's available space for an unprivileged writer
// (f_bavail, not f_bfree: the reserved blocks are not ours). Absolute bytes,
// because a percentage of a filesystem casfs does not own is not a budget.
func freeBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

// totalBytes is the filesystem's size, used once to turn the default 95%
// watermark into the bytes floor everything else works in.
func totalBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Blocks) * int64(st.Bsize), nil
}
