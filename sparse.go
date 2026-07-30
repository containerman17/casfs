package casfs

import (
	"os"
	"syscall"
)

// Linux only. The cache is one sparse file per artifact, and the kernel's
// extent map is the record of which chunks are present, so this file is a thin
// wrapper over the three syscalls that make that work: SEEK_DATA/SEEK_HOLE to
// read the map, FALLOC_FL_PUNCH_HOLE to free a chunk, and mmap to hand a
// consumer a zero-copy view. None of them have a portable analogue worth
// faking, so there is no fallback and the package does not build elsewhere.
const (
	seekData = 3 // SEEK_DATA
	seekHole = 4 // SEEK_HOLE

	fallocKeepSize  = 0x01 // FALLOC_FL_KEEP_SIZE
	fallocPunchHole = 0x02 // FALLOC_FL_PUNCH_HOLE
)

// punch frees the blocks backing [off, off+n) and leaves the file length
// alone. The range reads back as zeros afterwards, with no error and no
// signal, which is the entire reason pinning exists.
func punch(f *os.File, off, n int64) error {
	return syscall.Fallocate(int(f.Fd()), fallocPunchHole|fallocKeepSize, off, n)
}

// dataRanges reports the file's allocated ranges, clamped to size. The kernel
// may report data where there is really a hole, but never a hole where there
// is data, so a chunk fully covered by a reported range is the only thing a
// caller may treat as present, and every other answer just costs a refill.
//
// It moves the file offset, which is harmless here: every other access in this
// package is pread/pwrite.
func dataRanges(f *os.File, size int64, yield func(off, end int64)) error {
	fd := int(f.Fd())
	for off := int64(0); off < size; {
		d, err := syscall.Seek(fd, off, seekData)
		if err == syscall.ENXIO { // no data at or after off
			return nil
		} else if err != nil {
			return err
		}
		h, err := syscall.Seek(fd, d, seekHole)
		if err != nil {
			return err
		}
		if h > size {
			h = size
		}
		if d >= h {
			return nil
		}
		yield(d, h)
		off = h
	}
	return nil
}

// mapWhole maps the whole file read-only and shared, so later chunk fills
// through pwrite are visible in it (same page cache) and later hole punches
// blank it. The descriptor is not needed once the mapping exists.
func mapWhole(path string, size int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if size == 0 {
		return []byte{}, nil
	}
	return syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
}

func unmap(b []byte) {
	if len(b) > 0 {
		syscall.Munmap(b)
	}
}
