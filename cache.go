package casfs

// THE WINDOWED SHARED CHUNK CACHE.
//
// The cache is a directory of plain chunk files, 4MB each, named
// `<artifacthash>.<index>`. The name is NOT a content hash: the artifact hash
// plus the index already names immutable bytes uniquely, is derivable without
// anyone's chunk list, and keeps ownership of a file decidable by looking at
// it.
//
// Files live in per-window subdirectories, one per 20 UTC minutes
// (unix_minutes/20, an integer, never local time). The window a file sits in
// IS its recency: a read of a chunk in any older window renames it into the
// current one, which is the whole LRU, costs one rename per chunk per window,
// and survives restarts without a journal because it is written in the
// directory tree rather than in anyone's memory.
//
// Nothing here is a byte budget. Fills are governed by ADMISSION CONTROL (over
// the disk watermark, do not cache, serve from memory) and space is recovered
// by ONE BACKGROUND WORKER deleting from the oldest non-current window. The
// worker never touches the current window, so a saturated cache freezes full
// instead of churning its own fresh fills.

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	// windowMinutes is the cache's recency granularity. Small enough that the
	// oldest window is a fair victim, large enough that a hot chunk is renamed
	// three times an hour at worst.
	windowMinutes = 20
	// DefaultMaxAge is how long a window survives regardless of disk fill.
	DefaultMaxAge = 30 * 24 * time.Hour
	// defaultFullPct is the watermark: cache up to 95% of the filesystem.
	defaultFullPct = 95

	evictBatch = 256              // names read per getdents on the victim window
	evictSleep = 2 * time.Millisecond
	pollIdle   = 5 * time.Second
	sweepEvery = 5 * time.Minute
	tmpMaxAge  = time.Hour
)

// window is the bucket a file created at t belongs to.
func window(t time.Time) int64 { return t.UTC().Unix() / 60 / windowMinutes }

func nowWindow() int64 { return window(time.Now()) }

func (s *Store) windowDir(w int64) string {
	return filepath.Join(s.cfg.CacheDir, strconv.FormatInt(w, 10))
}

func chunkName(hash string, idx int64) string {
	return hash + "." + strconv.FormatInt(idx, 10)
}

// validChunkName recognizes this cache's own files and nothing else, so a
// stray, a tmp, or a leftover from the pre-window layout is never mistaken for
// a chunk.
func validChunkName(name string) bool {
	dot := len(name) - 1
	for ; dot >= 0 && name[dot] != '.'; dot-- {
		if name[dot] < '0' || name[dot] > '9' {
			return false
		}
	}
	return dot == 64 && dot < len(name)-1 && validHash(name[:64])
}

// scanCache rebuilds the chunk->window map with ONE NAME-ONLY WALK of the
// window tree, and deletes anything that is not part of it, which is also how
// a pre-window sparse cache is retired (the cache is disposable, so there is
// no migration, only a wipe).
//
// The map is a hint owned by this process. An entry that is wrong because a
// sibling evicted the file costs one ENOENT and a refetch, never a wrong
// answer, so no process ever has to agree with any other about what is cached.
func (s *Store) scanCache() error {
	ents, err := os.ReadDir(s.cfg.CacheDir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		w, werr := strconv.ParseInt(e.Name(), 10, 64)
		if !e.IsDir() || werr != nil {
			if err := os.RemoveAll(filepath.Join(s.cfg.CacheDir, e.Name())); err != nil {
				return err
			}
			continue
		}
		if err := s.scanWindow(w); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) scanWindow(w int64) error {
	f, err := os.Open(s.windowDir(w))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	for {
		// f.ReadDir does not sort and does not stat, unlike os.ReadDir: this is
		// getdents and a name check, which is what keeps a startup walk over a
		// six-figure cache a fraction of a second.
		ents, err := f.ReadDir(evictBatch * 16)
		for _, e := range ents {
			name := e.Name()
			// A newer window wins, so a crash between the two halves of a
			// promote cannot leave a reader looking at the stale copy.
			if !validChunkName(name) {
				continue
			}
			if old, ok := s.where[name]; !ok || w > old {
				s.where[name] = w
			}
		}
		if errors.Is(err, io.EOF) || len(ents) == 0 {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (s *Store) forget(name string, w int64) {
	s.mu.Lock()
	if cur, ok := s.where[name]; ok && cur == w {
		delete(s.where, name)
	}
	s.mu.Unlock()
}

// openChunk opens a cached chunk and promotes it on the way past. A miss
// (never cached here, or evicted by anyone) returns nil, nil: that is an
// ordinary read, not an error.
func (s *Store) openChunk(name string) (*os.File, error) {
	s.mu.Lock()
	w, ok := s.where[name]
	s.mu.Unlock()
	if !ok {
		return nil, nil
	}
	f, err := os.Open(filepath.Join(s.windowDir(w), name))
	if errors.Is(err, fs.ErrNotExist) {
		s.forget(name, w)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.promote(name, w)
	return f, nil
}

// promote renames a chunk read in ANY older window into the current one.
//
// Promote-from-any-older, not promote-only-when-far-behind: under pressure the
// second rule stops distinguishing hot from cold (everything the worker is
// about to eat looks equally stale) and the cache degrades to FIFO. The cost
// of the greedy rule is bounded at one rename per chunk per window.
//
// The caller already holds the file open, so a promotion that loses a race
// costs a map entry, never the read in flight.
func (s *Store) promote(name string, from int64) {
	cur := nowWindow()
	if from == cur {
		return
	}
	dir := s.windowDir(cur)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	err := os.Rename(filepath.Join(s.windowDir(from), name), filepath.Join(dir, name))
	switch {
	case err == nil:
		s.mu.Lock()
		s.where[name] = cur
		s.mu.Unlock()
	case errors.Is(err, fs.ErrNotExist):
		// Someone else moved it or the worker ate it. One stat says which.
		if _, serr := os.Stat(filepath.Join(dir, name)); serr == nil {
			s.mu.Lock()
			s.where[name] = cur
			s.mu.Unlock()
			return
		}
		s.forget(name, from)
	}
	// Any other failure leaves the entry alone: the file is still where this
	// process thinks it is.
}

// flight is one in-progress upstream read. Concurrent misses on one chunk
// share it, so N readers hitting a cold chunk together cost ONE ranged GET.
type flight struct {
	wg  sync.WaitGroup
	b   []byte
	err error
}

// fetch reads one chunk from the durable copy and caches it if the disk has
// room. The returned bytes are shared with every other waiter and are
// READ-ONLY.
func (s *Store) fetch(hash string, size, idx int64) ([]byte, error) {
	name := chunkName(hash, idx)
	s.mu.Lock()
	if fl, ok := s.flight[name]; ok {
		s.mu.Unlock()
		fl.wg.Wait()
		return fl.b, fl.err
	}
	fl := &flight{}
	fl.wg.Add(1)
	s.flight[name] = fl
	s.mu.Unlock()

	fl.b, fl.err = s.pull(hash, size, idx)
	if fl.err == nil {
		s.admit(name, fl.b)
	}
	s.mu.Lock()
	delete(s.flight, name)
	s.mu.Unlock()
	fl.wg.Done()
	return fl.b, fl.err
}

// pull reads a chunk's bytes from the spool file when the artifact is still
// local and by a ranged GET when it is not. That is the only respect in which
// spooled and remote content differ anywhere.
func (s *Store) pull(hash string, size, idx int64) ([]byte, error) {
	off := idx * s.cfg.ChunkSize
	n := chunkLen(size, s.cfg.ChunkSize, idx)
	b := make([]byte, n)
	if f, err := os.Open(s.SpoolPath(hash)); err == nil {
		defer f.Close()
		if _, err := f.ReadAt(b, off); err != nil {
			return nil, err
		}
		return b, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	body, _, err := s.s3.get(s.key(hash), off, n)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	if _, err := io.ReadFull(body, b); err != nil {
		return nil, err
	}
	return b, nil
}

// roomy reports whether the filesystem is under the watermark.
func (s *Store) roomy() bool {
	free, err := s.cfg.free(s.cfg.CacheDir)
	return err == nil && free >= s.cfg.CacheMinFree
}

// admit writes a fetched chunk into the current window. IT NEVER EVICTS TO
// MAKE ROOM: over the watermark the fill is simply not cached and the bytes
// are served from memory, so a full disk degrades a node to S3-speed reads
// rather than into a delete-per-fill treadmill. The background worker is the
// only thing that frees space, and it runs on its own schedule.
//
// The fsync is MANDATORY, not tuning. Power loss between the write and the
// rename must never leave a torn chunk under a correct name: nothing reads
// chunk files back with a checksum, so torn bytes under the right name are
// silent wrong answers (a half-written bloom page answers "no" for keys that
// are there).
func (s *Store) admit(name string, b []byte) {
	if !s.roomy() {
		s.refusals.Add(1)
		return
	}
	dir := s.windowDir(nowWindow())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	f, err := os.CreateTemp(dir, name+".*.tmp")
	if err != nil {
		return
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, name))
	}
	if err != nil {
		os.Remove(tmp)
		return
	}
	s.mu.Lock()
	s.where[name] = window(time.Now())
	s.mu.Unlock()
}

// ---------- the background worker ----------

// worker is the ONLY thing that deletes cached chunks. While the disk is over
// the watermark it unlinks one file at a time from the oldest non-current
// window, sleeping between deletes; otherwise it idles. No throttle is needed
// by construction: one delete per tick is the throttle.
func (s *Store) worker() {
	defer close(s.done)
	var lastSweep time.Time
	for {
		if time.Since(lastSweep) >= sweepEvery {
			s.sweep()
			lastSweep = time.Now()
		}
		d := pollIdle
		if !s.roomy() && s.evictOne() {
			d = evictSleep
		}
		select {
		case <-s.stop:
			s.dropVictim()
			return
		case <-time.After(d):
		}
	}
}

func (s *Store) dropVictim() {
	if s.vic != nil {
		s.vic.Close()
		s.vic, s.vicNames = nil, nil
	}
}

// windows lists the window directories present, oldest first is not
// guaranteed: callers pick.
func (s *Store) windows() []int64 {
	ents, err := os.ReadDir(s.cfg.CacheDir)
	if err != nil {
		return nil
	}
	var out []int64
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if w, err := strconv.ParseInt(e.Name(), 10, 64); err == nil {
			out = append(out, w)
		}
	}
	return out
}

// oldestVictim is the oldest window that is NOT the current one. The current
// window is off limits: evicting from it would delete the fills this same
// second produced, which is the churn the whole design exists to avoid. When
// only the current window has files the worker stops and admission control
// carries the load.
func (s *Store) oldestVictim() (int64, bool) {
	cur := nowWindow()
	best, ok := int64(0), false
	for _, w := range s.windows() {
		if w >= cur {
			continue
		}
		if !ok || w < best {
			best, ok = w, true
		}
	}
	return best, ok
}

// evictOne unlinks one chunk and reports whether it made progress. The victim
// window's directory handle is CACHED across calls, so a delete costs one
// unlink and not a readdir of a window holding a hundred thousand files.
func (s *Store) evictOne() bool {
	for tries := 0; tries < 4; tries++ {
		if s.vic == nil {
			w, ok := s.oldestVictim()
			if !ok {
				return false
			}
			f, err := os.Open(s.windowDir(w))
			if err != nil {
				return false
			}
			s.vic, s.vicWin = f, w
		}
		if len(s.vicNames) == 0 {
			ents, err := s.vic.ReadDir(evictBatch)
			for _, e := range ents {
				s.vicNames = append(s.vicNames, e.Name())
			}
			if len(s.vicNames) == 0 || (err != nil && !errors.Is(err, io.EOF)) {
				// Drained, or as drained as this pass can see: unlinking while
				// getdents walks the same directory may skip entries, so a
				// window that refuses to rmdir is simply revisited next pass.
				s.dropVictim()
				os.Remove(s.windowDir(s.vicWin))
				continue
			}
		}
		name := s.vicNames[0]
		s.vicNames = s.vicNames[1:]
		err := os.Remove(filepath.Join(s.windowDir(s.vicWin), name))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		// ENOENT is a sibling process's delete, i.e. progress by someone.
		s.evictions.Add(1)
		s.horizon.Store(s.vicWin)
		s.forget(name, s.vicWin)
		return true
	}
	return false
}

// sweep is the time-based half: whole windows older than the max age go
// REGARDLESS OF DISK FILL, by name and without a stat, and stray tmp files
// from a killed fill are collected.
//
// Deleting a whole window by its name is safe because a promotion's target is
// always the CURRENT window: nothing a reader still wants can be sitting in a
// directory named thirty days ago.
func (s *Store) sweep() {
	cur := nowWindow()
	cutoff := cur - int64(s.cfg.CacheMaxAge/(windowMinutes*time.Minute))
	for _, w := range s.windows() {
		if w < cutoff {
			if s.vic != nil && s.vicWin == w {
				s.dropVictim()
			}
			os.RemoveAll(s.windowDir(w))
			s.forgetWindow(w)
			continue
		}
		// A tmp can only ever have been created in the window that was current
		// at the time, so an hour of windows is the whole search space.
		if w >= cur-int64(tmpMaxAge/(windowMinutes*time.Minute))-1 {
			s.collectTmp(w)
		}
	}
}

func (s *Store) forgetWindow(w int64) {
	s.mu.Lock()
	for name, at := range s.where {
		if at == w {
			delete(s.where, name)
		}
	}
	s.mu.Unlock()
}

func (s *Store) collectTmp(w int64) {
	ents, err := os.ReadDir(s.windowDir(w))
	if err != nil {
		return
	}
	for _, e := range ents {
		if filepath.Ext(e.Name()) != ".tmp" {
			continue
		}
		fi, err := e.Info()
		if err != nil || time.Since(fi.ModTime()) < tmpMaxAge {
			continue
		}
		os.Remove(filepath.Join(s.windowDir(w), e.Name()))
	}
}

// ---------- metrics ----------

// Stats is what the cache tier can honestly say about itself. VictimAge is the
// real eviction horizon: the age of the window the worker last deleted from,
// i.e. how long a chunk survives here in practice. A byte budget could only
// have reported its own configuration back.
type Stats struct {
	Evictions uint64        // chunk files unlinked by the worker since start
	Refusals  uint64        // fills not cached because the disk was over the watermark
	VictimAge time.Duration // age of the last window evicted from, 0 if none yet
	FreeBytes int64         // what statfs says now
	MinFree   int64         // the watermark, in the same units
}

func (s *Store) Stats() Stats {
	st := Stats{
		Evictions: s.evictions.Load(),
		Refusals:  s.refusals.Load(),
		MinFree:   s.cfg.CacheMinFree,
	}
	if w := s.horizon.Load(); w != 0 {
		st.VictimAge = time.Duration(nowWindow()-w) * windowMinutes * time.Minute
	}
	st.FreeBytes, _ = s.cfg.free(s.cfg.CacheDir)
	return st
}
