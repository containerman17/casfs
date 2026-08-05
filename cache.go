package casfs

// THE WINDOWED SHARED CHUNK CACHE.
//
// The cache is a directory of plain chunk files, 4MB each, named
// `<artifacthash>.<index>`. The name is NOT a content hash: the artifact hash
// plus the index already names immutable bytes uniquely, is derivable without
// anyone's chunk list, and keeps ownership of a file decidable by looking at
// it.
//
// The tree is `<CacheDir>/<window>/<namespace>/<hash>.<index>`.
//
// THE WINDOW COMES FIRST, and that ordering is the whole design. It is the UTC
// start of a 20-minute bucket, written 2026-08-03T12-40: fixed width in every
// field, so ALPHABETICAL ORDER IS CHRONOLOGICAL ORDER. The globally oldest
// cohort is therefore the lexicographically first directory under the cache
// root, which collapses eviction into `rm -r` of one directory: no per-file
// victim selection, no cursor, no scan. It also lets an operator eyeball the
// tree and hand-trim it, which an opaque bucket number did not.
//
// THE NAMESPACE under it is the store's owner (epochdb passes a blockchainID).
// Hash filenames are illegible to a human, so this level exists to make
// ownership VISIBLE: `du` per owner, `rm -r cache/*/<owner>` to wipe one
// owner, and the one-writer-per-owner invariant enforced by the directory tree
// instead of by a convention.
//
// The window a file sits in IS its recency, so the LRU lives in the directory
// tree rather than in anyone's memory and survives a restart with no journal.
// Nothing here is a byte budget: fills are governed by ADMISSION CONTROL (over
// the disk watermark, do not cache, serve from memory) and space is recovered
// by ONE BACKGROUND WORKER dropping whole old windows. The worker never
// touches the current window, so a saturated cache freezes full instead of
// churning its own fresh fills.

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// windowMinutes is the cache's recency granularity, and now also its
	// EVICTION GRANULARITY, since a window is dropped whole. Small enough that
	// one cohort is not the whole cache, large enough that a hot chunk is
	// renamed three times an hour at worst. It must divide an hour, or the
	// minute field would stop being one of 00, 20, 40.
	windowMinutes = 20
	// windowLayout is the bucket's UTC start. Fixed width in every field, so a
	// plain string compare orders windows in time.
	windowLayout = "2006-01-02T15-04"
	// DefaultMaxAge is how long a window survives regardless of disk fill.
	DefaultMaxAge = 30 * 24 * time.Hour
	// defaultFullPct is the watermark: cache up to 95% of the filesystem.
	defaultFullPct = 95

	// settleDelay is how long the worker waits after dropping a window before
	// it believes statfs again. A whole cohort of unlinks does not show up in
	// f_bavail instantly, and evicting twice on one stale reading would throw
	// away a window nobody needed to lose.
	settleDelay  = time.Minute
	pollIdle     = 5 * time.Second
	sweepEvery   = 5 * time.Minute
	tmpMaxAge    = time.Hour
	readDirBatch = 4096
)

// windowName is the name of the bucket an event at t belongs to.
func windowName(t time.Time) string {
	return t.UTC().Truncate(windowMinutes * time.Minute).Format(windowLayout)
}

func curWindow() string { return windowName(time.Now()) }

// windowAt parses a name back to the instant its window started. It is exact
// in both directions: a name that does not re-format to itself is not one of
// ours, which rejects a stray directory and a minute field that is not 00, 20
// or 40 without needing a second rule for either.
func windowAt(name string) (time.Time, bool) {
	t, err := time.Parse(windowLayout, name)
	if err != nil || windowName(t) != name {
		return time.Time{}, false
	}
	return t, true
}

// windowDir is a whole cohort, every owner's chunks in it. Only the worker
// names this: it is the unit of eviction and of nothing else.
func (s *Store) windowDir(w string) string { return filepath.Join(s.cfg.CacheDir, w) }

// chunkDir is where THIS store's chunks live inside a window.
func (s *Store) chunkDir(w string) string {
	return filepath.Join(s.cfg.CacheDir, w, s.cfg.Namespace)
}

func chunkName(hash string, idx int64) string {
	return hash + "." + strconv.FormatInt(idx, 10)
}

// validChunkName recognizes this cache's own files and nothing else, so a
// stray, a tmp, or a leftover from an older layout is never mistaken for a
// chunk.
func validChunkName(name string) bool {
	dot := len(name) - 1
	for ; dot >= 0 && name[dot] != '.'; dot-- {
		if name[dot] < '0' || name[dot] > '9' {
			return false
		}
	}
	return dot == 64 && dot < len(name)-1 && validHash(name[:64])
}

// windows lists the cohorts present, in CHRONOLOGICAL ORDER, because os.ReadDir
// sorts by name and the names were built so those are the same thing.
func (s *Store) windows() ([]string, error) {
	ents, err := os.ReadDir(s.cfg.CacheDir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if _, ok := windowAt(e.Name()); ok {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// scanCache rebuilds the chunk->window map with ONE NAME-ONLY WALK of this
// store's own subdirectory of each window, and deletes anything at the cache
// root that is not a window (which is also the whole migration story off any
// older layout: the cache is disposable, so a layout change is paid for by
// refetching).
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
		if _, ok := windowAt(e.Name()); !ok {
			if err := os.RemoveAll(filepath.Join(s.cfg.CacheDir, e.Name())); err != nil {
				return err
			}
			continue
		}
		if err := s.scanWindow(e.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) scanWindow(w string) error {
	f, err := os.Open(s.chunkDir(w))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // some other owner's cohort, or an empty one
		}
		return err
	}
	defer f.Close()
	for {
		// f.ReadDir does not sort and does not stat, unlike os.ReadDir: this is
		// getdents and a name check, which is what keeps a startup walk over a
		// six-figure cache a fraction of a second.
		ents, err := f.ReadDir(readDirBatch)
		for _, e := range ents {
			name := e.Name()
			if !validChunkName(name) {
				continue
			}
			// A newer window wins, so a crash between the two halves of a
			// promote cannot leave a reader looking at the stale copy.
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

func (s *Store) forget(name, w string) {
	s.mu.Lock()
	if cur, ok := s.where[name]; ok && cur == w {
		delete(s.where, name)
	}
	s.mu.Unlock()
}

func (s *Store) forgetWindow(w string) {
	s.mu.Lock()
	for name, at := range s.where {
		if at == w {
			delete(s.where, name)
		}
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
	f, err := os.Open(filepath.Join(s.chunkDir(w), name))
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
func (s *Store) promote(name, from string) {
	cur := curWindow()
	if from == cur {
		return
	}
	dir := s.chunkDir(cur)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	err := os.Rename(filepath.Join(s.chunkDir(from), name), filepath.Join(dir, name))
	switch {
	case err == nil:
		s.mu.Lock()
		s.where[name] = cur
		s.mu.Unlock()
	case errors.Is(err, fs.ErrNotExist):
		// Someone else moved it or the worker ate its whole window. One stat
		// says which.
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

// fetch reads one chunk from the durable copy, VERIFIES IT AGAINST THE
// ARTIFACT'S OWN HASH LIST, and caches it if the disk has room. The returned
// bytes are shared with every other waiter and are READ-ONLY.
//
// THE VERIFICATION IS THE POINT OF THE WHOLE FORMAT and it happens HERE, on
// the fill, before the bytes are cached or handed to anyone. A cache HIT is
// not re-verified: the cached file was verified when it was filled and landed
// by fsync+rename, and re-hashing 4MB on every hot read is a cost with nothing
// to buy.
func (s *Store) fetch(a *artifact, idx int64) ([]byte, error) {
	name := chunkName(a.hash, idx)
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

	fl.b, fl.err = s.pull(a, idx)
	if fl.err == nil {
		if err := VerifyChunk(a.hash, a.list, idx, fl.b); err != nil {
			s.note(&s.fillErrors, "verify "+name, err)
			fl.b, fl.err = nil, err
		} else {
			s.admit(name, fl.b)
		}
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
func (s *Store) pull(a *artifact, idx int64) ([]byte, error) {
	off := idx * s.cfg.ChunkSize
	n := chunkLen(a.size, s.cfg.ChunkSize, idx)
	b := make([]byte, n)
	if f, err := os.Open(s.SpoolPath(a.hash)); err == nil {
		defer f.Close()
		if _, err := f.ReadAt(b, off); err != nil {
			return nil, err
		}
		return b, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	body, total, err := s.s3.get(s.key(a.hash), off, n)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	// A cheap early-out on the wrong object. It is no longer the integrity
	// check (fetch hashes these bytes against the artifact's own list), but a
	// size mismatch names the failure better than a hash mismatch does.
	if total != a.stored {
		return nil, fmt.Errorf("casfs: chunk %d of %s: the bucket's object is %d bytes, this store expected %d",
			idx, a.hash, total, a.stored)
	}
	if _, err := io.ReadFull(body, b); err != nil {
		return nil, err
	}
	return b, nil
}

// roomy reports whether the filesystem is under the watermark. THE ERROR IS
// PART OF THE ANSWER: a statfs that failed means the disk is unknown, which is
// not the same as full, and the two callers would otherwise read that one
// silent false in opposite directions (admit declines to cache, safe; the
// worker starts evicting, which empties the whole cache while a mount flaps).
func (s *Store) roomy() (bool, error) {
	free, err := s.cfg.free(s.cfg.CacheDir)
	if err != nil {
		return false, err
	}
	return free >= s.cfg.CacheMinFree, nil
}

// note records a cache-plane failure that has no caller to return it to. The
// cache degrades silently BY DESIGN (a fill that cannot land is served from
// memory, an eviction that cannot run just leaves the disk full), so without
// these counters a read-only cache directory, exhausted inodes or an fsync EIO
// turn a node into an S3 passthrough forever while Stats says everything is
// fine.
func (s *Store) note(c *atomic.Uint64, op string, err error) {
	c.Add(1)
	s.lastErr.Store("casfs: " + op + ": " + err.Error())
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
	ok, err := s.roomy()
	if err != nil {
		s.note(&s.fillErrors, "statfs", err)
		return
	}
	if !ok {
		s.refusals.Add(1)
		return
	}
	w := curWindow()
	dir := s.chunkDir(w)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		s.note(&s.fillErrors, "mkdir "+dir, err)
		return
	}
	f, err := os.CreateTemp(dir, name+".*.tmp")
	if err != nil {
		s.note(&s.fillErrors, "create tmp in "+dir, err)
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
		s.note(&s.fillErrors, "fill "+name, err)
		return
	}
	s.mu.Lock()
	s.where[name] = w
	s.mu.Unlock()
}

// ---------- the background worker ----------

// worker is the ONLY thing that deletes cached chunks: while the disk is over
// the watermark it drops the oldest window WHOLE and waits for statfs to
// settle, otherwise it idles.
func (s *Store) worker() {
	defer close(s.done)
	var lastSweep time.Time
	for {
		if time.Since(lastSweep) >= sweepEvery {
			s.sweep()
			lastSweep = time.Now()
		}
		d := pollIdle
		if s.step() {
			d = settleDelay
		}
		select {
		case <-s.stop:
			return
		case <-time.After(d):
		}
	}
}

// step is one worker decision, split out so a test can drive it without
// waiting on the poll. It reports whether it dropped a window.
//
// A STATFS FAILURE MEANS DO NOTHING. It is not "no room": read as one, a
// briefly flapping mount would drop one window per settleDelay until the
// entire cache was gone, silently, while Stats claimed the disk was full.
func (s *Store) step() bool {
	ok, err := s.roomy()
	if err != nil {
		s.note(&s.evictErrors, "statfs", err)
		return false
	}
	return !ok && s.evictOldest()
}

// evictOldest removes the oldest non-current window ENTIRELY and reports
// whether it did. One `rm -r`, no victim selection and no cursor: the names
// sort chronologically, so the first entry of a sorted readdir IS the oldest
// cohort, and everything in it is at least one window cold by construction.
//
// IT NEVER TOUCHES THE CURRENT WINDOW. If the current window is all there is,
// the worker stops and admission control carries the load: a saturated cache
// freezes full rather than eating the fills it just made, because every
// evicted-and-refetched chunk is a GET that bought nothing.
func (s *Store) evictOldest() bool {
	cur := curWindow()
	ws, err := s.windows()
	if err != nil {
		s.note(&s.evictErrors, "read cache dir", err)
		return false
	}
	for _, w := range ws { // chronological
		if w >= cur {
			return false // only current or newer left: stop
		}
		if err := os.RemoveAll(s.windowDir(w)); err != nil {
			// The worker reads false as "nothing left to evict" and goes back
			// to polling every pollIdle, so this counter is the only thing
			// between a cache that cannot free anything and total silence.
			s.note(&s.evictErrors, "evict window "+w, err)
			return false
		}
		s.evictions.Add(1)
		s.horizon.Store(w)
		s.forgetWindow(w)
		return true
	}
	return false
}

// sweep is the time-based half: the same whole-window drop, gated on the
// window's own name instead of on disk fill, plus collection of the tmp files
// a killed fill left behind.
//
// Expiring by name is safe because a promotion's target is always the CURRENT
// window: nothing a reader still wants can be sitting in a directory named
// thirty days ago.
func (s *Store) sweep() {
	cutoff := windowName(time.Now().Add(-s.cfg.CacheMaxAge))
	// A tmp can only ever have been created in the window that was current at
	// the time, so an hour of windows plus one is the whole search space.
	fresh := windowName(time.Now().Add(-tmpMaxAge - windowMinutes*time.Minute))
	ws, err := s.windows()
	if err != nil {
		s.note(&s.evictErrors, "read cache dir", err)
		return
	}
	for _, w := range ws {
		if w < cutoff {
			if err := os.RemoveAll(s.windowDir(w)); err != nil {
				s.note(&s.evictErrors, "expire window "+w, err)
				continue
			}
			s.forgetWindow(w)
			continue
		}
		if w >= fresh {
			s.collectTmp(w)
		}
	}
}

func (s *Store) collectTmp(w string) {
	ents, err := os.ReadDir(s.chunkDir(w))
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
		os.Remove(filepath.Join(s.chunkDir(w), e.Name()))
	}
}

// ---------- metrics ----------

// Stats is what the cache tier can honestly say about itself. VictimAge is the
// real eviction horizon: the age of the window the worker last dropped, i.e.
// how long a chunk survives here in practice. A byte budget could only have
// reported its own configuration back.
type Stats struct {
	Evictions uint64 // WINDOWS dropped by the worker since start, not files
	Refusals  uint64 // fills not cached because the disk was over the watermark
	// FillErrors is fills that failed for a reason that is NOT the watermark:
	// a read-only cache directory, no inodes, an fsync EIO. A node with a
	// climbing count here is an S3 passthrough and nothing else says so.
	FillErrors uint64
	// EvictErrors is the worker failing to measure or free space.
	EvictErrors uint64
	LastError   string        // most recent of either, "" if none
	VictimAge   time.Duration // age of the last window dropped, 0 if none yet
	// FreeBytes is what statfs says now, and -1 WHEN STATFS ITSELF FAILED:
	// zero would read as "disk full", the one explanation that is certainly
	// wrong when the question could not be asked.
	FreeBytes int64
	MinFree   int64 // the watermark, in the same units
}

func (s *Store) Stats() Stats {
	st := Stats{
		Evictions:   s.evictions.Load(),
		Refusals:    s.refusals.Load(),
		FillErrors:  s.fillErrors.Load(),
		EvictErrors: s.evictErrors.Load(),
		MinFree:     s.cfg.CacheMinFree,
	}
	st.LastError, _ = s.lastErr.Load().(string)
	if w, _ := s.horizon.Load().(string); w != "" {
		if t, ok := windowAt(w); ok {
			st.VictimAge = time.Since(t)
		}
	}
	var err error
	if st.FreeBytes, err = s.cfg.free(s.cfg.CacheDir); err != nil {
		st.FreeBytes = -1
	}
	return st
}
