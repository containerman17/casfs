package casfs

import (
	"context"
	"io/fs"
	"path/filepath"
	"time"
)

// AdoptDir walks dir and hands every regular file to the store: Register (the
// file becomes readable by hash at once, straight off the local disk), then
// Upload (a no-op if the bucket already has that content), then onPut, then
// optionally Release, which deletes the local original so later reads go
// through the chunk cache.
//
// pace is the delay between files, which is how "drop files in a folder and
// they trickle to S3" is spelled. onPut receives the path relative to dir and
// the content hash; returning an error aborts the walk, so a caller that needs
// to persist the name to hash mapping can do it before the original is
// released.
//
// This is a helper over the public API, not a daemon. Run it in a goroutine or
// on a ticker if you want it continuous.
func (s *Store) AdoptDir(ctx context.Context, dir string, pace time.Duration, release bool, onPut func(rel, hash string) error) error {
	first := true
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return err
		}
		if !first && pace > 0 {
			t := time.NewTimer(pace)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
			}
		}
		first = false
		if err := ctx.Err(); err != nil {
			return err
		}

		hash, err := s.Register(p)
		if err != nil {
			return err
		}
		if err := s.Upload(hash); err != nil {
			return err
		}
		if onPut != nil {
			rel, relErr := filepath.Rel(dir, p)
			if relErr != nil {
				rel = p
			}
			if err := onPut(rel, hash); err != nil {
				return err
			}
		}
		if release {
			return s.Release(hash)
		}
		return nil
	})
}
