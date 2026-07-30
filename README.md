# casfs

A content-addressed file store on top of any S3-compatible bucket, with lazy
chunked reads and a byte-capped local disk cache.

Whole files live in the bucket under their hex sha256, which is the entire
object key (optionally behind a configured prefix). Uploads are therefore
idempotent, and two writers racing on the same content write identical bytes,
so there is nothing to coordinate. Reads are lazy: a miss pulls one aligned
chunk via a ranged GET, not the whole object.

Zero dependencies outside the standard library.

## Read tiering

`Open(hash)` serves reads from the first tier that has the bytes, with no
caller-visible difference between them:

1. the original local file, whole and unchunked, while it is still registered
2. cached chunk files on local disk
3. the bucket, one aligned ranged GET per missing chunk

`Register(path)` computes the hash and puts the file in tier zero, doing no
network I/O at all. From that moment `Open(hash)` works. The original is only
dropped by an explicit `Release(hash)`, which refuses until the upload is
confirmed, so a hash is never left unreadable.

## API

```go
s, err := casfs.New(casfs.Config{
    Endpoint:   "https://<account>.r2.cloudflarestorage.com", // or http://127.0.0.1:9000
    Region:     "auto",
    Bucket:     "epochs",
    Prefix:     "v1/",     // optional, used verbatim
    AccessKey:  "...",
    SecretKey:  "...",
    CacheDir:   "/var/lib/app/casfs",
    CacheBytes: 8 << 30,
    ChunkSize:  4 << 20,   // default
})

hash, err := s.Register(path)   // hash + tier zero, no network
err = s.Upload(hash)            // idempotent, skips if the bucket has it
hash, err := s.Put(path)        // Register + Upload, synchronous
err = s.Release(hash)           // delete the original, upload-confirmed only

f, err := s.Open(hash)          // *File: io.ReaderAt, io.Closer, Size() int64
n, err := f.ReadAt(p, off)

err = s.SetPointer("latest", hash)
v, err := s.GetPointer("latest") // fs.ErrNotExist if absent

err = s.AdoptDir(ctx, dir, pace, release, func(rel, hash string) error { ... })
```

`AdoptDir` is the "drop files in a folder and they end up on S3 slowly" helper:
it walks the directory, registers and uploads each regular file, waits `pace`
between files, calls back with the relative path and hash (return an error to
abort, e.g. after failing to persist the mapping), and optionally releases the
original. It is a helper over the public API, not a daemon. Run it on a ticker
if you want it continuous.

Pointers are the one mutable, non-content-addressed object. A pointer name that
looks like a content hash is rejected, so the two key spaces cannot collide.

## Cache layout

```
<CacheDir>/<first 2 hex of hash>/<hash>.<chunkIndex>
<CacheDir>/<first 2 hex of hash>/<hash>.<chunkIndex>.tmp<random>   transient
```

One file per chunk, written to a tmp name in the same directory and renamed
into place. That rename is the entire crash-safety story: a torn tmp file is
garbage, and `New` deletes every `*.tmp*` it finds while scanning. There is no
on-disk index, no manifest, and no compaction. The filesystem is the database.

## Eviction

An in-memory LRU over chunk files, capped by `CacheBytes`. Recency is seeded
from mtime at startup and updated on hit; it is approximate on purpose. Evicting
means unlinking a whole chunk file, nothing else. Readers hold an open handle to
the chunk they are reading, and a POSIX unlink does not disturb an open file, so
eviction never races a read. Chunks are never fetched for content that has not
been uploaded (tier zero serves those reads from the original file), so
eviction can never strand an in-flight upload.

## Dependency choice

Hand-rolled SigV4 over `net/http`: casfs needs exactly HEAD, PUT, GET and
ranged GET, which is about 60 lines of signing that both R2 and MinIO accept,
versus minio-go's transitive dependency tree for the same four calls.

## Deviations from the original sketch

- `Put` is synchronous rather than queueing a background upload. The
  register/upload split gives the same contract without a daemon, a queue, or a
  `Close` that has to drain one: call `Register` then `Upload` yourself (or let
  `AdoptDir` pace it) if you want the upload to trail the write.
- No `Close` and no manual `Evict`. The store owns no goroutines and holds no
  file descriptors between calls, so there is nothing to shut down, and
  eviction is driven by the byte cap alone.
- `Open` on a hash this process has not registered or fetched issues one HEAD
  to learn the size, then memoizes it. Sizes are not persisted, because that
  would mean the on-disk index this design does not want.

## Testing

`go test -race ./...` runs entirely in process against a fake S3 built on
`httptest`. No docker, no network. The fake verifies that requests carry a
well-formed SigV4 Authorization header and that PUT bodies match the signed
payload hash; the signing key derivation is pinned to the published AWS test
vector. Signature acceptance by a real service is not covered offline.
