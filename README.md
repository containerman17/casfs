# casfs

A content-addressed file store on top of any S3-compatible bucket, with lazy
chunked reads and a byte-capped local disk cache.

Whole files live in the bucket under their hex sha256, which is the entire
object key (optionally behind a configured prefix). Uploads are therefore
idempotent, and two writers racing on the same content write identical bytes,
so there is nothing to coordinate.

Zero dependencies outside the standard library.

## The spool: durability is the filesystem

The store owns a spool directory. A caller adds content by atomically renaming
a file whose name is its hex sha256 into that directory. **That rename is the
registration.** There is no handshake, no ack, no journal, no in-memory
bookkeeping that a `kill -9` can lose. Either the rename happened or it did
not, and the filesystem already answered that question.

`Sync` scans the spool and uploads everything the bucket does not already have.
It can run at startup, on a ticker, or right after a write; a file dropped in
the spool by a process that then died is picked up by the next one to look. The
bytes are hashed while they stream to S3, so a file whose name lies about its
contents fails loudly and never pollutes a content address, without a separate
verification pass over a multi-gigabyte file.

`Release` is the only thing that removes a spool file, and it refuses until the
bucket is confirmed to hold the content. So a hash is never unreadable: the
durable copy is the spool file, then the bucket, and the two overlap.

Chunk cache files never count as durability. They are disposable by
construction.

## One read path

`Open(hash).ReadAt` always reads through the chunk cache. Never anything else.

A chunk miss is filled from one of two sources, and that is the *only*
difference between local and remote content:

- the spool file is still there, so `pread` the aligned range out of it
- it is not, so issue an aligned ranged GET

Either way the result is materialized as a normal cache file, counted against
`CacheBytes`, and evicted like any other chunk. Two consequences worth having:

- **The upload transition is invisible.** Ranges that real traffic touched
  while the file was spool-resident are already sitting in the chunk cache, so
  when the upload ACKs and `Release` unlinks the spool file, the hot path does
  not notice.
- **Eviction accounting is uniform.** One LRU, one cap, one kind of file. No
  special case for "the local one".

`Release` stays dumb on purpose: it does not pre-warm the cache with the whole
file. Ranges nobody ever read while the file was local are cold by definition,
and copying gigabytes of them in would evict genuinely hot chunks of other
files to do it. Those ranges fall to ranged GETs on demand, which is the point.

## API

```go
s, err := casfs.New(casfs.Config{
    Endpoint:   "https://<account>.r2.cloudflarestorage.com", // or http://127.0.0.1:9000
    Region:     "auto",
    Bucket:     "epochs",
    Prefix:     "v1/",     // optional, used verbatim
    AccessKey:  "...",
    SecretKey:  "...",
    SpoolDir:   "/var/lib/app/spool",
    CacheDir:   "/var/lib/app/chunks",
    CacheBytes: 8 << 30,
    ChunkSize:  4 << 20,   // default
})

path := s.SpoolPath(hash)       // rename your finished file onto this, yourself
hash, err := s.Put(path)        // or let Put hash it and do the rename for you

done, err := s.Sync()           // upload everything spooled and not yet in the bucket
err = s.Release(hash)           // unlink the spool file, refuses until uploaded

f, err := s.Open(hash)          // *File: io.ReaderAt, io.Closer, Size() int64
n, err := f.ReadAt(p, off)

err = s.SetPointer("latest", hash)
v, err := s.GetPointer("latest") // fs.ErrNotExist if absent

s.CacheUsage()                   // chunk bytes on disk, spool files excluded
```

`Put` is a convenience: it hashes the file and renames it into the spool, and
requires the file to be on the same filesystem as `SpoolDir`. A caller that
already knows the hash (because it just computed one while writing the file)
should skip `Put` entirely and rename onto `SpoolPath(hash)` itself. Both roads
end at the same rename.

`Sync` returns the hashes now confirmed present in the bucket, so the usual
loop is `for _, h := range done { s.Release(h) }`. Errors are collected per
file, so one bad spool entry does not stall the rest.

Pointers are the one mutable, non-content-addressed object. A pointer name that
looks like a content hash is rejected, so the two key spaces cannot collide.

There is no `Close` and no manual `Evict`. The store owns no goroutines and
holds no file descriptors between calls, so there is nothing to shut down, and
eviction is driven by the byte cap alone.

## The drop folder

There is no `AdoptDir`, because the spool directory already is one. Point your
writer at `SpoolDir`, name files after their hash, call `Sync` on a ticker, and
files trickle to S3 at whatever pace you tick. That is the whole feature and it
needs no library code.

## Layout

```
<SpoolDir>/<hash>                                                  durable
<CacheDir>/<first 2 hex of hash>/<hash>.<chunkIndex>               disposable
<CacheDir>/<first 2 hex of hash>/<hash>.<chunkIndex>.tmp<random>   transient
```

One file per chunk, written to a tmp name in the same directory and renamed
into place. That rename is the entire crash-safety story for the cache: a torn
tmp file is garbage, and `New` deletes every `*.tmp*` it finds while scanning.
There is no on-disk index, no manifest, and no compaction. The filesystem is
the database.

## Eviction

An in-memory LRU over chunk files, capped by `CacheBytes`. Recency is seeded
from mtime at startup and updated on hit; it is approximate on purpose.
Evicting means unlinking a whole chunk file, nothing else. Readers hold an open
handle to the chunk they are reading, and a POSIX unlink does not disturb an
open file, so eviction never races a read. Spool files are outside the cache
entirely: they are never evicted, and only `Release` removes one.

## Dependency choice

Hand-rolled SigV4 over `net/http`: casfs needs exactly HEAD, PUT, GET and
ranged GET, which is about 60 lines of signing that both R2 and MinIO accept,
versus minio-go's transitive dependency tree for the same four calls.

## Notes and deliberate omissions

- `Open` on a hash that is neither spooled nor known to this process issues one
  HEAD to learn the size, then memoizes it. Sizes are not persisted, because
  that would mean the on-disk index this design does not want. The in-memory
  size and upload-confirmation maps are caches only; losing them costs one HEAD.
- While a file is spool-resident, ranges that get read exist twice on disk, once
  in the spool file and once as chunks. That is the price of the single read
  path, and it resolves itself at `Release`.
- Not implemented: multipart upload, DELETE, LIST, retries and backoff,
  virtual-host-style addressing, and singleflight over concurrent fills of the
  same chunk (a duplicate fill is correct, just wasteful, and the LRU does not
  double-count it).

## Testing

`go test -race ./...` runs entirely in process against a fake S3 built on
`httptest`. No docker, no network. The fake verifies that requests carry a
well-formed SigV4 Authorization header and that PUT bodies match the signed
payload hash; the signing key derivation is pinned to the published AWS test
vector. Signature acceptance by a real service is not covered offline.

That signed payload hash is also the real defence against a lying spool file
name: a compliant endpoint rejects the mismatched bytes before storing them.
The local streaming digest turns that into a legible error and covers endpoints
that do not verify.
