# casfs

A content-addressed file store on top of any S3-compatible bucket, with lazy
chunked reads and a byte-capped local disk cache.

Whole files live in the bucket under their hex sha256, which is the entire
object key (optionally behind a configured prefix). Uploads are therefore
idempotent, and two writers racing on the same content write identical bytes,
so there is nothing to coordinate.

Locally, an object is cached as **one sparse file of its full size**, so a
consumer can mmap the whole thing and let the kernel tier RAM to SSD while
casfs tiers SSD to S3.

Zero dependencies outside the standard library. Linux only: presence is
SEEK_DATA and eviction is FALLOC_FL_PUNCH_HOLE, and neither has a portable
analogue worth faking, so there is no fallback.

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

The cache never counts as durability. It is disposable by construction, and
the crash-safety section below leans on that hard.

## One read path

`Open(hash).ReadAt` always reads through the chunk cache. Never anything else.

A chunk miss is filled from one of two sources, and that is the *only*
difference between local and remote content:

- the spool file is still there, so `pread` the aligned range out of it
- it is not, so issue an aligned ranged GET

Either way the bytes are `pwrite`n into the object's sparse cache file **at
their true offset**, counted against `CacheBytes`, and evicted like any other
chunk. Two consequences worth having:

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
    AccessKey:  "...",     // static keys win; leave empty for the AWS default chain
    SecretKey:  "...",
    SpoolDir:   "/var/lib/app/spool",
    CacheDir:   "/var/lib/app/cache",
    CacheBytes: 8 << 30,
    ChunkSize:  4 << 20,   // default

    // How often a cache hit may refresh an object's mtime, which is what the
    // startup LRU seed reads. 0 means 1 hour, negative disables it.
    TouchInterval: time.Hour,
})

path := s.SpoolPath(hash)       // rename your finished file onto this, yourself
hash, err := s.Put(path)        // or let Put hash it and do the rename for you

done, err := s.Sync()           // upload everything spooled and not yet in the bucket
err = s.Release(hash)           // unlink the spool file, refuses until uploaded

f, err := s.Open(hash)          // *File: io.ReaderAt, io.Closer, Size() int64
n, err := f.ReadAt(p, off)      // copies, always correct, never needs a pin

err = f.Pin(off, n)             // this range may not be hole-punched
b, err := f.View(off, n)        // zero-copy window onto an mmap of the object
err = f.Unpin(off, n)           // ...and now it may be

err = s.Close()                 // flush, mark the cache clean, drop the fds

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

There is no manual `Evict`: eviction is driven by the byte cap alone. `Close`
is not a shutdown handshake either, it is a flush plus the clean marker, and
skipping it costs the cache and nothing else. The store owns no goroutines.

## Views and the pinning contract

`View` returns a subslice of a whole-object `PROT_READ` `MAP_SHARED` mapping of
the cache file, after filling whatever chunks the range needs. Nothing is
copied and nothing lands on the Go heap: a consumer can map a 4GB artifact,
walk an index inside it, and let the kernel decide what stays in RAM.

That mapping is coherent with the fills, on Linux, because `pwrite` and `mmap`
go through the same page cache. A chunk filled after the mapping was created is
visible through it immediately, with no remap and no barrier.

**A hole punch under a live mapping is silent.** The pages go away, the
mapping stays, and the range reads back as zeros: no error, no fault, no short
read. Whether that is harmless or catastrophic depends entirely on what the
consumer thinks those bytes mean. For a bloom filter it is catastrophic, since
zeroed bits turn "maybe present" into "definitely absent", which is a wrong
answer rather than a slow one.

So: **`Pin(off, n)` before reading a `View`, `Unpin(off, n)` after.** Eviction
skips every chunk a pinned range touches, and will blow through `CacheBytes`
rather than punch one. Pins are counted, live in memory only, and die with the
process, which is correct, because so does every mapping they protect.

`ReadAt` needs no pins. It copies, and it holds an internal pin for the
duration of the copy, so it cannot be punched mid-read.

A `View` of a spool-resident object maps the spool file directly instead, so it
never doubles the bytes on disk. `Release` unlinking that file afterwards does
not disturb the mapping, because unlinking never does.

`File.Close` unmaps, which invalidates every `View` that `File` handed out.
Touching one afterwards is a segfault, not an error return.

## The drop folder

There is no `AdoptDir`, because the spool directory already is one. Point your
writer at `SpoolDir`, name files after their hash, call `Sync` on a ticker, and
files trickle to S3 at whatever pace you tick. That is the whole feature and it
needs no library code.

## Layout

```
<SpoolDir>/<hash>                              durable
<CacheDir>/<first 2 hex of hash>/<hash>        disposable, sparse, full size
<CacheDir>/.clean                              written by Close, removed by New
```

One file per object, created at the object's full length and otherwise empty.
A fill `pwrite`s a chunk at its true offset; everything never fetched, and
everything evicted, is a hole that costs no blocks.

**The kernel's extent map is the index.** `New` walks each file with
`SEEK_DATA`/`SEEK_HOLE` and rebuilds an in-memory bitmap of which chunks are
present. A chunk counts as present only if its whole range is reported as data,
because the kernel is allowed to report data where there is really a hole but
never the reverse, so the worst that conservatism costs is a refill. There is
still no on-disk index, no manifest, and no compaction. The filesystem is the
database, and now it is also the presence bitmap.

Anything in the cache directory that is not a hash-named file in its own
two-hex directory is deleted on startup, which is also the entire migration
story off the old one-file-per-chunk layout. There is no compatibility mode:
the cache is disposable, so a layout change is paid for by refetching.

## Eviction

An in-memory LRU keyed by (hash, chunk index), capped by `CacheBytes`. Evicting
means `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)` over that chunk's
range: the blocks go back to the filesystem, the file keeps its length, and the
range reads as zeros from then on. Pinned chunks are skipped, so a pin outranks
the cap. Spool files are outside the cache entirely: they are never evicted,
and only `Release` removes one.

Because eviction can now cut a hole in a file someone is reading, both read
paths take an internal pin for the duration of a fill and of a copy. That is
also why a duplicate fill of the same chunk stays correct with no singleflight:
both writers pwrite identical bytes to the same offsets, and both hold the
range against eviction while they do it.

### Throttled touch on read

The in-memory LRU is the live authority. But it dies with the process, and the
restart seed comes from mtime, so an object fetched three days ago and read
every second since would look ancient to a fresh process and be evicted first,
exactly backwards. So a cache hit also refreshes the file's mtime, throttled to
at most one `utimes` per object per `TouchInterval` (default 1 hour, negative
disables it). The last written mtime is kept in memory, so the throttle check
costs no stat and the common hit does no extra syscall at all.

There is one file per object now, so **the restart seed is per object, not per
chunk**: all of one object's chunks are reseeded with one timestamp, in index
order. That is a real loss of resolution and it is accepted, because the live
LRU is per chunk and takes over within seconds of a restart, while the seed
only has to get the coarse ordering between objects right.

The cost ceiling is one `utimes` per object per interval, which is now trivial:
a 50GB hot set of 4GB artifacts is 13 files.

## Crash safety: the cache is wiped, not journalled

The old layout got atomicity from `rename`. A sparse file has none: a fill is
one `pwrite`, and a process that dies with dirty pages can leave an extent that
`SEEK_DATA` calls present and that reads back half zeros. Nothing on disk can
tell that apart from a complete chunk.

Two sound answers exist. A per-object sidecar bitmap, written after the data
with an fsync between them, so presence is `SEEK_DATA` intersected with
committed bits. Or a clean-shutdown marker: `Close` fsyncs every cached file
and then writes `<CacheDir>/.clean`, `New` removes it, and a `New` that does
not find it wipes the cache.

**casfs takes the marker.** The sidecar taxes every fill with two fsyncs,
forever, to protect a cache whose entire contents can be refetched with one
ranged GET each. The marker costs one fsync per object at shutdown and nothing
at all in steady state, and its failure mode is a cold cache after a crash,
which is the same thing as a cold start. Trading a rare bounded cost for a
constant one is the wrong direction, so it is not built.

Consequences to know about:

- **A process that never calls `Close` starts cold every time.** That is the
  contract, not a bug.
- One process at a time per cache directory. `New` removing the marker means a
  second `New` over a live cache directory would wipe it out from under the
  first. The in-memory LRU already assumed single ownership.
- A `kill -9` costs the cache, never correctness, and never anything durable:
  the spool and the bucket are untouched.

## Dependency choice

Hand-rolled SigV4 over `net/http`: casfs needs exactly HEAD, PUT, GET and
ranged GET, which is about 60 lines of signing that both R2 and MinIO accept,
versus minio-go's transitive dependency tree for the same four calls.

The one AWS dependency is credential resolution, not S3: `aws-sdk-go-v2`'s
`config`/`credentials` supply `Config.Credentials`, so SSO, instance roles and
anything else the default chain knows about work, including their refresh.
Static `AccessKey`/`SecretKey` take precedence and never touch the chain (the
R2 and MinIO path). Credentials are retrieved per request; when they carry a
session token it is signed as a fourth header, `x-amz-security-token`, and
`TestSignMatchesAWSSigner` compares the whole Authorization header against the
SDK's own signer with and without one. The default chain also supplies the
region when `Region` is empty, before the `"auto"` fallback.

## Notes and deliberate omissions

- `Open` on a hash that is neither spooled nor known to this process issues one
  HEAD to learn the size, then memoizes it. There is still no on-disk index:
  the cache file *is* the object's full length, so a clean restart learns the
  size of everything it has cached for free. The in-memory size and
  upload-confirmation maps are caches only; losing one costs one HEAD.
- While a file is spool-resident, ranges that `ReadAt` touches exist twice on
  disk, once in the spool file and once in the cache file. That is the price of
  the single read path, and it resolves itself at `Release`. `View` does not
  pay it: it maps the spool file directly.
- One open descriptor per object touched since startup, never per chunk. That
  is bounded by the number of distinct objects, which is what this store is
  for; a workload that opens thousands would want an fd LRU that does not exist
  yet.
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

The sparse layout is tested against the filesystem rather than against itself:
eviction is asserted in `st_blocks` (8 chunks of 64KB read under a 256KB cap
leave a 512KB file holding exactly 256KB of blocks), presence recovery is
asserted by restarting over an interleaved set of filled chunks and reading
them back with the S3 endpoint shut down, `View` is asserted to alias rather
than copy, a pinned range is asserted to survive eviction pressure that punches
everything around it, and the same range is then unpinned and asserted to read
back as zeros, so the hazard the pin exists for is a test rather than a claim.

That signed payload hash is also the real defence against a lying spool file
name: a compliant endpoint rejects the mismatched bytes before storing them.
The local streaming digest turns that into a legible error and covers endpoints
that do not verify.
