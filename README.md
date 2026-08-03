# casfs

A content-addressed file store on top of any S3-compatible bucket, with lazy
chunked reads and a shared local disk cache.

Whole files live in the bucket under their hex sha256, which is the entire
object key (optionally behind a configured prefix). Uploads are therefore
idempotent, and two writers racing on the same content write identical bytes,
so there is nothing to coordinate.

Locally, an object is cached as **plain 4MB chunk files in a shared directory
of time windows**. Reads are `open`+`pread`; a consumer that genuinely needs a
range for the life of its process can map it, one mapping per chunk.

Zero dependencies outside the standard library, apart from AWS credential
resolution. Linux only: the cache uses `statfs` and `mmap` with no fallback.

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

The cache never counts as durability. It is disposable by construction, which
is what lets everything below be as blunt as it is.

## One read path

`Open(hash).ReadAt` always reads through the chunk cache. Never anything else.

A chunk miss is filled from one of two sources, and that is the *only*
difference between local and remote content:

- the spool file is still there, so `pread` the aligned range out of it
- it is not, so issue an aligned ranged GET

Concurrent misses on one chunk collapse into a single upstream read. The bytes
are handed back to every waiter and, if the disk has room, written to the
current window as `<hash>.<index>` by tmp + fsync + rename.

**The upload transition is invisible.** Ranges that real traffic touched while
the file was spool-resident keep being served from the spool descriptor the
`File` holds, so when the upload ACKs and `Release` unlinks the spool file, the
hot path does not notice. `Release` stays dumb on purpose: it does not pre-warm
the cache. Ranges nobody ever read while the file was local are cold by
definition, and copying gigabytes of them in would only push out chunks
somebody else is using.

## API

```go
s, err := casfs.New(casfs.Config{
    Endpoint:  "https://<account>.r2.cloudflarestorage.com", // or http://127.0.0.1:9000
    Region:    "auto",
    Bucket:    "epochs",
    Prefix:    "v1/",     // optional, used verbatim
    AccessKey: "...",     // static keys win; leave empty for the AWS default chain
    SecretKey: "...",
    SpoolDir:  "/var/lib/app/spool",
    CacheDir:  "/var/lib/app/cache",
    ChunkSize: 4 << 20,   // default

    // Admission watermark, in absolute bytes of free space. 0 means 5% of the
    // filesystem, i.e. cache up to 95% full.
    CacheMinFree: 20 << 30,
    // Whole windows older than this are deleted by name, whatever the disk
    // looks like. 0 means 30 days.
    CacheMaxAge: 30 * 24 * time.Hour,
})

path := s.SpoolPath(hash)       // rename your finished file onto this, yourself
hash, err := s.Put(path)        // or let Put hash it and do the rename for you

done, err := s.Sync()           // upload everything spooled and not yet in the bucket
err = s.Release(hash)           // unlink the spool file, refuses until uploaded

f, err := s.Open(hash)          // *File: io.ReaderAt, io.Closer, Size() int64
n, err := f.ReadAt(p, off)      // the query path: pread and copy

v, err := f.View(off, n)        // long-lived: one mapping per chunk
b := v.Slice(off, n)            // aliases inside a chunk, copies across one
err = v.Close()                 // unmaps

err = s.Close()                 // stops the eviction worker, nothing else

err = s.SetPointer("latest", hash)
val, err := s.GetPointer("latest") // fs.ErrNotExist if absent

st := s.Stats()                  // evictions, admission refusals, victim age, free bytes
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
They have EXACTLY THE SPOOL SEMANTICS OF CONTENT. `SetPointer` writes the value
under the spool (`.pointers/<name>`, tmp+rename) and returns, making no network
call at all; `Sync` uploads it AFTER that pass's content, so a bucket reader
following a pointer never lands on an object that is not there yet, and then
deletes the local file, the same release an artifact gets. A pass whose content
upload failed leaves its pointers spooled and retries next time.

`GetPointer` answers from the spooled value while there is one. Once it has
been uploaded and released, or on a store that never wrote it, the read goes to
the bucket and the value is written back to the spool, so the next read and the
next process are local again. That write-back is clean, never dirty: a store
re-uploading a value it did not author could only put a stale pointer over a
newer one. A bucket read that fails bubbles as it is, and a missing pointer
wraps `fs.ErrNotExist`; nothing is ever invented.

A store whose credentials have expired therefore keeps setting and reading its
own pointers exactly as an offline one does. Only uploads stall, and the values
simply stay in the spool until they can go.

`Close` stops the eviction worker and does nothing else. There is no flush, no
marker, and no shutdown handshake: skipping it costs nothing at all.

## Layout

```
<SpoolDir>/<hash>                       durable until uploaded
<SpoolDir>/.pointers/<name>             durable until uploaded
<CacheDir>/<window>/<hash>.<index>      disposable, 4MB, one file per chunk
<CacheDir>/<window>/<hash>.<index>.*.tmp   a fill in flight
```

A chunk file is named by **the artifact hash and the chunk index, not by a
content hash of the chunk**. That name already identifies immutable bytes
uniquely, a reader can derive it without anyone's chunk list, and any process
looking at the file can decide who it belongs to. A content-hashed name would
buy deduplication nobody has ever needed here and cost the ability to find a
chunk you have not already been told the hash of.

A window is `unix_minutes / 20` as an integer, in UTC, never local time. The
window a file sits in **is** its recency, so the LRU lives in the directory
tree rather than in anyone's memory and survives a restart with no journal.

`New` does one **name-only walk** of the window tree to build this process's
`chunk -> window` map (175k files in ~110ms warm on ext4). Anything at the top
level that is not a numeric window directory is deleted, which is the entire
migration story off the old sparse per-artifact cache. There is no
compatibility mode: the cache is disposable, so a layout change is paid for by
refetching.

That map is a **hint owned by one process**. An entry that is wrong because a
sibling process evicted the file costs one `ENOENT` and a refetch, never a
wrong answer, so no two processes have to agree about anything and several may
share one cache directory.

## Recency: promote on touch

Reading a chunk that is in **any** window older than the current one renames it
into the current one. That is at most one rename per chunk per window, and it
is deliberately greedy: promoting only when a chunk is two or more windows
behind stops distinguishing hot from cold exactly when it matters, because
under pressure everything the worker is about to eat looks equally stale, and
the cache degrades to FIFO.

The file is opened before the rename, so a promotion that loses a race to
another process costs a map entry and never the read in flight.

## Admission control, not eviction, on the write path

Before a fill is written, `statfs` says how many bytes are available. Over the
watermark, **the chunk is not cached**: the fetched bytes are served from
memory and forgotten. Nothing is ever deleted to make room for a fill.

The fill itself is tmp + **fsync** + rename. The fsync is not tuning. Power
loss between the write and the rename must never leave a torn chunk under a
correct name: nothing reads chunk files back with a checksum, so torn bytes
under the right name are a silent wrong answer, and a half-written bloom page
answers "definitely absent" for keys that are there. A tmp name never becomes a
chunk name, so a torn write is only ever garbage to collect.

The watermark is absolute bytes, not a percentage, because casfs does not own
the filesystem: what matters to everything else on the box is how much room is
left, not what share of it casfs took. The default is 5% of the filesystem free,
i.e. cache up to 95% full.

## Eviction: one background worker

One goroutine per store. While the disk is over the watermark it unlinks **one
file at a time from the oldest non-current window**, in readdir order, with a
small sleep between deletes; otherwise it idles on a long poll. The victim
window's directory handle is cached across deletes, so a delete costs one
`unlink` and not a readdir of a window holding a hundred thousand files. One
delete per tick is the throttle; there is no other one.

**It never touches the current window.** If only the current window has files,
the worker stops and admission control carries the load: a saturated cache
freezes full rather than eating the fills it just made. Churning is strictly
worse than freezing, because every evicted-and-refetched chunk is a GET that
bought nothing.

A delete that returns `ENOENT` counts as progress: a sibling process got there
first. A window the worker drains is `rmdir`ed. Unlinking while `getdents`
walks the same directory may skip entries, so a window that refuses to `rmdir`
is simply revisited on the next pass.

Separately, and regardless of disk fill, whole window directories older than
`CacheMaxAge` (default 30 days) are deleted **by name**, with no stat and no
per-file work. That is safe precisely because a promotion's target is always
the current window: nothing anyone still reads can be sitting in a directory
named thirty days ago. Stray `*.tmp` files older than an hour are collected in
the same pass.

`Stats()` reports evictions, admission refusals, and **the age of the window
the worker last deleted from**. That last number is the honest cache horizon:
how long a chunk actually survives here. A byte budget could only ever have
reported its own configuration back.

## Views: the one place mappings are allowed

`ReadAt` is the query path and it copies. Use it for everything transient.

`View(off, n)` is for ranges a consumer reads for the life of its process:
indexes, dictionaries, filters. It maps one chunk file per chunk the range
covers. `Slice` is zero-copy inside a chunk and **copies across a chunk
boundary**, which is the whole price of chunk files not being contiguous: at
4MB granularity a 69-byte index entry straddles one boundary in about 60000, so
the copy is noise and the common case allocates nothing.

Because a mapping keeps its inode alive, a chunk that is unlinked while mapped
keeps its blocks until the last `Close`. The ghost disk a consumer can hold is
therefore bounded by the size of its resident set, and that is the accepted
cost of not having a pin protocol. In exchange there is no way for eviction to
turn live bytes into zeros, which is what the old hole-punch cache had to be
defended against with pins.

A `View` of a spool-resident object maps the spool file directly, so it never
doubles the bytes on disk. A chunk the disk refused to cache is held as heap
bytes instead, so a view is always complete whatever the disk is doing.

## The drop folder

There is no `AdoptDir`, because the spool directory already is one. Point your
writer at `SpoolDir`, name files after their hash, call `Sync` on a ticker, and
files trickle to S3 at whatever pace you tick. That is the whole feature and it
needs no library code.

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

- Object sizes are not persisted. `Open` on a hash that is neither spooled nor
  known to this process issues one HEAD and memoizes it, so a restart pays one
  HEAD per artifact it opens and nothing else. The old sparse layout learned
  sizes from the cache file's length; plain chunk files do not carry that, and
  one HEAD per artifact is cheaper than an index that could go stale.
- The query path opens the chunk file on every `ReadAt`. That is `open`,
  `pread`, `close`: three syscalls, no descriptor table to bound, and no cache
  to invalidate when a sibling process deletes the file underneath.
- Over the watermark every read refetches, because nothing is allowed to land.
  That is a real degraded mode and it is counted (`Stats().Refusals`) rather
  than hidden.
- Not implemented: multipart upload, DELETE, LIST, retries and backoff, and
  virtual-host-style addressing.

## Testing

`go test -race ./...` runs entirely in process against a fake S3 built on
`httptest`. No docker, no network. The fake verifies that requests carry a
well-formed SigV4 Authorization header and that PUT bodies match the signed
payload hash; the signing key derivation is pinned to the published AWS test
vector. Signature acceptance by a real service is not covered offline.

The cache is tested against the filesystem rather than against itself. The
worker is asserted to drain the oldest window first, whole, and then to stop
dead when only the current window is left. Admission refusal is driven by a
fake `statfs`, and a view over a disk that refuses everything is asserted to
still return the right bytes. A chunk planted a day back in the window tree is
asserted to be renamed forward by the read that touches it. A truncated tmp is
asserted never to become a named chunk, and the read that follows it is
asserted to come back correct. Thirty-two goroutines racing on one cold chunk
are asserted to cost exactly one GET, and eight readers running against a
goroutine deleting the entire cache in a loop are asserted to return
byte-correct answers throughout.

That signed payload hash is also the real defence against a lying spool file
name: a compliant endpoint rejects the mismatched bytes before storing them.
The local streaming digest turns that into a legible error and covers endpoints
that do not verify.
