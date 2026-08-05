package casfs

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE ONLY TEST HERE THAT TOUCHES A REAL CLOUD BUCKET, and the only exercise
// the multipart path has ever had outside the in-process fake. The fake accepts
// parts in order and echoes ETags it generated itself, which proves the shapes
// and nothing about AWS: ETag quotes surviving xml.Marshal, a genuine multi-GB
// body over the wire, a real EntityTooSmall, the completion that fails with 200
// OK and an Error body, and the abort actually removing the parts are all
// things only S3 can answer.
//
// It is skipped unless CASFS_LIVE_S3_BUCKET is set, so `go test ./...` stays
// offline and fast. Run it by hand:
//
//	CASFS_LIVE_S3_BUCKET=ilya-solohin-backups-ap-northeast-1 \
//	CASFS_LIVE_S3_REGION=ap-northeast-1 \
//	CASFS_LIVE_S3_ENDPOINT=https://s3.ap-northeast-1.amazonaws.com \
//	CASFS_LIVE_S3_PREFIX=epochdb-multipart-smoke/ \
//	go test -run TestLiveS3 -timeout 2h -v ./...
//
// Credentials come from the AWS default chain (SSO here). IT WRITES AND DELETES
// UNDER ITS PREFIX AND NOWHERE ELSE, and it cleans up after itself on every
// exit path, uploads included: an abandoned multipart upload is billed storage
// nobody will ever hear about again.
func liveStore(t *testing.T, dir string) (*Store, string) {
	t.Helper()
	bucket := os.Getenv("CASFS_LIVE_S3_BUCKET")
	if bucket == "" {
		t.Skip("set CASFS_LIVE_S3_BUCKET (and _REGION/_ENDPOINT/_PREFIX) to run against real S3")
	}
	prefix := os.Getenv("CASFS_LIVE_S3_PREFIX")
	if prefix == "" {
		t.Fatal("CASFS_LIVE_S3_PREFIX is required: this test must never write to a bucket's root")
	}
	// A sub-prefix per run, so a run that dies without cleaning up cannot make
	// the next one's listings ambiguous.
	prefix = fmt.Sprintf("%s%d/", prefix, time.Now().UnixNano())
	s, err := New(Config{
		Endpoint: os.Getenv("CASFS_LIVE_S3_ENDPOINT"),
		Region:   os.Getenv("CASFS_LIVE_S3_REGION"),
		Bucket:   bucket,
		Prefix:   prefix,
		SpoolDir: filepath.Join(dir, "spool"),
		CacheDir: filepath.Join(dir, "cache"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, prefix
}

// payloadBlock is the unit the deterministic payload is generated in. It
// divides the chunk size, so a chunk boundary is always a block boundary.
const payloadBlock = 64 << 10

// fillPayload writes the deterministic payload's bytes for [off, off+len(p))
// into p. splitmix64 keyed by absolute block index, so ANY range is computable
// directly without streaming to it, which is what lets a spot check at 5 GiB
// cost nothing. Incompressible enough that S3 is moving real bytes.
func fillPayload(p []byte, off int64) {
	var blk [payloadBlock]byte
	for len(p) > 0 {
		idx := off / payloadBlock
		x := uint64(idx) * 0x9E3779B97F4A7C15
		for i := 0; i < payloadBlock; i += 8 {
			x += 0x9E3779B97F4A7C15
			z := x
			z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
			z = (z ^ (z >> 27)) * 0x94D049BB133111EB
			binary.LittleEndian.PutUint64(blk[i:], z^(z>>31))
		}
		n := copy(p, blk[off%payloadBlock:])
		p, off = p[n:], off+int64(n)
	}
}

// writePayload lays down size bytes of the deterministic payload at path.
func writePayload(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	for off := int64(0); off < size; off += int64(len(buf)) {
		b := buf[:min(int64(len(buf)), size-off)]
		fillPayload(b, off)
		if _, err := f.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
}

// signedReq issues one signed request with an empty body and returns the body.
// TEST-ONLY: casfs itself never deletes an object and never lists an upload, so
// neither belongs on the client. The cleanup this test owes the bucket does.
func (c *s3) signedReq(t *testing.T, method, key string, q url.Values) []byte {
	t.Helper()
	u, err := c.urlFor(key)
	if err != nil {
		t.Fatal(err)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.sign(req, emptySHA256, time.Now()); err != nil {
		t.Fatal(err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		t.Fatalf("%s %s: %s: %s", method, key, resp.Status, body)
	}
	return body
}

// liveUploads lists the multipart uploads still in progress under the store's
// prefix. Zero is the only acceptable answer at the end of a run.
func liveUploads(t *testing.T, s *Store) []string {
	t.Helper()
	body := s.s3.signedReq(t, http.MethodGet, "", url.Values{"uploads": {""}, "prefix": {s.cfg.Prefix}})
	var out struct {
		Uploads []struct {
			Key      string `xml:"Key"`
			UploadID string `xml:"UploadId"`
		} `xml:"Upload"`
	}
	if err := xml.Unmarshal(body, &out); err != nil {
		t.Fatalf("list uploads: %v: %s", err, body)
	}
	var ids []string
	for _, u := range out.Uploads {
		ids = append(ids, u.Key+" "+u.UploadID)
	}
	return ids
}

// liveKeys lists every object key under the store's prefix.
func liveKeys(t *testing.T, s *Store) []string {
	t.Helper()
	body := s.s3.signedReq(t, http.MethodGet, "", url.Values{"list-type": {"2"}, "prefix": {s.cfg.Prefix}})
	var listed struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal(body, &listed); err != nil {
		t.Fatalf("list objects: %v: %s", err, body)
	}
	var keys []string
	for _, o := range listed.Contents {
		keys = append(keys, o.Key)
	}
	return keys
}

// liveCleanup removes every object under the store's prefix and aborts every
// upload still open there. Deferred, so it runs on failure too.
//
// IT RE-LISTS AFTERWARDS AND FAILS IF ANYTHING SURVIVED, which is not
// belt-and-braces: S3 answers a DELETE for a key that does not exist with 204,
// so a cleanup aimed at the wrong key reports perfect success and leaves the
// object (and its bill) exactly where it was. Keys go in WHOLE: s3.urlFor takes
// the full key and Store.key is what prepends cfg.Prefix, so stripping the
// prefix off a listed key aims the DELETE at the bucket root.
func liveCleanup(t *testing.T, s *Store) {
	for _, key := range liveKeys(t, s) {
		s.s3.signedReq(t, http.MethodDelete, key, nil)
	}
	for _, u := range liveUploads(t, s) {
		key, id, _ := strings.Cut(u, " ")
		s.s3.signedReq(t, http.MethodDelete, key, url.Values{"uploadId": {id}})
		t.Errorf("cleanup had to abort a leftover upload: %s", u)
	}
	if left := liveKeys(t, s); len(left) != 0 {
		t.Errorf("cleanup left %d object(s) in the bucket: %v", len(left), left)
	}
}

// TestLiveS3MultipartAbort is the CHEAP half and runs first on purpose: a
// deliberately illegal part size makes real S3 reject the completion, which is
// the only way to see the three things the fake cannot show without moving
// gigabytes. Parts under 5 MiB upload FINE and only the completion refuses
// them, so this costs 3 MiB and reaches EntityTooSmall, the error-body branch,
// and the abort that has to leave the bucket clean behind it.
func TestLiveS3MultipartAbort(t *testing.T) {
	dir := t.TempDir()
	s, _ := liveStore(t, dir)
	defer liveCleanup(t, s)

	// One ordinary single-PUT object first, so the deferred cleanup has
	// something real to delete on every run. A cleanup that never deletes
	// anything is a cleanup nobody has tested.
	small := filepath.Join(dir, "tiny")
	writePayload(t, small, 64<<10)
	if _, err := s.Put(small); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	if len(liveKeys(t, s)) != 1 {
		t.Fatalf("want exactly the one object just uploaded, got %v", liveKeys(t, s))
	}

	// Vars for exactly this reason. Restored so the 5 GiB test below sees the
	// real thresholds.
	defer func(mt, ps int64) { multipartThreshold, partSize = mt, ps }(multipartThreshold, partSize)
	multipartThreshold, partSize = 2<<20, 1<<20

	path := filepath.Join(dir, "small")
	writePayload(t, path, 3<<20)
	if _, err := s.Put(path); err != nil {
		t.Fatal(err)
	}
	_, err := s.Sync()
	if err == nil {
		t.Fatal("S3 completed a multipart upload whose parts are under the 5 MiB minimum")
	}
	// The failure has to be S3's own, reported as S3 named it, and the abort on
	// the way out has to have worked: putMultipart says so explicitly when it
	// did not, and a silent orphan is the whole reason it says so.
	//
	// WHICH BRANCH REPORTS IT IS NOT S3'S CONTRACT and this test deliberately
	// does not care: observed 2026-08-05, the same request returned a 200 OK
	// carrying an <Error> body on one run (caught by the completion's own XML
	// check) and a plain 400 on the next (caught by httpErr). Both are real,
	// both must abort, so the assertion is on the code and not on the status.
	if !strings.Contains(err.Error(), "EntityTooSmall") {
		t.Fatalf("want EntityTooSmall from real S3, got: %v", err)
	}
	if strings.Contains(err.Error(), "aborting upload") {
		t.Fatalf("the abort itself failed, so parts are still in the bucket: %v", err)
	}
	if left := liveUploads(t, s); len(left) != 0 {
		t.Fatalf("the abort returned success but %d upload(s) are still open: %v", len(left), left)
	}
	t.Logf("real S3 refused the completion as expected: %v", err)
}

// TestLiveS3MultipartRoundTrip is the real thing: an artifact just over 5 GiB,
// which is the size class Fuji's epochs land in, through the same Put -> Sync
// -> Release -> Open path a node uses, against the real bucket. It proves the
// name a multipart object comes back under is the name its content commits to,
// that every 4MB chunk verifies against the list over the wire, and that the
// short final chunk and the chunk boundaries read correctly.
func TestLiveS3MultipartRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("moves 10 GB")
	}
	dir := t.TempDir()
	s, _ := liveStore(t, dir)
	defer liveCleanup(t, s)

	// Just over 5 GiB, and deliberately NOT chunk-aligned: 5 GiB is an exact
	// multiple of 4MB, so a round size would never exercise a short final
	// chunk. This is 1281 chunks, the last of them 1048573 bytes.
	const size = 5<<30 + 1048573
	path := filepath.Join(dir, "epoch")

	start := time.Now()
	writePayload(t, path, size)
	t.Logf("generated %d bytes in %s", size, time.Since(start).Round(time.Millisecond))

	start = time.Now()
	hash, err := s.Put(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Put (hash list + tail + rename) in %s, name %s", time.Since(start).Round(time.Millisecond), hash)

	start = time.Now()
	if _, err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	up := time.Since(start)
	t.Logf("UPLOAD %d bytes in %s (%.1f MB/s)", size, up.Round(time.Millisecond), float64(size)/up.Seconds()/1e6)

	// Drop the local copy: from here every byte comes off the wire, which is
	// the only way the read path is actually being tested.
	if err := s.Release(hash); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.SpoolPath(hash)); err == nil {
		t.Fatal("Release left the local copy, so the reads below would not touch S3")
	}

	// Open re-derives sha256(list) from the tail it fetches and refuses a name
	// that does not match, so reaching this line IS the name reproducing after
	// a 41-part multipart assembly.
	f, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Size() != size {
		t.Fatalf("Size = %d, want %d: the tail did not survive the round trip", f.Size(), size)
	}

	// Every chunk, in order, verified against the list inside casfs before it
	// is served. The read size straddles chunk boundaries by construction, so
	// the cross-chunk seam is exercised on every single read rather than once.
	start = time.Now()
	buf := make([]byte, 3<<20+1013)
	want := make([]byte, len(buf))
	for off := int64(0); off < size; off += int64(len(buf)) {
		n := min(int64(len(buf)), size-off)
		if _, err := f.ReadAt(buf[:n], off); err != nil && err != io.EOF {
			t.Fatalf("ReadAt(%d): %v", off, err)
		}
		fillPayload(want[:n], off)
		if !bytes.Equal(buf[:n], want[:n]) {
			t.Fatalf("bytes differ at offset %d", off)
		}
	}
	down := time.Since(start)
	t.Logf("DOWNLOAD+VERIFY %d bytes in %s (%.1f MB/s)", size, down.Round(time.Millisecond), float64(size)/down.Seconds()/1e6)

	// Spot checks on the seams that a whole-file pass can still get lucky on:
	// the first chunk boundary, the boundary into the SHORT final chunk, and
	// the last byte of the object. View is the mmap path and ReadAt the pread
	// one, so both read roads are covered.
	cs := s.cfg.ChunkSize
	last := (size / cs) * cs
	for _, tc := range []struct{ off, n int64 }{
		{cs - 16, 32},       // across the first chunk boundary
		{last - 16, 32},     // across the boundary into the short final chunk
		{size - 100, 100},   // the short chunk's tail, where casfs's own tail begins
		{last, size - last}, // the whole short final chunk
	} {
		fillPayload(want[:tc.n], tc.off)
		got := make([]byte, tc.n)
		if _, err := f.ReadAt(got, tc.off); err != nil {
			t.Fatalf("ReadAt(%d,%d): %v", tc.off, tc.n, err)
		}
		if !bytes.Equal(got, want[:tc.n]) {
			t.Fatalf("ReadAt(%d,%d) returned the wrong bytes", tc.off, tc.n)
		}
		v, err := f.View(tc.off, tc.n)
		if err != nil {
			t.Fatalf("View(%d,%d): %v", tc.off, tc.n, err)
		}
		if !bytes.Equal(v.Slice(0, tc.n), want[:tc.n]) {
			t.Fatalf("View(%d,%d) returned the wrong bytes", tc.off, tc.n)
		}
		v.Close()
	}

	// A read past the logical end must never hand back casfs's own tail.
	if n, err := f.ReadAt(make([]byte, 64), size-8); n != 8 || err != io.EOF {
		t.Fatalf("read past the content returned n=%d err=%v, want 8 and EOF", n, err)
	}

	if left := liveUploads(t, s); len(left) != 0 {
		t.Fatalf("upload(s) still open after a clean completion: %v", left)
	}
}
