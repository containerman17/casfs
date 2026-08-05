package casfs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeS3 is an in-process, single-bucket S3 good enough for PUT, GET, ranged
// GET, HEAD and multipart upload. It also checks that requests carry a
// plausible SigV4 Authorization header, that PUT bodies (whole objects and
// parts alike) match the signed payload hash, and that the query string is in
// canonical form.
type fakeS3 struct {
	*httptest.Server
	bucket string

	mu      sync.Mutex
	objects map[string][]byte
	counts  map[string]int // method -> request count
	puts    []string       // keys stored, in the order they were stored
	uploads map[string][][]byte
	nextID  int
	// failComplete answers CompleteMultipartUpload with an Error body under a
	// 200, which is a thing S3 really does.
	failComplete bool
	// rangeShift offsets every ranged answer, standing in for a bucket that
	// hands back bytes from somewhere other than where they were asked for.
	rangeShift int64
}

func (f *fakeS3) setRangeShift(n int64) {
	f.mu.Lock()
	f.rangeShift = n
	f.mu.Unlock()
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	f := &fakeS3{
		bucket:  "epochs",
		objects: map[string][]byte{},
		counts:  map[string]int{},
		uploads: map[string][][]byte{},
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Server.Close)
	return f
}

func (f *fakeS3) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[method]
}

func (f *fakeS3) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.counts[r.Method]++
	f.mu.Unlock()

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=") ||
		!strings.Contains(auth, "SignedHeaders=host;x-amz-content-sha256;x-amz-date") ||
		!strings.Contains(auth, "Signature=") ||
		r.Header.Get("X-Amz-Date") == "" || r.Header.Get("X-Amz-Content-Sha256") == "" {
		http.Error(w, "<Error><Code>AccessDenied</Code></Error>", http.StatusForbidden)
		return
	}

	prefix := "/" + f.bucket + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, "<Error><Code>NoSuchBucket</Code></Error>", http.StatusNotFound)
		return
	}
	key := r.URL.Path[len(prefix):]

	// A signed request's query string must already be in canonical form, since
	// the signature commits to RawQuery verbatim.
	if r.URL.RawQuery != r.URL.Query().Encode() {
		http.Error(w, "<Error><Code>SignatureDoesNotMatch</Code></Error>", http.StatusForbidden)
		return
	}
	if f.serveMultipart(w, r, key) {
		return
	}

	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "<Error><Code>IncompleteBody</Code></Error>", http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256(body)
		if got, want := hex.EncodeToString(sum[:]), r.Header.Get("X-Amz-Content-Sha256"); got != want {
			http.Error(w, "<Error><Code>XAmzContentSHA256Mismatch</Code></Error>", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.objects[key] = body
		f.puts = append(f.puts, key)
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)

	case http.MethodHead, http.MethodGet:
		f.mu.Lock()
		obj, ok := f.objects[key]
		f.mu.Unlock()
		if !ok {
			http.Error(w, "<Error><Code>NoSuchKey</Code></Error>", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", strconv.Itoa(len(obj)))
			w.WriteHeader(http.StatusOK)
			return
		}
		start, end, ranged := parseRange(r.Header.Get("Range"), int64(len(obj)))
		if !ranged {
			w.Header().Set("Content-Length", strconv.Itoa(len(obj)))
			w.WriteHeader(http.StatusOK)
			w.Write(obj)
			return
		}
		// A bucket that answers from an offset nobody asked for: a caching
		// proxy serving a neighbouring range, or a rewritten key. It reports
		// the range it actually sent, which is the whole point.
		f.mu.Lock()
		shift := f.rangeShift
		f.mu.Unlock()
		start, end = start+shift, end+shift
		if start >= int64(len(obj)) {
			http.Error(w, "<Error><Code>InvalidRange</Code></Error>", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if end >= int64(len(obj)) {
			end = int64(len(obj)) - 1
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(obj)))
		w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(obj[start : end+1])

	default:
		http.Error(w, "<Error><Code>MethodNotAllowed</Code></Error>", http.StatusMethodNotAllowed)
	}
}

// serveMultipart answers initiate / part / complete / abort, and reports
// whether it handled the request at all. Parts are kept per upload id and only
// concatenated at completion, so a half-finished upload stores nothing.
func (f *fakeS3) serveMultipart(w http.ResponseWriter, r *http.Request, key string) bool {
	q := r.URL.Query()
	id := q.Get("uploadId")
	_, initiating := q["uploads"]
	if !initiating && id == "" {
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "<Error><Code>IncompleteBody</Code></Error>", http.StatusBadRequest)
		return true
	}
	sum := sha256.Sum256(body)
	if got, want := hex.EncodeToString(sum[:]), r.Header.Get("X-Amz-Content-Sha256"); got != want {
		http.Error(w, "<Error><Code>XAmzContentSHA256Mismatch</Code></Error>", http.StatusBadRequest)
		return true
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case initiating:
		f.nextID++
		id = fmt.Sprintf("upload-%d-%s", f.nextID, key)
		f.uploads[id] = nil
		fmt.Fprintf(w, "<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>", id)

	case r.Method == http.MethodDelete:
		delete(f.uploads, id)
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPut:
		n, err := strconv.Atoi(q.Get("partNumber"))
		if err != nil || n != len(f.uploads[id])+1 {
			// Sequential by construction here; a gap means a bug worth failing on.
			http.Error(w, "<Error><Code>InvalidPart</Code></Error>", http.StatusBadRequest)
			return true
		}
		f.uploads[id] = append(f.uploads[id], body)
		w.Header().Set("ETag", fmt.Sprintf("%q", hex.EncodeToString(sum[:8])))
		w.WriteHeader(http.StatusOK)

	default: // complete
		parts, ok := f.uploads[id]
		if !ok {
			http.Error(w, "<Error><Code>NoSuchUpload</Code></Error>", http.StatusNotFound)
			return true
		}
		if f.failComplete {
			fmt.Fprint(w, "<Error><Code>InternalError</Code><Message>we encountered an internal error</Message></Error>")
			return true
		}
		var req struct {
			Parts []struct {
				PartNumber int
				ETag       string
			} `xml:"Part"`
		}
		if err := xml.Unmarshal(body, &req); err != nil || len(req.Parts) != len(parts) {
			http.Error(w, "<Error><Code>InvalidPart</Code></Error>", http.StatusBadRequest)
			return true
		}
		var obj []byte
		for i, p := range req.Parts {
			want := fmt.Sprintf("%q", hex.EncodeToString(sha256Of(parts[i])[:8]))
			if p.PartNumber != i+1 || p.ETag != want {
				http.Error(w, "<Error><Code>InvalidPart</Code></Error>", http.StatusBadRequest)
				return true
			}
			obj = append(obj, parts[i]...)
		}
		delete(f.uploads, id)
		f.objects[key] = obj
		f.puts = append(f.puts, key)
		// 200 with a body, which is the shape a failure would arrive in too.
		fmt.Fprintf(w, "<CompleteMultipartUploadResult><ETag>%q</ETag></CompleteMultipartUploadResult>",
			hex.EncodeToString(sha256Of(obj)[:8]))
	}
	return true
}

func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func parseRange(h string, size int64) (start, end int64, ok bool) {
	if !strings.HasPrefix(h, "bytes=") {
		return 0, 0, false
	}
	a, b, found := strings.Cut(strings.TrimPrefix(h, "bytes="), "-")
	if !found {
		return 0, 0, false
	}
	start, err := strconv.ParseInt(a, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	end, err = strconv.ParseInt(b, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	if end >= size {
		end = size - 1
	}
	return start, end, true
}
