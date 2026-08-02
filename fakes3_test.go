package casfs

import (
	"crypto/sha256"
	"encoding/hex"
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
// GET and HEAD. It also checks that requests carry a plausible SigV4
// Authorization header and that PUT bodies match the signed payload hash.
type fakeS3 struct {
	*httptest.Server
	bucket string

	mu      sync.Mutex
	objects map[string][]byte
	counts  map[string]int // method -> request count
	puts    []string       // keys stored, in the order they were stored
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	f := &fakeS3{
		bucket:  "epochs",
		objects: map[string][]byte{},
		counts:  map[string]int{},
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
		if start >= int64(len(obj)) {
			http.Error(w, "<Error><Code>InvalidRange</Code></Error>", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(obj)))
		w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(obj[start : end+1])

	default:
		http.Error(w, "<Error><Code>MethodNotAllowed</Code></Error>", http.StatusMethodNotAllowed)
	}
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
