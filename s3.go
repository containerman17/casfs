package casfs

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// emptySHA256 is the hex sha256 of the empty byte slice, used as the payload
// hash for requests without a body.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// s3 is a minimal path-style S3 client: HEAD, GET (optionally ranged) and PUT,
// signed with AWS Signature Version 4. That is the whole protocol surface casfs
// needs.
type s3 struct {
	endpoint string
	region   string
	bucket   string
	creds    aws.CredentialsProvider
	http     *http.Client
}

func (c *s3) urlFor(key string) (*url.URL, error) {
	u, err := url.Parse(c.endpoint)
	if err != nil {
		return nil, fmt.Errorf("casfs: bad endpoint %q: %w", c.endpoint, err)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + c.bucket + "/" + key
	u.RawQuery = ""
	return u, nil
}

func hmacSHA(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// signingKey derives the SigV4 signing key. Split out so a test can pin it to
// the published AWS test vector.
func signingKey(secret, date, region, service string) []byte {
	k := hmacSHA([]byte("AWS4"+secret), date)
	k = hmacSHA(k, region)
	k = hmacSHA(k, service)
	return hmacSHA(k, "aws4_request")
}

// sign adds the SigV4 headers. Only host, x-amz-content-sha256, x-amz-date and,
// for temporary credentials, x-amz-security-token are signed; Range is
// deliberately left unsigned, which S3 allows. Credentials are retrieved per
// request, so a provider that refreshes (SSO, instance role) is picked up
// without rebuilding the store.
func (c *s3) sign(req *http.Request, payloadHash string, now time.Time) error {
	cr, err := c.creds.Retrieve(req.Context())
	if err != nil {
		return fmt.Errorf("casfs: retrieve credentials: %w", err)
	}
	amzDate := now.UTC().Format("20060102T150405Z")
	date := now.UTC().Format("20060102")
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.Header.Set("X-Amz-Date", amzDate)

	signed := "host;x-amz-content-sha256;x-amz-date"
	canonHeaders := "host:" + req.URL.Host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"
	if cr.SessionToken != "" {
		// A session token is an ordinary signed header, and it sorts last of
		// the four.
		req.Header.Set("X-Amz-Security-Token", cr.SessionToken)
		signed += ";x-amz-security-token"
		canonHeaders += "x-amz-security-token:" + cr.SessionToken + "\n"
	}
	canonReq := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		req.URL.RawQuery,
		canonHeaders,
		signed,
		payloadHash,
	}, "\n")

	scope := date + "/" + c.region + "/s3/aws4_request"
	sum := sha256.Sum256([]byte(canonReq))
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	sig := hex.EncodeToString(hmacSHA(signingKey(cr.SecretAccessKey, date, c.region, "s3"), sts))

	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+cr.AccessKeyID+"/"+scope+
		", SignedHeaders="+signed+", Signature="+sig)
	return nil
}

// httpErr turns a non-2xx response into an error, mapping 404 to fs.ErrNotExist
// so callers can use errors.Is.
func httpErr(op string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("casfs: %s: %w", op, fs.ErrNotExist)
	}
	var e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	_ = xml.Unmarshal(body, &e)
	if e.Code != "" {
		return fmt.Errorf("casfs: %s: %s: %s: %s", op, resp.Status, e.Code, e.Message)
	}
	return fmt.Errorf("casfs: %s: %s: %s", op, resp.Status, strings.TrimSpace(string(body)))
}

func (c *s3) head(key string) (int64, error) {
	u, err := c.urlFor(key)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest(http.MethodHead, u.String(), nil)
	if err != nil {
		return 0, err
	}
	if err := c.sign(req, emptySHA256, time.Now()); err != nil {
		return 0, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("casfs: head %s: %w", key, err)
	}
	if resp.StatusCode/100 != 2 {
		return 0, httpErr("head "+key, resp)
	}
	resp.Body.Close()
	return resp.ContentLength, nil
}

// get fetches [off, off+n) of key. It returns the body and the total object
// size (from Content-Range when the server honoured the range).
func (c *s3) get(key string, off, n int64) (io.ReadCloser, int64, error) {
	u, err := c.urlFor(key)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	if n > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(off, 10)+"-"+strconv.FormatInt(off+n-1, 10))
	}
	if err := c.sign(req, emptySHA256, time.Now()); err != nil {
		return nil, 0, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("casfs: get %s: %w", key, err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, 0, httpErr("get "+key, resp)
	}
	total := resp.ContentLength
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		if i := strings.LastIndex(cr, "/"); i >= 0 {
			if v, err := strconv.ParseInt(strings.TrimSpace(cr[i+1:]), 10, 64); err == nil {
				total = v
			}
		}
	} else if resp.StatusCode == http.StatusOK && off > 0 {
		// Server ignored the range and is streaming from byte zero.
		resp.Body.Close()
		return nil, 0, fmt.Errorf("casfs: get %s: server ignored Range header", key)
	}
	return resp.Body, total, nil
}

// put uploads size bytes from body. payloadHash must be the hex sha256 of those
// bytes; S3 verifies it against the signature.
func (c *s3) put(key string, body io.Reader, size int64, payloadHash string) error {
	u, err := c.urlFor(key)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, u.String(), body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	if err := c.sign(req, payloadHash, time.Now()); err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("casfs: put %s: %w", key, err)
	}
	if resp.StatusCode/100 != 2 {
		return httpErr("put "+key, resp)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	return nil
}

// A single PUT tops out at 5 GiB of object, which a big epoch passes, so
// anything larger goes up in parts. Vars, not consts, so a test can cross the
// threshold with kilobytes instead of gigabytes.
var (
	multipartThreshold int64 = 5 << 30
	partSize           int64 = 128 << 20
)

// putMultipart uploads size bytes from body as a multipart upload: initiate,
// one PUT per part, complete. Each part is buffered whole because SigV4 commits
// to its sha256 in the signature before the body goes out, so peak memory is
// one partSize regardless of the object. Parts are sequential: the bottleneck
// here is a home uplink, not S3.
func (c *s3) putMultipart(key string, body io.Reader, size int64) error {
	u, err := c.urlFor(key)
	if err != nil {
		return err
	}
	// send performs one signed request whose body is fully in memory. RawQuery
	// comes from url.Values.Encode, i.e. sorted and encoded, which is exactly
	// the canonical query string sign() commits to verbatim.
	send := func(method string, q url.Values, payload []byte) (http.Header, []byte, error) {
		ru := *u
		ru.RawQuery = q.Encode()
		req, err := http.NewRequest(method, ru.String(), bytes.NewReader(payload))
		if err != nil {
			return nil, nil, err
		}
		req.ContentLength = int64(len(payload))
		sum := sha256.Sum256(payload)
		if err := c.sign(req, hex.EncodeToString(sum[:]), time.Now()); err != nil {
			return nil, nil, err
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("casfs: %s %s: %w", method, key, err)
		}
		if resp.StatusCode/100 != 2 {
			return nil, nil, httpErr(method+" "+key, resp)
		}
		out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		return resp.Header, out, err
	}

	_, out, err := send(http.MethodPost, url.Values{"uploads": {""}}, nil)
	if err != nil {
		return err
	}
	var initiated struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(out, &initiated); err != nil || initiated.UploadID == "" {
		return fmt.Errorf("casfs: multipart %s: no upload id in %q", key, out)
	}
	// Anything that goes wrong from here leaves parts behind, which a bucket
	// keeps charging for until a lifecycle rule notices. Abort on the way out,
	// best effort, and return the error that actually happened.
	fail := func(err error) error {
		send(http.MethodDelete, url.Values{"uploadId": {initiated.UploadID}}, nil)
		return err
	}

	var parts []completedPart
	buf := make([]byte, partSize)
	for remaining := size; remaining > 0; {
		n := min(partSize, remaining)
		num := len(parts) + 1
		if _, err := io.ReadFull(body, buf[:n]); err != nil {
			return fail(fmt.Errorf("casfs: multipart %s: read part %d: %w", key, num, err))
		}
		h, _, err := send(http.MethodPut, url.Values{
			"partNumber": {strconv.Itoa(num)},
			"uploadId":   {initiated.UploadID},
		}, buf[:n])
		if err != nil {
			return fail(err)
		}
		// The ETag goes back verbatim, quotes included: it is the completion's
		// only proof that this part is the one the bucket stored.
		etag := h.Get("ETag")
		if etag == "" {
			return fail(fmt.Errorf("casfs: multipart %s: part %d came back without an ETag", key, num))
		}
		parts = append(parts, completedPart{PartNumber: num, ETag: etag})
		remaining -= n
	}

	body2, err := xml.Marshal(completeUpload{Parts: parts})
	if err != nil {
		return fail(err)
	}
	_, out, err = send(http.MethodPost, url.Values{"uploadId": {initiated.UploadID}}, body2)
	if err != nil {
		return fail(err)
	}
	// A COMPLETION CAN FAIL WITH 200 OK. S3 holds the connection open while it
	// assembles the object, so the status line is already written by the time
	// anything can go wrong and the failure arrives as an Error body instead.
	var done struct {
		XMLName xml.Name
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if err := xml.Unmarshal(out, &done); err != nil {
		return fail(fmt.Errorf("casfs: multipart %s: complete: unreadable response %q", key, out))
	}
	if done.XMLName.Local == "Error" || done.Code != "" {
		return fail(fmt.Errorf("casfs: multipart %s: complete: %s: %s", key, done.Code, done.Message))
	}
	return nil
}

type completedPart struct {
	PartNumber int
	ETag       string
}

type completeUpload struct {
	XMLName xml.Name        `xml:"CompleteMultipartUpload"`
	Parts   []completedPart `xml:"Part"`
}

func (c *s3) getAll(key string) ([]byte, error) {
	body, _, err := c.get(key, 0, 0)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(body)
}
