package casfs

import (
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
	ak, sk   string
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

// sign adds the SigV4 headers. Only host, x-amz-content-sha256 and x-amz-date
// are signed; Range is deliberately left unsigned, which S3 allows.
func (c *s3) sign(req *http.Request, payloadHash string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	date := now.UTC().Format("20060102")
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.Header.Set("X-Amz-Date", amzDate)

	const signed = "host;x-amz-content-sha256;x-amz-date"
	canonHeaders := "host:" + req.URL.Host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"
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
	sig := hex.EncodeToString(hmacSHA(signingKey(c.sk, date, c.region, "s3"), sts))

	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.ak+"/"+scope+
		", SignedHeaders="+signed+", Signature="+sig)
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
	c.sign(req, emptySHA256, time.Now())
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
	c.sign(req, emptySHA256, time.Now())
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
	c.sign(req, payloadHash, time.Now())
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

func (c *s3) getAll(key string) ([]byte, error) {
	body, _, err := c.get(key, 0, 0)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(body)
}
