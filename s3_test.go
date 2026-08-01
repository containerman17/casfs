package casfs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// TestSignMatchesAWSSigner pins the hand-rolled signer to the SDK's own SigV4
// implementation, with and without a session token. That is the whole reason
// temporary credentials (SSO, instance roles) work: the token is an ordinary
// signed header, and dropping it from SignedHeaders is an invalid signature,
// not a missing feature.
func TestSignMatchesAWSSigner(t *testing.T) {
	now := time.Date(2026, 8, 1, 4, 5, 6, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		token  string
		signed string
	}{
		{"static", "", "host;x-amz-content-sha256;x-amz-date"},
		{"temporary", "FwoGZXIvYXdzEBcaDG", "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cr := aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI", SessionToken: tc.token}
			c := &s3{
				endpoint: "https://s3.ap-northeast-1.amazonaws.com",
				region:   "ap-northeast-1",
				bucket:   "bucket",
				creds:    credentials.StaticCredentialsProvider{Value: cr},
			}
			u, err := c.urlFor("epochdb-smoke/abc")
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodGet, u.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.sign(req, emptySHA256, now); err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Get("X-Amz-Security-Token"); got != tc.token {
				t.Fatalf("X-Amz-Security-Token = %q, want %q", got, tc.token)
			}
			if got := req.Header.Get("Authorization"); !strings.Contains(got, "SignedHeaders="+tc.signed+",") {
				t.Fatalf("SignedHeaders in %q, want %s", got, tc.signed)
			}

			// Same request, signed by the SDK. Both signatures must be equal
			// byte for byte, so this is a spec check and not a self-check.
			ref, err := http.NewRequest(http.MethodGet, u.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			ref.Header.Set("X-Amz-Content-Sha256", emptySHA256)
			if err := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true }).
				SignHTTP(context.Background(), cr, ref, emptySHA256, "s3", c.region, now); err != nil {
				t.Fatal(err)
			}
			if got, want := req.Header.Get("Authorization"), ref.Header.Get("Authorization"); got != want {
				t.Fatalf("Authorization\n got %s\nwant %s", got, want)
			}
		})
	}
}

// rotatingCreds hands out a different access key on every Retrieve, standing in
// for a provider whose temporary credentials expire mid-run.
type rotatingCreds struct{ n int }

func (r *rotatingCreds) Retrieve(context.Context) (aws.Credentials, error) {
	r.n++
	return aws.Credentials{
		AccessKeyID:     "AKID" + strconv.Itoa(r.n),
		SecretAccessKey: "secret" + strconv.Itoa(r.n),
		SessionToken:    "token" + strconv.Itoa(r.n),
	}, nil
}

// TestCredentialsRetrievedPerRequest proves the store does not latch the keys
// it started with: a refreshed credential is used by the very next request.
func TestCredentialsRetrievedPerRequest(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		cred := strings.TrimPrefix(auth[strings.Index(auth, "Credential=")+len("Credential="):], "")
		seen = append(seen, strings.SplitN(cred, "/", 2)[0]+" "+r.Header.Get("X-Amz-Security-Token"))
		w.Header().Set("Content-Length", "0")
	}))
	defer srv.Close()

	c := &s3{endpoint: srv.URL, region: "auto", bucket: "b", creds: &rotatingCreds{}, http: srv.Client()}
	for i := 0; i < 2; i++ {
		if _, err := c.head("k"); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"AKID1 token1", "AKID2 token2"}
	if len(seen) != len(want) || seen[0] != want[0] || seen[1] != want[1] {
		t.Fatalf("credentials seen by the server = %v, want %v", seen, want)
	}
}
