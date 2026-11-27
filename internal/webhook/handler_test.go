package webhook

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KerckhoffsLabs/scep-intune/internal/intune"
)

type fakeIntune struct {
	validateErr error
	calls       []string
	lastTxn     string
	lastCSR     []byte
}

func (f *fakeIntune) Validate(_ context.Context, txn string, csr []byte) error {
	f.calls = append(f.calls, "validate")
	f.lastTxn, f.lastCSR = txn, csr
	return f.validateErr
}

func (f *fakeIntune) NotifySuccess(_ context.Context, _ string, _ []byte, _ *x509.Certificate) error {
	f.calls = append(f.calls, "success")
	return nil
}

func (f *fakeIntune) NotifyFailure(_ context.Context, _ string, _ []byte, _ int32, _ string) error {
	f.calls = append(f.calls, "failure")
	return nil
}

var (
	validateSecret = bytes.Repeat([]byte{'v'}, 64)
	notifySecret   = bytes.Repeat([]byte{'n'}, 64)
	testNow        = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
)

// newHandler builds a handler with the test secrets and a fixed clock.
func newHandler(t *testing.T, v Validator) http.Handler {
	t.Helper()
	h, err := New(v, Options{
		ValidateSecret: validateSecret,
		NotifySecret:   notifySecret,
		Now:            func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// testCSR is a real DER PKCS#10 request.
var testCSR = func() []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "dev"}}, key)
	if err != nil {
		panic(err)
	}
	return der
}()

// signedWith signs body (with a timestamp added unless it has one) for path.
func signedWith(secret []byte, path string, body map[string]any) *http.Request {
	if _, ok := body["timestamp"]; !ok {
		body["timestamp"] = testNow
	}
	b, _ := json.Marshal(body)
	mac := hmac.New(sha256.New, secret)
	mac.Write(b)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("X-Smallstep-Signature", hex.EncodeToString(mac.Sum(nil)))
	return req
}

// signed signs body with the secret step-ca would use for path.
func signed(path string, body map[string]any) *http.Request {
	secret := validateSecret
	if path == "/notify" {
		secret = notifySecret
	}
	return signedWith(secret, path, body)
}

func do(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestValidateAllow(t *testing.T) {
	fi := &fakeIntune{}
	rec := do(newHandler(t, fi), signed("/validate", map[string]any{
		"x509CertificateRequest": map[string]any{"raw": testCSR},
		"scepTransactionID":      "txn-1",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var resp response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Allow {
		t.Error("allow = false, want true")
	}
	if fi.lastTxn != "txn-1" || !bytes.Equal(fi.lastCSR, testCSR) {
		t.Errorf("txn=%q csr=%q", fi.lastTxn, fi.lastCSR)
	}
}

func TestValidateRejectedDenies(t *testing.T) {
	fi := &fakeIntune{validateErr: fmt.Errorf("%w: ChallengeExpired", intune.ErrRejected)}
	rec := do(newHandler(t, fi), signed("/validate", map[string]any{
		"x509CertificateRequest": map[string]any{"raw": testCSR},
		"scepTransactionID":      "txn-2",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 with allow=false", rec.Code)
	}
	var resp response
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Allow {
		t.Error("allow = true, want false on rejection")
	}
}

func TestValidateTransientErrorIs502(t *testing.T) {
	fi := &fakeIntune{validateErr: fmt.Errorf("intune: returned HTTP 503")}
	rec := do(newHandler(t, fi), signed("/validate", map[string]any{
		"x509CertificateRequest": map[string]any{"raw": testCSR},
		"scepTransactionID":      "txn-3",
	}))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502 on transient error", rec.Code)
	}
}

func TestInvalidSignatureRejected(t *testing.T) {
	fi := &fakeIntune{}
	req := signed("/validate", map[string]any{"scepTransactionID": "x"})
	req.Header.Set("X-Smallstep-Signature", "deadbeef") // tamper
	rec := do(newHandler(t, fi), req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if len(fi.calls) != 0 {
		t.Errorf("intune called despite bad signature: %v", fi.calls)
	}
}

func TestNotifyFailureWhenNoCert(t *testing.T) {
	fi := &fakeIntune{}
	rec := do(newHandler(t, fi), signed("/notify", map[string]any{
		"x509CertificateRequest": map[string]any{"raw": testCSR},
		"scepTransactionID":      "txn-4",
		"scepErrorCode":          5,
		"scepErrorDescription":   "boom",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if got := strings.Join(fi.calls, ","); got != "failure" {
		t.Errorf("calls = %s, want failure", got)
	}
}

// step-ca's SCEP error code is an int; Intune's hResult is an int32. A value
// out of range must not wrap around into an unrelated code.
func TestHResult(t *testing.T) {
	for in, want := range map[int]int32{
		0:                 0,
		2:                 2,
		-2147024809:       -2147024809,
		math.MaxInt32:     math.MaxInt32,
		math.MaxInt32 + 1: hResultFail,
		math.MinInt32 - 1: hResultFail,
	} {
		if got := hResult(in); got != want {
			t.Errorf("hResult(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestNewRefusesWeakSecrets(t *testing.T) {
	for name, opts := range map[string]Options{
		"empty validate": {ValidateSecret: nil, NotifySecret: notifySecret},
		"empty notify":   {ValidateSecret: validateSecret, NotifySecret: []byte{}},
		"short":          {ValidateSecret: validateSecret[:MinSecretBytes-1], NotifySecret: notifySecret},
		"shared":         {ValidateSecret: validateSecret, NotifySecret: validateSecret},
	} {
		if _, err := New(&fakeIntune{}, opts); err == nil {
			t.Errorf("%s: New accepted the secrets", name)
		}
	}
}

// An empty key must never verify, even if a caller bypassed New.
func TestVerifySignatureEmptySecret(t *testing.T) {
	body := []byte(`{}`)
	mac := hmac.New(sha256.New, nil)
	mac.Write(body)
	if verifySignature(nil, body, hex.EncodeToString(mac.Sum(nil))) {
		t.Fatal("signature with an empty key verified")
	}
}

// Each endpoint verifies with its own secret: a request signed for one is
// refused by the other.
func TestCrossEndpointSignatureRejected(t *testing.T) {
	fi := &fakeIntune{}
	h := newHandler(t, fi)
	rec := do(h, signedWith(validateSecret, "/notify", map[string]any{"scepTransactionID": "x"}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	rec = do(h, signedWith(notifySecret, "/validate", map[string]any{
		"x509CertificateRequest": map[string]any{"raw": testCSR}, "scepTransactionID": "x",
	}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if len(fi.calls) != 0 {
		t.Errorf("intune called: %v", fi.calls)
	}
}

func TestStaleOrMissingTimestampRejected(t *testing.T) {
	for name, ts := range map[string]any{
		"too old":    testNow.Add(-DefaultMaxRequestAge - time.Second),
		"in future":  testNow.Add(DefaultMaxRequestAge + time.Second),
		"missing":    nil,
		"zero value": time.Time{},
	} {
		t.Run(name, func(t *testing.T) {
			fi := &fakeIntune{}
			rec := do(newHandler(t, fi), signed("/validate", map[string]any{
				"timestamp":              ts,
				"x509CertificateRequest": map[string]any{"raw": testCSR},
				"scepTransactionID":      "txn",
			}))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("code = %d, want 401", rec.Code)
			}
			if len(fi.calls) != 0 {
				t.Errorf("intune called: %v", fi.calls)
			}
		})
	}
}

func TestTimestampWithinWindowAccepted(t *testing.T) {
	rec := do(newHandler(t, &fakeIntune{}), signed("/validate", map[string]any{
		"timestamp":              testNow.Add(-DefaultMaxRequestAge + time.Second),
		"x509CertificateRequest": map[string]any{"raw": testCSR},
		"scepTransactionID":      "txn",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
}

func TestMethodAndPathRestricted(t *testing.T) {
	h := newHandler(t, &fakeIntune{})
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/validate", http.StatusMethodNotAllowed},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodPost, "/validate/", http.StatusNotFound},
		{http.MethodGet, "/healthz", http.StatusOK},
	} {
		rec := do(h, httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s: missing Cache-Control: no-store", tc.method, tc.path)
		}
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/validate",
		bytes.NewReader(make([]byte, maxBody+1)))
	rec := do(newHandler(t, &fakeIntune{}), req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code = %d, want 413", rec.Code)
	}
}

func TestValidateRequiresParseableCSRAndTransactionID(t *testing.T) {
	for name, body := range map[string]map[string]any{
		"garbage csr":    {"x509CertificateRequest": map[string]any{"raw": []byte("csr")}, "scepTransactionID": "t"},
		"no transaction": {"x509CertificateRequest": map[string]any{"raw": testCSR}},
	} {
		fi := &fakeIntune{}
		rec := do(newHandler(t, fi), signed("/validate", body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code = %d, want 400", name, rec.Code)
		}
		if len(fi.calls) != 0 {
			t.Errorf("%s: intune called: %v", name, fi.calls)
		}
	}
}
