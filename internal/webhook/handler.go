// Package webhook implements the HTTP bridge that lets a vanilla step-ca
// SCEP provisioner validate enrollments against Microsoft Intune and report
// issuance results, using step-ca's webhook extension point.
//
// step-ca is configured with two webhooks on the SCEP provisioner:
//
//	SCEPCHALLENGE -> POST /validate  (validate the dynamic challenge with Intune)
//	NOTIFYING     -> POST /notify    (report issuance success/failure to Intune)
//
// Each request carries step-ca's webhook payload and an HMAC-SHA256 signature in
// X-Smallstep-Signature; the handler verifies it, then calls the Intune client.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/KerckhoffsLabs/scep-intune/internal/intune"
)

// maxBody caps a webhook request body. step-ca webhook payloads are small.
const maxBody = 1 << 20

// MinSecretBytes is the shortest HMAC key New accepts. step-ca generates 64
// random bytes per webhook.
const MinSecretBytes = 32

// DefaultMaxRequestAge is used when Options.MaxRequestAge is zero.
const DefaultMaxRequestAge = 5 * time.Minute

// Validator is the Intune-facing behavior the handler needs. *intune.Client
// satisfies it.
type Validator interface {
	Validate(ctx context.Context, txnID string, csrDER []byte) error
	NotifySuccess(ctx context.Context, txnID string, csrDER []byte, cert *x509.Certificate) error
	NotifyFailure(ctx context.Context, txnID string, csrDER []byte, hResult int32, desc string) error
}

// request is the subset of step-ca's webhook.RequestBody this bridge consumes.
type request struct {
	// Timestamp is set by step-ca when it signs the request; it is covered by
	// the signature, so it bounds how long a captured request can be replayed.
	Timestamp              time.Time `json:"timestamp"`
	X509CertificateRequest *rawCert  `json:"x509CertificateRequest"`
	X509Certificate        *rawCert  `json:"x509Certificate"`
	SCEPTransactionID      string    `json:"scepTransactionID"`
	SCEPErrorCode          int       `json:"scepErrorCode"`
	SCEPErrorDescription   string    `json:"scepErrorDescription"`
}

// rawCert holds the DER bytes step-ca includes for a CSR or certificate.
type rawCert struct {
	Raw []byte `json:"raw"`
}

// response is step-ca's webhook.ResponseBody (the fields this bridge sets).
type response struct {
	Allow bool `json:"allow"`
}

// Options configure the handler.
type Options struct {
	// ValidateSecret and NotifySecret are the raw (decoded) HMAC keys for the
	// SCEPCHALLENGE and NOTIFYING webhooks respectively. step-ca generates a
	// distinct secret per webhook, so each endpoint is verified with its own.
	// Both are required and must be at least MinSecretBytes long.
	ValidateSecret, NotifySecret []byte
	// MaxRequestAge bounds the difference between step-ca's signed request
	// timestamp and the local clock, in either direction. Default 5m.
	MaxRequestAge time.Duration
	// Log receives request logs; default slog.Default().
	Log *slog.Logger
	// Now returns the current time; default time.Now. For tests.
	Now func() time.Time
}

type handler struct {
	intune         Validator
	validateSecret []byte
	notifySecret   []byte
	maxAge         time.Duration
	now            func() time.Time
	log            *slog.Logger
}

// New returns an http.Handler serving POST /validate, POST /notify and
// GET /healthz. It refuses to build a handler whose secrets would not
// authenticate requests: an empty or short HMAC key, or one key shared by both
// endpoints.
func New(v Validator, opts Options) (http.Handler, error) {
	for name, k := range map[string][]byte{"validate": opts.ValidateSecret, "notify": opts.NotifySecret} {
		if len(k) < MinSecretBytes {
			return nil, fmt.Errorf("webhook: %s secret is %d bytes, at least %d are required", name, len(k), MinSecretBytes)
		}
	}
	if hmac.Equal(opts.ValidateSecret, opts.NotifySecret) {
		return nil, errors.New("webhook: the validate and notify secrets must differ")
	}
	h := &handler{
		intune:         v,
		validateSecret: opts.ValidateSecret,
		notifySecret:   opts.NotifySecret,
		maxAge:         opts.MaxRequestAge,
		now:            opts.Now,
		log:            opts.Log,
	}
	if h.maxAge <= 0 {
		h.maxAge = DefaultMaxRequestAge
	}
	if h.now == nil {
		h.now = time.Now
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /validate", h.handleValidate)
	mux.HandleFunc("POST /notify", h.handleNotify)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return securityHeaders(mux), nil
}

// securityHeaders marks every response as uncacheable and not to be sniffed.
// Responses carry issuance decisions; no intermediary should store them.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// handleValidate bridges a SCEPCHALLENGE webhook to Intune challenge validation.
func (h *handler) handleValidate(w http.ResponseWriter, r *http.Request) {
	req, ok := h.read(w, r, h.validateSecret)
	if !ok {
		return
	}
	if req.X509CertificateRequest == nil || len(req.X509CertificateRequest.Raw) == 0 {
		http.Error(w, "missing certificate request", http.StatusBadRequest)
		return
	}
	// The CSR must at least parse: Intune matches its challenge against it,
	// and step-ca will sign what it describes.
	if _, err := x509.ParseCertificateRequest(req.X509CertificateRequest.Raw); err != nil {
		h.log.Warn("unparseable certificate request", "transactionID", req.SCEPTransactionID, "err", err)
		http.Error(w, "invalid certificate request", http.StatusBadRequest)
		return
	}
	err := h.intune.Validate(r.Context(), req.SCEPTransactionID, req.X509CertificateRequest.Raw)
	switch {
	case err == nil:
		h.log.Info("intune validated challenge", "transactionID", req.SCEPTransactionID)
		writeAllow(w, true)
	case errors.Is(err, intune.ErrRejected):
		// Definitive rejection (bad/expired challenge): tell step-ca to deny.
		h.log.Warn("intune rejected challenge", "transactionID", req.SCEPTransactionID, "err", err)
		writeAllow(w, false)
	default:
		// Transient/transport failure: 5xx so step-ca fails the request and the
		// device retries, rather than treating it as a permanent rejection.
		h.log.Error("intune validate error", "transactionID", req.SCEPTransactionID, "err", err)
		http.Error(w, "intune upstream error", http.StatusBadGateway)
	}
}

// handleNotify bridges a NOTIFYING webhook to Intune success/failure reporting.
// A request carrying an issued certificate is a success; otherwise it's a failure.
func (h *handler) handleNotify(w http.ResponseWriter, r *http.Request) {
	req, ok := h.read(w, r, h.notifySecret)
	if !ok {
		return
	}
	var csrDER []byte
	if req.X509CertificateRequest != nil {
		csrDER = req.X509CertificateRequest.Raw
	}

	var err error
	if req.X509Certificate != nil && len(req.X509Certificate.Raw) > 0 {
		var cert *x509.Certificate
		if cert, err = x509.ParseCertificate(req.X509Certificate.Raw); err != nil {
			http.Error(w, "invalid certificate", http.StatusBadRequest)
			return
		}
		err = h.intune.NotifySuccess(r.Context(), req.SCEPTransactionID, csrDER, cert)
	} else {
		err = h.intune.NotifyFailure(r.Context(), req.SCEPTransactionID, csrDER, hResult(req.SCEPErrorCode), req.SCEPErrorDescription)
	}
	if err != nil {
		h.log.Error("intune notify error", "transactionID", req.SCEPTransactionID, "err", err)
		http.Error(w, "intune upstream error", http.StatusBadGateway)
		return
	}
	h.log.Info("intune notified", "transactionID", req.SCEPTransactionID,
		"success", req.X509Certificate != nil && len(req.X509Certificate.Raw) > 0)
	writeAllow(w, true)
}

// read verifies the step-ca webhook signature and the request's freshness,
// and decodes the body. It writes the error response and returns ok=false on
// any failure. Nothing from the body is trusted, or logged, before the
// signature has been verified.
func (h *handler) read(w http.ResponseWriter, r *http.Request, secret []byte) (*request, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return nil, false
		}
		http.Error(w, "read error", http.StatusBadRequest)
		return nil, false
	}
	if !verifySignature(secret, body, r.Header.Get("X-Smallstep-Signature")) {
		h.log.Warn("invalid webhook signature", "remote", r.RemoteAddr, "path", r.URL.Path)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return nil, false
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return nil, false
	}
	// The signature covers the timestamp, so an old request replayed verbatim
	// is refused here. step-ca's one retry re-sends the same body a second
	// later, well inside the window.
	if age := h.now().Sub(req.Timestamp); req.Timestamp.IsZero() || age > h.maxAge || age < -h.maxAge {
		h.log.Warn("stale or missing webhook timestamp", "remote", r.RemoteAddr, "path", r.URL.Path,
			"timestamp", req.Timestamp, "maxAge", h.maxAge)
		http.Error(w, "stale request", http.StatusUnauthorized)
		return nil, false
	}
	if req.SCEPTransactionID == "" {
		http.Error(w, "missing scepTransactionID", http.StatusBadRequest)
		return nil, false
	}
	h.log.Info("webhook request", "path", r.URL.Path, "transactionID", req.SCEPTransactionID,
		"webhookID", r.Header.Get("X-Smallstep-Webhook-ID"), "requestID", r.Header.Get("X-Request-Id"))
	return &req, true
}

// verifySignature checks step-ca's X-Smallstep-Signature: hex(HMAC-SHA256(secret, body)).
// An empty secret never verifies: HMAC with an empty key is computable by anyone.
func verifySignature(secret, body []byte, sigHex string) bool {
	if len(secret) == 0 {
		return false
	}
	got, err := hex.DecodeString(sigHex)
	if err != nil || len(got) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), got)
}

func writeAllow(w http.ResponseWriter, allow bool) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response{Allow: allow})
}

// hResultFail is E_FAIL (0x80004005), reported when step-ca's error code
// doesn't fit Intune's 32-bit hResult.
const hResultFail int32 = -2147467259

// hResult converts step-ca's SCEP error code to Intune's int32 hResult without
// wrapping an out-of-range value into an unrelated code.
func hResult(code int) int32 {
	if code < math.MinInt32 || code > math.MaxInt32 {
		return hResultFail
	}
	return int32(code)
}
