package tlsconf

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf issues a certificate for dnsNames (and 127.0.0.1) usable for both
// server and client auth, returning PEM cert and key.
func (ca *testCA) leaf(t *testing.T, serial int64, dnsNames ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func write(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// serve starts a TLS server with s's config and returns its URL.
func serve(t *testing.T, s *Server) string {
	t.Helper()
	cfg, err := s.Config()
	if err != nil {
		t.Fatal(err)
	}
	// Not httptest's StartTLS: it adds its own certificate, which a client
	// connecting by IP (no SNI) would get instead of GetCertificate's.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	var h http.Handler = ok
	if s.opts.ClientCAFile != "" {
		h = RequireClientCert(ok, slog.New(slog.DiscardHandler), "/healthz")
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String()
}

func client(ca *testCA, cert *tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	tc := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if cert != nil {
		tc.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: 5 * time.Second}
}

// get fetches u/validate (or u+path), failing unless the answer is 200.
func get(c *http.Client, u string, path ...string) error {
	p := "/validate"
	if len(path) > 0 {
		p = path[0]
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u+p, nil)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func TestMutualTLS(t *testing.T) {
	dir := t.TempDir()
	serverCA, clientCA, otherCA := newCA(t, "server CA"), newCA(t, "step-ca root"), newCA(t, "other")
	sc, sk := serverCA.leaf(t, 2, "bridge.example")
	s, err := New(Options{
		CertFile:       write(t, dir, "s.crt", sc),
		KeyFile:        write(t, dir, "s.key", sk),
		ClientCAFile:   write(t, dir, "client-ca.pem", clientCA.pem),
		ClientDNSNames: []string{"ca.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := serve(t, s)

	pair := func(ca *testCA, names ...string) *tls.Certificate {
		c, k := ca.leaf(t, 3, names...)
		p, err := tls.X509KeyPair(c, k)
		if err != nil {
			t.Fatal(err)
		}
		return &p
	}
	if err := get(client(serverCA, pair(clientCA, "ca.example")), u); err != nil {
		t.Errorf("step-ca's certificate refused: %v", err)
	}
	for name, cert := range map[string]*tls.Certificate{
		"no client certificate": nil,
		"untrusted issuer":      pair(otherCA, "ca.example"),
		"wrong DNS name":        pair(clientCA, "attacker.example"),
	} {
		if err := get(client(serverCA, cert), u); err == nil {
			t.Errorf("%s: request accepted", name)
		}
	}
	// Health probes cannot present a certificate and don't need one.
	if err := get(client(serverCA, nil), u, "/healthz"); err != nil {
		t.Errorf("/healthz without a client certificate: %v", err)
	}
}

func TestDefaultMinVersionIsTLS13(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, "ca")
	c, k := ca.leaf(t, 2)
	s, err := New(Options{CertFile: write(t, dir, "c", c), KeyFile: write(t, dir, "k", k)})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := s.Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x", cfg.MinVersion)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("client auth required without a client CA")
	}
}

func TestReloadOnChange(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, "ca")
	c1, k1 := ca.leaf(t, 10)
	certFile, keyFile := write(t, dir, "c", c1), write(t, dir, "k", k1)
	s, err := New(Options{CertFile: certFile, KeyFile: keyFile, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	first := s.cert.Load().Leaf.SerialNumber

	// A broken pair (new cert, old key) keeps the current certificate.
	c2, k2 := ca.leaf(t, 20)
	write(t, dir, "c", c2)
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(certFile, future, future)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Watch(ctx, 10*time.Millisecond); close(done) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	if got := s.cert.Load().Leaf.SerialNumber; got.Cmp(first) != 0 {
		t.Fatalf("mismatched pair was loaded: serial %v", got)
	}

	// Completing the renewal loads the new certificate.
	write(t, dir, "k", k2)
	_ = os.Chtimes(keyFile, future, future)
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { s.Watch(ctx, 10*time.Millisecond); close(done) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	if got := s.cert.Load().Leaf.SerialNumber; got.Int64() != 20 {
		t.Fatalf("serial = %v, want the renewed certificate (20)", got)
	}
}

func TestBadClientCAFile(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, "ca")
	c, k := ca.leaf(t, 2)
	s, err := New(Options{CertFile: write(t, dir, "c", c), KeyFile: write(t, dir, "k", k), ClientCAFile: write(t, dir, "ca", []byte("nope"))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Config(); err == nil {
		t.Fatal("a client CA file without certificates was accepted")
	}
}
