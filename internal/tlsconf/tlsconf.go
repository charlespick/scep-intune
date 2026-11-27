// Package tlsconf builds the bridge's HTTPS server configuration: a minimum
// protocol version, an optional client-certificate requirement (mutual TLS
// with step-ca), and a serving certificate that is reloaded from disk when it
// changes, so short-lived certificates (step-ca issues 24h ones by default)
// can be renewed in place without a restart.
package tlsconf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// Options configure the server TLS settings.
type Options struct {
	CertFile, KeyFile string
	// MinVersion is tls.VersionTLS12 or tls.VersionTLS13 (default).
	MinVersion uint16
	// ClientCAFile, when set, requires every client to present a certificate
	// that chains to a CA in this PEM bundle.
	ClientCAFile string
	// ClientDNSNames, when set, requires the verified client certificate to
	// carry at least one of these DNS SANs.
	ClientDNSNames []string
	Log            *slog.Logger
}

// Server holds a server tls.Config and the reloadable serving certificate.
type Server struct {
	opts Options
	cert atomic.Pointer[tls.Certificate]
	// modTimes of the cert and key at the last successful load.
	certMod, keyMod time.Time
}

// New loads the serving certificate (and the client CA bundle, if any) and
// returns the server state. Call Config for the tls.Config and Watch to
// reload the certificate when its files change.
func New(opts Options) (*Server, error) {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.MinVersion == 0 {
		opts.MinVersion = tls.VersionTLS13
	}
	if opts.MinVersion != tls.VersionTLS12 && opts.MinVersion != tls.VersionTLS13 {
		return nil, errors.New("tlsconf: MinVersion must be TLS 1.2 or TLS 1.3")
	}
	s := &Server{opts: opts}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Config returns the tls.Config for an http.Server.
func (s *Server) Config() (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: s.opts.MinVersion,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.cert.Load(), nil
		},
	}
	if s.opts.ClientCAFile == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(s.opts.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("tlsconf: client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tlsconf: client CA %s holds no PEM certificates", s.opts.ClientCAFile)
	}
	cfg.ClientCAs = pool
	// A presented certificate must verify; whether one is required at all is
	// decided per route by RequireClientCert, so that health probes (which
	// cannot present one) still work.
	cfg.ClientAuth = tls.VerifyClientCertIfGiven
	if names := s.opts.ClientDNSNames; len(names) > 0 {
		// VerifyConnection runs on every handshake, resumed ones included.
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return nil // no certificate: RequireClientCert refuses the request
			}
			if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
				return errors.New("tlsconf: no verified client certificate")
			}
			leaf := cs.VerifiedChains[0][0]
			for _, n := range leaf.DNSNames {
				if slices.ContainsFunc(names, func(want string) bool { return strings.EqualFold(n, want) }) {
					return nil
				}
			}
			return fmt.Errorf("tlsconf: client certificate %q has none of the allowed DNS names", leaf.Subject.CommonName)
		}
	}
	return cfg, nil
}

func (s *Server) load() error {
	certInfo, err := os.Stat(s.opts.CertFile)
	if err != nil {
		return fmt.Errorf("tlsconf: %w", err)
	}
	keyInfo, err := os.Stat(s.opts.KeyFile)
	if err != nil {
		return fmt.Errorf("tlsconf: %w", err)
	}
	pair, err := tls.LoadX509KeyPair(s.opts.CertFile, s.opts.KeyFile)
	if err != nil {
		return fmt.Errorf("tlsconf: %w", err)
	}
	if pair.Leaf != nil && time.Now().After(pair.Leaf.NotAfter) {
		return fmt.Errorf("tlsconf: certificate %s expired at %s", s.opts.CertFile, pair.Leaf.NotAfter.UTC())
	}
	s.cert.Store(&pair)
	s.certMod, s.keyMod = certInfo.ModTime(), keyInfo.ModTime()
	if pair.Leaf != nil {
		s.opts.Log.Info("tls certificate loaded", "subject", pair.Leaf.Subject.String(), "notAfter", pair.Leaf.NotAfter.UTC())
	}
	return nil
}

// changed reports whether the cert or key file's modification time differs
// from the last successful load.
func (s *Server) changed() bool {
	c, err1 := os.Stat(s.opts.CertFile)
	k, err2 := os.Stat(s.opts.KeyFile)
	if err1 != nil || err2 != nil {
		return false // keep serving the loaded pair; the next poll retries
	}
	return !c.ModTime().Equal(s.certMod) || !k.ModTime().Equal(s.keyMod)
}

// Watch polls the certificate and key files every interval until ctx ends,
// reloading them when either changes. A pair that fails to load (for example
// a half-written renewal, or a mismatched key) is logged and the previous
// certificate stays in use. Once the certificate is in the last tenth of its
// lifetime without having been renewed, every poll logs a warning.
func (s *Server) Watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if s.changed() {
			if err := s.load(); err != nil {
				s.opts.Log.Error("tls certificate reload failed, keeping the current one", "err", err)
			}
		}
		if leaf := s.cert.Load().Leaf; leaf != nil {
			if left := time.Until(leaf.NotAfter); left < 0 {
				s.opts.Log.Error("tls certificate has expired", "notAfter", leaf.NotAfter.UTC())
			} else if lifetime := leaf.NotAfter.Sub(leaf.NotBefore); left < lifetime/10 {
				s.opts.Log.Warn("tls certificate is close to expiry and has not been renewed", "notAfter", leaf.NotAfter.UTC())
			}
		}
	}
}

// RequireClientCert wraps next so that every request, except to the exempt
// paths, must arrive over TLS with a client certificate verified against the
// configured client CA (and DNS names). Others get 403 without reaching next.
func RequireClientCert(next http.Handler, log *slog.Logger, exempt ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slices.Contains(exempt, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			log.Warn("request without a verified client certificate", "remote", r.RemoteAddr, "path", r.URL.Path)
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
