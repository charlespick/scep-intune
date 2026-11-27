// Command scep-intune is a webhook bridge: it lets a vanilla step-ca SCEP
// provisioner validate enrollments against Microsoft Intune and report issuance
// results, via step-ca's SCEPCHALLENGE and NOTIFYING webhooks.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KerckhoffsLabs/scep-intune/internal/config"
	"github.com/KerckhoffsLabs/scep-intune/internal/intune"
	"github.com/KerckhoffsLabs/scep-intune/internal/tlsconf"
	"github.com/KerckhoffsLabs/scep-intune/internal/webhook"
)

// certReloadInterval is how often the TLS certificate files are checked for
// a renewal.
const certReloadInterval = time.Minute

func main() {
	// run returns instead of calling os.Exit, so deferred cleanup (closing the
	// log file) always happens.
	os.Exit(run())
}

func run() int {
	cfgPath := flag.String("config", "config.yaml", "path to YAML config")
	flag.Parse()

	// Bootstrap logger until config (which may redirect logs to a file) loads.
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Load fails on a missing, malformed, short or shared webhook secret: the
	// bridge never starts with requests it cannot authenticate.
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		return 1
	}

	logger, logCloser, err := cfg.Logger()
	if err != nil {
		log.Error("logging setup", "err", err)
		return 1
	}
	if logCloser != nil {
		defer func() { _ = logCloser.Close() }()
	}
	log = logger

	tokens, err := newTokens(cfg, log)
	if err != nil {
		log.Error("entra credential", "auth", cfg.Intune.Auth, "err", err)
		return 1
	}
	logEndpoints(cfg, log)
	client := intune.New(tokens, cfg.Intune.CallerInfo, intune.Endpoints{
		GraphURL:    cfg.Intune.GraphURL,
		ResourceURL: cfg.Intune.ResourceURL,
		AppID:       cfg.Intune.AppID,
	})

	validateKey, notifyKey := cfg.WebhookKeys()
	h, err := webhook.New(client, webhook.Options{
		ValidateSecret: validateKey,
		NotifySecret:   notifyKey,
		MaxRequestAge:  cfg.Webhook.MaxRequestAge,
		Log:            log,
	})
	if err != nil {
		log.Error("webhook handler", "err", err)
		return 1
	}

	// Explicit timeouts bound slow/abusive connections (Slowloris). WriteTimeout
	// is generous because each request fans out to Intune (and, on first call,
	// Graph discovery) before responding.
	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Server.TLS.Enabled {
		minVersion := uint16(tls.VersionTLS13)
		if cfg.Server.TLS.MinVersion == "1.2" {
			minVersion = tls.VersionTLS12
		}
		ts, err := tlsconf.New(tlsconf.Options{
			CertFile:       cfg.Server.TLS.Cert,
			KeyFile:        cfg.Server.TLS.Key,
			MinVersion:     minVersion,
			ClientCAFile:   cfg.Server.TLS.ClientCA,
			ClientDNSNames: cfg.Server.TLS.ClientDNSNames,
			Log:            log,
		})
		if err != nil {
			log.Error("tls", "err", err)
			return 1
		}
		if srv.TLSConfig, err = ts.Config(); err != nil {
			log.Error("tls", "err", err)
			return 1
		}
		go ts.Watch(ctx, certReloadInterval)
		if cfg.Server.TLS.ClientCA != "" {
			srv.Handler = tlsconf.RequireClientCert(h, log, "/healthz")
		} else {
			log.Warn("server.tls.client_ca is not set: any TLS client may connect; " +
				"requests are still authenticated by their HMAC signature")
		}
	} else if !loopback(cfg.Server.Listen) {
		log.Warn("serving plain HTTP on a non-loopback address: webhook bodies carry the device's SCEP challenge; "+
			"terminate TLS in front of the bridge on the same host or pod", "listen", cfg.Server.Listen)
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("starting", "listen", cfg.Server.Listen, "tls", cfg.Server.TLS.Enabled,
			"mtls", cfg.Server.TLS.ClientCA != "", "auth", cfg.Intune.Auth)
		if cfg.Server.TLS.Enabled {
			serveErr <- srv.ListenAndServeTLS("", "") // certificate comes from TLSConfig.GetCertificate
		} else {
			serveErr <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", "err", err)
		}
		return 1
	case <-ctx.Done():
		stop() // restore default signal handling: a second signal force-quits
		log.Info("shutdown signal received, draining in-flight requests")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("graceful shutdown failed", "err", err)
			return 1
		}
		log.Info("shutdown complete")
	}
	return 0
}

// newTokens builds the Entra credential for the configured auth method.
func newTokens(cfg *config.Config, log *slog.Logger) (*intune.EntraTokens, error) {
	if env := os.Getenv("AZURE_AUTHORITY_HOST"); intune.EnvAuthorityConflicts(cfg.Intune.AuthorityHost, env) {
		log.Warn("AZURE_AUTHORITY_HOST is ignored: intune.authority_host (INTUNE_AUTHORITY_HOST) decides the Entra authority",
			"AZURE_AUTHORITY_HOST", env, "authority_host", cfg.Intune.AuthorityHost)
	}
	in := cfg.Intune
	if in.Auth == config.AuthWorkloadIdentity {
		if _, err := os.Stat(in.FederatedTokenFile); err != nil {
			// The kubelet writes the file before the container starts; its
			// absence means the pod was not mutated / the volume is missing.
			return nil, err
		}
		log.Info("using workload identity federation", "client_id", in.ClientID, "tenant_id", in.TenantID,
			"token_file", in.FederatedTokenFile)
		return intune.NewWorkloadIdentityTokens(in.TenantID, in.ClientID, in.FederatedTokenFile, in.AuthorityHost)
	}
	return intune.NewEntraTokens(in.TenantID, in.ClientID, in.ClientSecret, in.AuthorityHost)
}

// logEndpoints logs the effective Microsoft endpoints whenever any differs
// from its default: as a warning when the Entra authority is not Microsoft's,
// since the bridge's credential is presented there.
func logEndpoints(cfg *config.Config, log *slog.Logger) {
	in := cfg.Intune
	if in.AuthorityHost == config.DefaultAuthorityHost && in.GraphURL == config.DefaultGraphURL &&
		in.ResourceURL == config.DefaultResourceURL && in.AppID == config.DefaultAppID {
		return
	}
	level := slog.LevelInfo
	msg := "using non-default Microsoft endpoints"
	if !intune.KnownMicrosoftAuthority(in.AuthorityHost) {
		level = slog.LevelWarn
		msg = "using non-default Microsoft endpoints: the Entra credential is sent to a host that is not a Microsoft authority"
	}
	log.Log(context.Background(), level, msg,
		"authority_host", in.AuthorityHost, "graph_url", in.GraphURL,
		"resource_url", in.ResourceURL, "app_id", in.AppID)
}

// loopback reports whether a listen address binds only a loopback interface.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
