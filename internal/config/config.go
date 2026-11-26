// Package config defines the webhook-bridge configuration and its validation.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Logging configures where and how the server emits logs.
type Logging struct {
	// Output is "stdout", "stderr", or a file path. A file is opened for
	// append and created if absent.
	Output string `yaml:"output"`
	// Format is "json" (default) or "text".
	Format string `yaml:"format"`
	// Level is "debug", "info" (default), "warn", or "error".
	Level string `yaml:"level"`
}

// TLS configures the optional HTTPS listener.
type TLS struct {
	Enabled bool   `yaml:"enabled"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
	// ClientCA is a PEM bundle of the CA(s) that issue step-ca's own TLS
	// certificate (normally the step-ca root). When set, every connection must
	// present a client certificate chaining to it (mutual TLS). step-ca sends
	// its TLS certificate to webhook servers unless the webhook was created
	// with --disable-tls-client-auth.
	ClientCA string `yaml:"client_ca"`
	// ClientDNSNames, when set, additionally requires the client certificate
	// to carry at least one of these DNS SANs (step-ca's "dnsNames").
	ClientDNSNames []string `yaml:"client_dns_names"`
	// MinVersion is "1.3" (default) or "1.2". step-ca is a Go client and
	// always negotiates TLS 1.3; lower it only for a TLS-terminating proxy
	// that cannot.
	MinVersion string `yaml:"min_version"`
}

// Server configures the HTTP(S) listener.
type Server struct {
	Listen string `yaml:"listen"`
	TLS    TLS    `yaml:"tls"`
}

// Webhook holds the secrets used to verify step-ca's signed webhook requests
// (X-Smallstep-Signature). step-ca generates a distinct secret per webhook,
// so the SCEPCHALLENGE (/validate) and NOTIFYING (/notify) endpoints each
// have their own.
type Webhook struct {
	// base64 HMAC-SHA256 keys. Prefer the *_file variants or the env vars
	// SCEP_VALIDATE_SECRET(_FILE) / SCEP_NOTIFY_SECRET(_FILE).
	ValidateSecret     string `yaml:"validate_secret"`
	ValidateSecretFile string `yaml:"validate_secret_file"`
	NotifySecret       string `yaml:"notify_secret"`
	NotifySecretFile   string `yaml:"notify_secret_file"`
	// MaxRequestAge bounds how far step-ca's signed request timestamp may be
	// from the bridge's clock, in either direction, limiting the replay window
	// of a captured request. Default 5m.
	MaxRequestAge time.Duration `yaml:"max_request_age"`

	validateKey, notifyKey []byte
}

// Intune authentication methods (intune.auth).
const (
	// AuthClientSecret authenticates with an Entra app client secret.
	AuthClientSecret = "client_secret"
	// AuthWorkloadIdentity exchanges a Kubernetes service account token (or
	// any OIDC token in a file) for an Entra token via a federated identity
	// credential: no long-lived secret is stored.
	AuthWorkloadIdentity = "workload_identity"
)

// Intune configures the Entra identity and the Microsoft endpoints.
type Intune struct {
	// Auth is "client_secret" (default) or "workload_identity".
	Auth string `yaml:"auth"`

	TenantID         string `yaml:"tenant_id"`
	ClientID         string `yaml:"client_id"`
	ClientSecret     string `yaml:"client_secret"`
	ClientSecretFile string `yaml:"client_secret_file"`
	// FederatedTokenFile is the projected service account token used with
	// auth: workload_identity. Defaults to AZURE_FEDERATED_TOKEN_FILE, which
	// the Azure workload identity webhook sets.
	FederatedTokenFile string `yaml:"federated_token_file"`
	CallerInfo         string `yaml:"caller_info"`

	// Microsoft endpoints, mirroring the values Microsoft's reference SCEP
	// validation library makes configurable. The defaults target the
	// commercial cloud; override them for another Microsoft cloud or a mock.
	AuthorityHost string `yaml:"authority_host"` // Entra sign-in host
	GraphURL      string `yaml:"graph_url"`      // Graph base URL and scope base
	ResourceURL   string `yaml:"resource_url"`   // Intune token scope base
	AppID         string `yaml:"app_id"`         // Intune service principal app ID
}

// Config is the bridge configuration, loaded from YAML with env overrides.
type Config struct {
	Server  Server  `yaml:"server"`
	Webhook Webhook `yaml:"webhook"`
	Logging Logging `yaml:"logging"`
	Intune  Intune  `yaml:"intune"`
}

// Default Microsoft endpoints (commercial cloud).
const (
	DefaultAuthorityHost = "https://login.microsoftonline.com/"
	DefaultGraphURL      = "https://graph.microsoft.com/"
	DefaultResourceURL   = "https://api.manage.microsoft.com/"
	DefaultAppID         = "0000000a-0000-0000-c000-000000000000"
)

// MinSecretBytes is the minimum decoded length of a webhook secret. step-ca
// generates 64 random bytes per webhook; anything shorter than 256 bits was
// not produced by step-ca and is too weak for an HMAC key guarding issuance.
const MinSecretBytes = 32

// DefaultMaxRequestAge is the default webhook.max_request_age.
const DefaultMaxRequestAge = 5 * time.Minute

// maxSecretFileBytes caps a secret file read: secrets are a few hundred bytes.
const maxSecretFileBytes = 64 << 10

// Load reads and validates a YAML config file, applying defaults and env
// overrides. Unknown keys are an error, so a misspelt setting (for example a
// secret's key) cannot be silently ignored.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the path is the operator's own -config flag
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.applyEnv()
	cfg.applyDefaults()
	if err := cfg.resolveSecretFiles(); err != nil {
		return nil, err
	}
	cfg.normaliseEndpoints()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = ":8080"
	}
	if c.Intune.CallerInfo == "" {
		c.Intune.CallerInfo = "step-ca-scep"
	}
	if c.Logging.Output == "" {
		c.Logging.Output = "stdout"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Server.TLS.MinVersion == "" {
		c.Server.TLS.MinVersion = "1.3"
	}
	if c.Webhook.MaxRequestAge == 0 {
		c.Webhook.MaxRequestAge = DefaultMaxRequestAge
	}
	if c.Intune.Auth == "" {
		c.Intune.Auth = AuthClientSecret
	}
	if c.Intune.AuthorityHost == "" {
		c.Intune.AuthorityHost = DefaultAuthorityHost
	}
	if c.Intune.GraphURL == "" {
		c.Intune.GraphURL = DefaultGraphURL
	}
	if c.Intune.ResourceURL == "" {
		c.Intune.ResourceURL = DefaultResourceURL
	}
	if c.Intune.AppID == "" {
		c.Intune.AppID = DefaultAppID
	}
	// The Azure workload identity webhook injects these into the pod; use them
	// when the bridge's own settings leave the values unset.
	if c.Intune.Auth == AuthWorkloadIdentity {
		for _, d := range []struct {
			dst *string
			env string
		}{
			{&c.Intune.TenantID, "AZURE_TENANT_ID"},
			{&c.Intune.ClientID, "AZURE_CLIENT_ID"},
			{&c.Intune.FederatedTokenFile, "AZURE_FEDERATED_TOKEN_FILE"},
		} {
			if *d.dst == "" {
				*d.dst = os.Getenv(d.env)
			}
		}
	}
}

// normaliseEndpoints lower-cases each endpoint URL's scheme and host (both are
// case-insensitive) and makes it end with exactly one slash, so derived values
// ("<url>.default", "<url>v1.0/...") and comparisons with the defaults are
// correct however the URL was written. Values that don't parse as absolute URLs
// are left for Validate to reject.
func (c *Config) normaliseEndpoints() {
	for _, p := range []*string{&c.Intune.AuthorityHost, &c.Intune.GraphURL, &c.Intune.ResourceURL} {
		if u, err := url.Parse(*p); err == nil && u.Scheme != "" && u.Host != "" {
			u.Scheme = strings.ToLower(u.Scheme)
			u.Host = strings.ToLower(u.Host)
			*p = u.String()
		}
		*p = strings.TrimRight(*p, "/") + "/"
	}
}

// envOverrides maps each environment variable to the field it overrides. A
// variable overrides the file only when it is non-empty.
func (c *Config) envOverrides() []struct {
	env string
	dst *string
} {
	return []struct {
		env string
		dst *string
	}{
		{"INTUNE_AUTH", &c.Intune.Auth},
		{"INTUNE_TENANT_ID", &c.Intune.TenantID},
		{"INTUNE_CLIENT_ID", &c.Intune.ClientID},
		{"INTUNE_CLIENT_SECRET", &c.Intune.ClientSecret},
		{"INTUNE_CLIENT_SECRET_FILE", &c.Intune.ClientSecretFile},
		{"INTUNE_FEDERATED_TOKEN_FILE", &c.Intune.FederatedTokenFile},
		{"SCEP_VALIDATE_SECRET", &c.Webhook.ValidateSecret},
		{"SCEP_VALIDATE_SECRET_FILE", &c.Webhook.ValidateSecretFile},
		{"SCEP_NOTIFY_SECRET", &c.Webhook.NotifySecret},
		{"SCEP_NOTIFY_SECRET_FILE", &c.Webhook.NotifySecretFile},
		{"INTUNE_AUTHORITY_HOST", &c.Intune.AuthorityHost},
		{"INTUNE_GRAPH_URL", &c.Intune.GraphURL},
		{"INTUNE_RESOURCE_URL", &c.Intune.ResourceURL},
		{"INTUNE_APP_ID", &c.Intune.AppID},
	}
}

func (c *Config) applyEnv() {
	for _, o := range c.envOverrides() {
		if v := os.Getenv(o.env); v != "" {
			*o.dst = v
		}
	}
}

// resolveSecretFiles reads each secret given as a file (for example a mounted
// Kubernetes Secret or a Secrets Store CSI volume). A secret set both inline
// and as a file is ambiguous and refused. Surrounding whitespace, such as the
// trailing newline most tools write, is trimmed.
func (c *Config) resolveSecretFiles() error {
	for _, s := range []struct {
		key        string
		value      *string
		file       string
		envs, envf string
	}{
		{"webhook.validate_secret", &c.Webhook.ValidateSecret, c.Webhook.ValidateSecretFile, "SCEP_VALIDATE_SECRET", "SCEP_VALIDATE_SECRET_FILE"},
		{"webhook.notify_secret", &c.Webhook.NotifySecret, c.Webhook.NotifySecretFile, "SCEP_NOTIFY_SECRET", "SCEP_NOTIFY_SECRET_FILE"},
		{"intune.client_secret", &c.Intune.ClientSecret, c.Intune.ClientSecretFile, "INTUNE_CLIENT_SECRET", "INTUNE_CLIENT_SECRET_FILE"},
	} {
		if s.file == "" {
			continue
		}
		if *s.value != "" {
			return fmt.Errorf("config: %s is set both inline (%s or env %s) and as a file (%s_file or env %s); set one",
				s.key, s.key, s.envs, s.key, s.envf)
		}
		v, err := readSecretFile(s.file)
		if err != nil {
			return fmt.Errorf("config: %s_file: %w", s.key, err)
		}
		*s.value = v
	}
	return nil
}

func readSecretFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: operator-supplied secret path
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxSecretFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxSecretFileBytes {
		return "", fmt.Errorf("%s is larger than %d bytes", path, maxSecretFileBytes)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return v, nil
}

// Validate returns an error describing the first class of problem found:
// missing required fields (all listed), then invalid values.
func (c *Config) Validate() error {
	var missing []string
	req := []struct{ name, val string }{
		{"webhook.validate_secret", c.Webhook.ValidateSecret},
		{"webhook.notify_secret", c.Webhook.NotifySecret},
		{"intune.tenant_id", c.Intune.TenantID},
		{"intune.client_id", c.Intune.ClientID},
	}
	switch c.Intune.Auth {
	case AuthClientSecret:
		req = append(req, struct{ name, val string }{"intune.client_secret", c.Intune.ClientSecret})
	case AuthWorkloadIdentity:
		req = append(req, struct{ name, val string }{"intune.federated_token_file", c.Intune.FederatedTokenFile})
	default:
		return fmt.Errorf("config: intune.auth (env INTUNE_AUTH) must be %q or %q: %q",
			AuthClientSecret, AuthWorkloadIdentity, c.Intune.Auth)
	}
	for _, r := range req {
		if r.val == "" {
			missing = append(missing, r.name)
		}
	}
	if c.Server.TLS.Enabled {
		if c.Server.TLS.Cert == "" {
			missing = append(missing, "server.tls.cert")
		}
		if c.Server.TLS.Key == "" {
			missing = append(missing, "server.tls.key")
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("config: missing required fields: %v", missing)
	}

	// A configured-but-unused credential is a secret kept for no reason, and a
	// sign the operator expected a different method to be in effect.
	if c.Intune.Auth == AuthWorkloadIdentity && c.Intune.ClientSecret != "" {
		return errors.New("config: intune.client_secret must be empty with intune.auth: workload_identity " +
			"(remove it, and INTUNE_CLIENT_SECRET, from the deployment)")
	}
	if c.Intune.Auth == AuthClientSecret && c.Intune.FederatedTokenFile != "" {
		return errors.New("config: intune.federated_token_file is set but intune.auth is client_secret; " +
			"set intune.auth: workload_identity to use it")
	}
	if !c.Server.TLS.Enabled && (c.Server.TLS.ClientCA != "" || len(c.Server.TLS.ClientDNSNames) > 0) {
		return errors.New("config: server.tls.client_ca and client_dns_names require server.tls.enabled")
	}
	if len(c.Server.TLS.ClientDNSNames) > 0 && c.Server.TLS.ClientCA == "" {
		return errors.New("config: server.tls.client_dns_names requires server.tls.client_ca")
	}

	if v := c.Server.TLS.MinVersion; v != "1.2" && v != "1.3" {
		return fmt.Errorf("config: server.tls.min_version must be \"1.2\" or \"1.3\": %q", v)
	}

	if err := c.decodeWebhookKeys(); err != nil {
		return err
	}
	if c.Webhook.MaxRequestAge < 30*time.Second || c.Webhook.MaxRequestAge > time.Hour {
		return fmt.Errorf("config: webhook.max_request_age must be between 30s and 1h: %s", c.Webhook.MaxRequestAge)
	}

	for _, e := range []struct{ key, env, val string }{
		{"intune.authority_host", "INTUNE_AUTHORITY_HOST", c.Intune.AuthorityHost},
		{"intune.graph_url", "INTUNE_GRAPH_URL", c.Intune.GraphURL},
		{"intune.resource_url", "INTUNE_RESOURCE_URL", c.Intune.ResourceURL},
	} {
		if err := checkHTTPSURL(e.key, e.env, e.val); err != nil {
			return err
		}
	}
	// app_id goes into the discovery URL path; a typo or stray character would
	// silently query another Graph resource.
	if !guidPattern.MatchString(c.Intune.AppID) {
		return fmt.Errorf("config: intune.app_id (env INTUNE_APP_ID) must be a GUID: %q", c.Intune.AppID)
	}
	return nil
}

// decodeWebhookKeys decodes and checks both webhook secrets. Startup fails on
// a secret that is not base64, is shorter than MinSecretBytes, or is shared by
// both endpoints: step-ca generates a distinct 64-byte secret per webhook, so
// any of these means the bridge is not configured with step-ca's secrets.
func (c *Config) decodeWebhookKeys() error {
	keys := make([][]byte, 2)
	for i, s := range []struct{ key, env, val string }{
		{"webhook.validate_secret", "SCEP_VALIDATE_SECRET", c.Webhook.ValidateSecret},
		{"webhook.notify_secret", "SCEP_NOTIFY_SECRET", c.Webhook.NotifySecret},
	} {
		k, err := base64.StdEncoding.DecodeString(s.val)
		if err != nil {
			return fmt.Errorf("config: %s (env %s) must be base64, as printed by `step ca provisioner webhook add`", s.key, s.env)
		}
		if len(k) < MinSecretBytes {
			return fmt.Errorf("config: %s (env %s) decodes to %d bytes; at least %d are required (step-ca generates 64)",
				s.key, s.env, len(k), MinSecretBytes)
		}
		keys[i] = k
	}
	if bytes.Equal(keys[0], keys[1]) {
		return errors.New("config: webhook.validate_secret and webhook.notify_secret are identical; " +
			"step-ca generates a distinct secret per webhook")
	}
	c.Webhook.validateKey, c.Webhook.notifyKey = keys[0], keys[1]
	return nil
}

// WebhookKeys returns the decoded HMAC keys for /validate and /notify. They
// are set by a successful Validate (and so Load).
func (c *Config) WebhookKeys() (validate, notify []byte) {
	return c.Webhook.validateKey, c.Webhook.notifyKey
}

var guidPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// checkHTTPSURL reports an error unless val is an absolute https URL with a
// host and no credentials, query or fragment (scopes and paths are appended to
// it, and it is logged). The error names both the YAML key and the env var,
// since either may have set it, and never repeats a password.
func checkHTTPSURL(key, env, val string) error {
	u, err := url.Parse(val)
	if err != nil {
		return fmt.Errorf("config: %s (env %s) must be an absolute https URL", key, env)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return fmt.Errorf("config: %s (env %s) must be an absolute https URL without credentials, query or fragment: %q",
			key, env, u.Redacted())
	}
	return nil
}

// Logger builds an *slog.Logger from the logging config. When Output is a file
// path, the file is opened for append (created if absent) and returned so the
// caller controls its lifetime; for stdout/stderr the returned closer is nil.
func (c *Config) Logger() (*slog.Logger, io.Closer, error) {
	var w io.Writer
	var closer io.Closer
	switch c.Logging.Output {
	case "stdout", "":
		w = os.Stdout
	case "stderr":
		w = os.Stderr
	default:
		f, err := os.OpenFile(c.Logging.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640) //nolint:gosec // G302: group-readable for log shippers
		if err != nil {
			return nil, nil, fmt.Errorf("config: open log file %q: %w", c.Logging.Output, err)
		}
		w, closer = f, f
	}

	var level slog.Level
	switch strings.ToLower(c.Logging.Level) {
	case "debug":
		level = slog.LevelDebug
	case "info", "":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, nil, fmt.Errorf("config: invalid logging.level %q", c.Logging.Level)
	}
	opts := &slog.HandlerOptions{Level: level}

	var h slog.Handler
	switch strings.ToLower(c.Logging.Format) {
	case "json", "":
		h = slog.NewJSONHandler(w, opts)
	case "text":
		h = slog.NewTextHandler(w, opts)
	default:
		return nil, nil, fmt.Errorf("config: invalid logging.format %q", c.Logging.Format)
	}
	return slog.New(h), closer, nil
}
