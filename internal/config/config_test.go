package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Two distinct 64-byte secrets, as step-ca generates them.
var (
	validateB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'v'}, 64))
	notifyB64   = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'n'}, 64))
)

// setSecrets provides valid webhook secrets through the environment.
func setSecrets(t *testing.T) {
	t.Helper()
	t.Setenv("SCEP_VALIDATE_SECRET", validateB64)
	t.Setenv("SCEP_NOTIFY_SECRET", notifyB64)
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValidWithDefaults(t *testing.T) {
	setSecrets(t)
	p := writeConfig(t, `
server:
  listen: ":9090"
intune:
  tenant_id: "t"
  client_id: "c"
  client_secret: "s"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != ":9090" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Intune.CallerInfo != "step-ca-scep" {
		t.Errorf("callerInfo default = %q", cfg.Intune.CallerInfo)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("logging format default = %q", cfg.Logging.Format)
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("INTUNE_CLIENT_SECRET", "env-secret")
	t.Setenv("SCEP_VALIDATE_SECRET", validateB64)
	t.Setenv("SCEP_NOTIFY_SECRET", notifyB64)
	p := writeConfig(t, `
intune:
  tenant_id: "t"
  client_id: "c"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.ClientSecret != "env-secret" {
		t.Errorf("client secret = %q", cfg.Intune.ClientSecret)
	}
	if cfg.Webhook.ValidateSecret != validateB64 {
		t.Errorf("validate secret = %q", cfg.Webhook.ValidateSecret)
	}
	if cfg.Webhook.NotifySecret != notifyB64 {
		t.Errorf("notify secret = %q", cfg.Webhook.NotifySecret)
	}
}

func TestValidateMissingRequired(t *testing.T) {
	setSecrets(t)
	p := writeConfig(t, "server:\n  listen: \":8080\"\n")
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for missing required fields")
	}
	for _, want := range []string{"intune.tenant_id", "intune.client_id"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestTLSRequiresCertKey(t *testing.T) {
	setSecrets(t)
	p := writeConfig(t, `
intune:
  tenant_id: "t"
  client_id: "c"
  client_secret: "s"
server:
  tls:
    enabled: true
`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "server.tls.cert") {
		t.Fatalf("err = %v, want tls.cert required", err)
	}
}

const minimalIntune = `
intune:
  tenant_id: "t"
  client_id: "c"
  client_secret: "s"
`

func TestEndpointDefaults(t *testing.T) {
	setSecrets(t)
	cfg, err := Load(writeConfig(t, minimalIntune))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"authority_host": "https://login.microsoftonline.com/",
		"graph_url":      "https://graph.microsoft.com/",
		"resource_url":   "https://api.manage.microsoft.com/",
		"app_id":         "0000000a-0000-0000-c000-000000000000",
	}
	got := map[string]string{
		"authority_host": cfg.Intune.AuthorityHost,
		"graph_url":      cfg.Intune.GraphURL,
		"resource_url":   cfg.Intune.ResourceURL,
		"app_id":         cfg.Intune.AppID,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %q, want %q", k, got[k], w)
		}
	}
}

func TestEndpointFromFileAndEnv(t *testing.T) {
	setSecrets(t)
	t.Setenv("INTUNE_RESOURCE_URL", "https://api.manage.microsoft.us/")
	t.Setenv("INTUNE_APP_ID", "11111111-2222-3333-4444-555555555555")
	cfg, err := Load(writeConfig(t, minimalIntune+"  graph_url: https://graph.microsoft.us/\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.GraphURL != "https://graph.microsoft.us/" {
		t.Errorf("graph_url = %q", cfg.Intune.GraphURL)
	}
	if cfg.Intune.ResourceURL != "https://api.manage.microsoft.us/" {
		t.Errorf("resource_url = %q", cfg.Intune.ResourceURL)
	}
	if cfg.Intune.AppID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("app_id = %q", cfg.Intune.AppID)
	}
}

func TestEndpointTrailingSlashNormalised(t *testing.T) {
	setSecrets(t)
	cfg, err := Load(writeConfig(t, minimalIntune+
		"  authority_host: https://login.microsoftonline.us\n"+
		"  graph_url: https://graph.microsoft.us//\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.AuthorityHost != "https://login.microsoftonline.us/" {
		t.Errorf("authority_host = %q", cfg.Intune.AuthorityHost)
	}
	if cfg.Intune.GraphURL != "https://graph.microsoft.us/" {
		t.Errorf("graph_url = %q", cfg.Intune.GraphURL)
	}
}

func TestEndpointRejectsNonHTTPS(t *testing.T) {
	setSecrets(t)
	for _, key := range []string{"authority_host", "graph_url", "resource_url"} {
		for _, val := range []string{"http://x/", "graph.microsoft.com", "https://"} {
			t.Run(key+"="+val, func(t *testing.T) {
				_, err := Load(writeConfig(t, minimalIntune+"  "+key+": \""+val+"\"\n"))
				if err == nil || !strings.Contains(err.Error(), "intune."+key) {
					t.Fatalf("want error naming intune.%s, got %v", key, err)
				}
			})
		}
	}
}

func TestEndpointEmptyEnvKeepsFile(t *testing.T) {
	setSecrets(t)
	t.Setenv("INTUNE_GRAPH_URL", "")
	cfg, err := Load(writeConfig(t, minimalIntune+"  graph_url: https://g.example/\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.GraphURL != "https://g.example/" {
		t.Errorf("graph_url = %q", cfg.Intune.GraphURL)
	}
}

// The documented example must stay loadable (its secrets come from the env).
func TestExampleConfigLoads(t *testing.T) {
	setSecrets(t)
	t.Setenv("INTUNE_TENANT_ID", "t")
	t.Setenv("INTUNE_CLIENT_ID", "c")
	t.Setenv("INTUNE_CLIENT_SECRET", "s")
	cfg, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.GraphURL != DefaultGraphURL {
		t.Errorf("graph_url = %q", cfg.Intune.GraphURL)
	}
}

// Hosts are case-insensitive: an upper-case default must still count as the
// default (so instance discovery stays on) and derive the same scopes.
func TestEndpointHostLowercased(t *testing.T) {
	setSecrets(t)
	cfg, err := Load(writeConfig(t, minimalIntune+
		"  authority_host: HTTPS://LOGIN.microsoftonline.com\n"+
		"  graph_url: https://Graph.Microsoft.com/Path/\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.AuthorityHost != DefaultAuthorityHost {
		t.Errorf("authority_host = %q, want %q", cfg.Intune.AuthorityHost, DefaultAuthorityHost)
	}
	// Only scheme and host are case-insensitive; the path is kept as written.
	if cfg.Intune.GraphURL != "https://graph.microsoft.com/Path/" {
		t.Errorf("graph_url = %q", cfg.Intune.GraphURL)
	}
}

func TestEndpointRejectsQueryAndFragment(t *testing.T) {
	setSecrets(t)
	for _, val := range []string{"https://graph.microsoft.us/?x=1", "https://graph.microsoft.us/#frag"} {
		_, err := Load(writeConfig(t, minimalIntune+"  graph_url: \""+val+"\"\n"))
		if err == nil || !strings.Contains(err.Error(), "intune.graph_url") {
			t.Errorf("%s: want error naming intune.graph_url, got %v", val, err)
		}
	}
}

// The value may come from the environment, so the error names both sources.
func TestEndpointErrorNamesEnvVar(t *testing.T) {
	setSecrets(t)
	t.Setenv("INTUNE_GRAPH_URL", "http://insecure/")
	_, err := Load(writeConfig(t, minimalIntune))
	if err == nil || !strings.Contains(err.Error(), "INTUNE_GRAPH_URL") {
		t.Fatalf("want error naming INTUNE_GRAPH_URL, got %v", err)
	}
}

func TestAppIDMustBeGUID(t *testing.T) {
	setSecrets(t)
	for val, ok := range map[string]bool{
		"0000000a-0000-0000-c000-000000000000":  true,
		"0000000A-0000-0000-C000-000000000000":  true,
		"0000000a-0000-0000-c000-000000000000/": false,
		"x?y":                                   false,
		"abc":                                   false,
	} {
		_, err := Load(writeConfig(t, minimalIntune+"  app_id: \""+val+"\"\n"))
		if (err == nil) != ok {
			t.Errorf("app_id %q: err = %v, want ok=%v", val, err, ok)
		}
		if err != nil && !strings.Contains(err.Error(), "INTUNE_APP_ID") {
			t.Errorf("app_id %q: error %q should name INTUNE_APP_ID", val, err)
		}
	}
}

// Credentials in a URL would end up in logs and token scopes.
func TestEndpointRejectsUserinfo(t *testing.T) {
	setSecrets(t)
	_, err := Load(writeConfig(t, minimalIntune+"  graph_url: \"https://user:pass@graph.example/\"\n"))
	if err == nil || !strings.Contains(err.Error(), "intune.graph_url") {
		t.Fatalf("want error naming intune.graph_url, got %v", err)
	}
	if strings.Contains(err.Error(), "pass") {
		t.Fatalf("error leaks the password: %v", err)
	}
}

// Empty webhook secrets are a startup failure: there is no unauthenticated mode.
func TestWebhookSecretsRequired(t *testing.T) {
	for _, tc := range []struct{ validate, notify, want string }{
		{"", notifyB64, "webhook.validate_secret"},
		{validateB64, "", "webhook.notify_secret"},
		{"", "", "webhook.notify_secret"},
	} {
		t.Setenv("SCEP_VALIDATE_SECRET", tc.validate)
		t.Setenv("SCEP_NOTIFY_SECRET", tc.notify)
		_, err := Load(writeConfig(t, minimalIntune))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("validate=%q notify=%q: err = %v, want it to name %s", tc.validate, tc.notify, err, tc.want)
		}
	}
}

func TestWebhookSecretRules(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, MinSecretBytes-1))
	for name, tc := range map[string]struct{ validate, notify, want string }{
		"not base64": {"not base64!", notifyB64, "must be base64"},
		"too short":  {validateB64, short, "at least 32"},
		"identical":  {validateB64, validateB64, "identical"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("SCEP_VALIDATE_SECRET", tc.validate)
			t.Setenv("SCEP_NOTIFY_SECRET", tc.notify)
			_, err := Load(writeConfig(t, minimalIntune))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestWebhookKeysDecoded(t *testing.T) {
	setSecrets(t)
	cfg, err := Load(writeConfig(t, minimalIntune))
	if err != nil {
		t.Fatal(err)
	}
	v, n := cfg.WebhookKeys()
	if !bytes.Equal(v, bytes.Repeat([]byte{'v'}, 64)) || !bytes.Equal(n, bytes.Repeat([]byte{'n'}, 64)) {
		t.Fatalf("keys not decoded: %q %q", v, n)
	}
}

func writeSecret(t *testing.T, val string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(val), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSecretsFromFiles(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
webhook:
  validate_secret_file: "`+writeSecret(t, validateB64+"\n")+`"
  notify_secret_file: "`+writeSecret(t, notifyB64)+`"
intune:
  tenant_id: "t"
  client_id: "c"
  client_secret_file: "`+writeSecret(t, "s3cret\n")+`"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Webhook.ValidateSecret != validateB64 || cfg.Webhook.NotifySecret != notifyB64 {
		t.Errorf("webhook secrets not read from files")
	}
	if cfg.Intune.ClientSecret != "s3cret" {
		t.Errorf("client secret = %q, want trimmed file content", cfg.Intune.ClientSecret)
	}
}

func TestSecretFileFromEnv(t *testing.T) {
	t.Setenv("SCEP_VALIDATE_SECRET_FILE", writeSecret(t, validateB64))
	t.Setenv("SCEP_NOTIFY_SECRET_FILE", writeSecret(t, notifyB64))
	if _, err := Load(writeConfig(t, minimalIntune)); err != nil {
		t.Fatal(err)
	}
}

func TestSecretInlineAndFileIsAmbiguous(t *testing.T) {
	setSecrets(t)
	t.Setenv("SCEP_NOTIFY_SECRET_FILE", writeSecret(t, notifyB64))
	_, err := Load(writeConfig(t, minimalIntune))
	if err == nil || !strings.Contains(err.Error(), "webhook.notify_secret") {
		t.Fatalf("err = %v, want an ambiguity error", err)
	}
}

func TestEmptySecretFileRejected(t *testing.T) {
	t.Setenv("SCEP_VALIDATE_SECRET_FILE", writeSecret(t, "\n"))
	t.Setenv("SCEP_NOTIFY_SECRET", notifyB64)
	_, err := Load(writeConfig(t, minimalIntune))
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err = %v, want empty-file error", err)
	}
}

// A misspelt key must not be silently ignored (it would drop a secret).
func TestUnknownKeyRejected(t *testing.T) {
	setSecrets(t)
	_, err := Load(writeConfig(t, minimalIntune+"webhook:\n  validate_secert: \"x\"\n"))
	if err == nil || !strings.Contains(err.Error(), "validate_secert") {
		t.Fatalf("err = %v, want unknown-field error", err)
	}
}

func TestMaxRequestAge(t *testing.T) {
	setSecrets(t)
	cfg, err := Load(writeConfig(t, minimalIntune))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Webhook.MaxRequestAge != DefaultMaxRequestAge {
		t.Errorf("default max_request_age = %s", cfg.Webhook.MaxRequestAge)
	}
	cfg, err = Load(writeConfig(t, minimalIntune+"webhook:\n  max_request_age: 2m\n"))
	if err != nil || cfg.Webhook.MaxRequestAge != 2*time.Minute {
		t.Fatalf("max_request_age 2m: cfg=%v err=%v", cfg, err)
	}
	for _, bad := range []string{"1s", "2h"} {
		if _, err := Load(writeConfig(t, minimalIntune+"webhook:\n  max_request_age: "+bad+"\n")); err == nil {
			t.Errorf("max_request_age %s accepted", bad)
		}
	}
}

const workloadIdentity = `
intune:
  auth: workload_identity
`

func TestWorkloadIdentityFromInjectedEnv(t *testing.T) {
	setSecrets(t)
	t.Setenv("AZURE_TENANT_ID", "tenant-from-webhook")
	t.Setenv("AZURE_CLIENT_ID", "client-from-webhook")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/var/run/secrets/azure/tokens/azure-identity-token")
	cfg, err := Load(writeConfig(t, workloadIdentity))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.TenantID != "tenant-from-webhook" || cfg.Intune.ClientID != "client-from-webhook" ||
		cfg.Intune.FederatedTokenFile != "/var/run/secrets/azure/tokens/azure-identity-token" {
		t.Errorf("injected values not used: %+v", cfg.Intune)
	}
}

// The bridge's own settings win over the injected AZURE_* values.
func TestWorkloadIdentityExplicitWins(t *testing.T) {
	setSecrets(t)
	t.Setenv("AZURE_CLIENT_ID", "client-from-webhook")
	t.Setenv("AZURE_TENANT_ID", "tenant-from-webhook")
	cfg, err := Load(writeConfig(t, workloadIdentity+"  client_id: mine\n  federated_token_file: /tok\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.ClientID != "mine" || cfg.Intune.FederatedTokenFile != "/tok" {
		t.Errorf("explicit values overridden: %+v", cfg.Intune)
	}
}

func TestWorkloadIdentityRequiresTokenFile(t *testing.T) {
	setSecrets(t)
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	_, err := Load(writeConfig(t, workloadIdentity+"  tenant_id: t\n  client_id: c\n"))
	if err == nil || !strings.Contains(err.Error(), "intune.federated_token_file") {
		t.Fatalf("err = %v, want federated_token_file required", err)
	}
}

func TestWorkloadIdentityRefusesClientSecret(t *testing.T) {
	setSecrets(t)
	_, err := Load(writeConfig(t, workloadIdentity+"  tenant_id: t\n  client_id: c\n  client_secret: s\n  federated_token_file: /tok\n"))
	if err == nil || !strings.Contains(err.Error(), "client_secret must be empty") {
		t.Fatalf("err = %v, want client_secret refused", err)
	}
}

func TestClientSecretModeRefusesTokenFile(t *testing.T) {
	setSecrets(t)
	_, err := Load(writeConfig(t, minimalIntune+"  federated_token_file: /tok\n"))
	if err == nil || !strings.Contains(err.Error(), "federated_token_file") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnknownAuthRejected(t *testing.T) {
	setSecrets(t)
	t.Setenv("INTUNE_AUTH", "managed_identity")
	_, err := Load(writeConfig(t, minimalIntune))
	if err == nil || !strings.Contains(err.Error(), "INTUNE_AUTH") {
		t.Fatalf("err = %v", err)
	}
}

func TestTLSClientAuthSettings(t *testing.T) {
	setSecrets(t)
	tls := "server:\n  tls:\n    enabled: %s\n    cert: c\n    key: k\n%s"
	for name, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"client ca":               {fmt.Sprintf(tls, "true", "    client_ca: ca.pem\n    client_dns_names: [ca.example]\n"), true},
		"names without ca":        {fmt.Sprintf(tls, "true", "    client_dns_names: [ca.example]\n"), false},
		"client ca without tls":   {fmt.Sprintf(tls, "false", "    client_ca: ca.pem\n"), false},
		"min version 1.2":         {fmt.Sprintf(tls, "true", "    min_version: \"1.2\"\n"), true},
		"min version 1.1 refused": {fmt.Sprintf(tls, "true", "    min_version: \"1.1\"\n"), false},
	} {
		_, err := Load(writeConfig(t, minimalIntune+tc.body))
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tc.ok)
		}
	}
}
