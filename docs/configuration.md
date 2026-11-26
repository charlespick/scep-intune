# Configuration

The bridge reads a YAML config file (default `config.yaml`, override with
`-config`). Copy [`config.example.yaml`](../config.example.yaml) and adjust.
Secrets should come from the **environment** rather than the file.

## File reference

Unknown keys are an error, so a misspelt setting (for example a secret's key)
cannot be silently ignored.

```yaml
server:
  listen: ":8080"           # address:port to listen on
  tls:
    enabled: false          # serve HTTPS directly (see "TLS" below)
    cert: ""                # PEM cert path (required if enabled); reloaded when it changes
    key: ""                 # PEM key path  (required if enabled)
    client_ca: ""           # PEM CA bundle: require a client certificate from it (mTLS)
    client_dns_names: []    # require one of these DNS SANs on the client certificate
    min_version: "1.3"      # "1.3" (default) or "1.2"

webhook:
  # REQUIRED. step-ca generates a DISTINCT secret per webhook, so each endpoint
  # has its own. base64 HMAC-SHA256 keys, inline or (preferred) from a file.
  validate_secret: ""       # SCEPCHALLENGE webhook secret
  validate_secret_file: ""  #   ...or a file holding it
  notify_secret: ""         # NOTIFYING webhook secret
  notify_secret_file: ""    #   ...or a file holding it
  max_request_age: 5m       # accepted skew of step-ca's signed timestamp (30s-1h)

intune:
  auth: client_secret       # client_secret | workload_identity
  tenant_id: ""             # Entra tenant (directory) ID
  client_id: ""             # Entra app (client) ID
  client_secret: ""         # client_secret auth: Entra app client secret
  client_secret_file: ""    #   ...or a file holding it
  federated_token_file: ""  # workload_identity auth: projected service account token
  caller_info: "step-ca-scep"
  # Microsoft endpoints (see "Microsoft endpoints" below); defaults shown.
  authority_host: "https://login.microsoftonline.com/"
  graph_url: "https://graph.microsoft.com/"
  resource_url: "https://api.manage.microsoft.com/"
  app_id: "0000000a-0000-0000-c000-000000000000"

logging:
  output: "stdout"          # "stdout", "stderr", or a file path (append/created)
  format: "json"            # "json" or "text"
  level: "info"             # "debug", "info", "warn", or "error"
```

## Environment overrides

Environment variables take precedence over the file. Use them, or better the
`*_FILE` variants pointing at a mounted secret, so nothing sensitive lands in
the config file:

| Env var | Overrides |
|---------|-----------|
| `INTUNE_AUTH` | `intune.auth` |
| `INTUNE_TENANT_ID` | `intune.tenant_id` |
| `INTUNE_CLIENT_ID` | `intune.client_id` |
| `INTUNE_CLIENT_SECRET` / `INTUNE_CLIENT_SECRET_FILE` | `intune.client_secret` / `intune.client_secret_file` |
| `INTUNE_FEDERATED_TOKEN_FILE` | `intune.federated_token_file` |
| `SCEP_VALIDATE_SECRET` / `SCEP_VALIDATE_SECRET_FILE` | `webhook.validate_secret` / `webhook.validate_secret_file` (SCEPCHALLENGE) |
| `SCEP_NOTIFY_SECRET` / `SCEP_NOTIFY_SECRET_FILE` | `webhook.notify_secret` / `webhook.notify_secret_file` (NOTIFYING) |
| `INTUNE_AUTHORITY_HOST` | `intune.authority_host` |
| `INTUNE_GRAPH_URL` | `intune.graph_url` |
| `INTUNE_RESOURCE_URL` | `intune.resource_url` |
| `INTUNE_APP_ID` | `intune.app_id` |

An environment variable overrides the file only when it is non-empty. A secret
given both inline and as a file is refused as ambiguous; a secret file's
surrounding whitespace (such as a trailing newline) is trimmed.

Always required: both webhook secrets, `intune.tenant_id` and
`intune.client_id`. Then, by `intune.auth`:

| `intune.auth` | Also required | Must be empty |
|---------------|---------------|---------------|
| `client_secret` (default) | `intune.client_secret` | `intune.federated_token_file` |
| `workload_identity` | `intune.federated_token_file` | `intune.client_secret` |

With `workload_identity`, `tenant_id`, `client_id` and `federated_token_file`
fall back to `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
`AZURE_FEDERATED_TOKEN_FILE`, which the Azure workload identity webhook injects
into the pod. See [kubernetes.md](kubernetes.md).

## Microsoft endpoints

The bridge talks to three Microsoft services. Their addresses mirror the four
values Microsoft's reference SCEP validation library
([Intune-Resource-Access](https://github.com/microsoft/Intune-Resource-Access/tree/master/src/CsrValidation))
makes configurable, and default to the commercial cloud:

| Setting | Default | Used for |
|---------|---------|----------|
| `intune.authority_host` | `https://login.microsoftonline.com/` | Entra sign-in (client-credentials token) |
| `intune.graph_url` | `https://graph.microsoft.com/` | Graph service discovery, at `<graph_url>v1.0/servicePrincipals/appId=<app_id>/endpoints`; Graph token scope `<graph_url>.default` |
| `intune.resource_url` | `https://api.manage.microsoft.com/` | Intune token scope `<resource_url>.default` (never contacted directly: the Intune address comes from discovery) |
| `intune.app_id` | `0000000a-0000-0000-c000-000000000000` | Intune's service principal, looked up during discovery |

The three URLs must be absolute `https://` URLs without credentials, query or
fragment; the scheme and host are lower-cased and a trailing slash is added if
missing. `app_id` must be a GUID. The address returned by Graph discovery must
be `https://` too: the bridge refuses to send its Intune token anywhere else. When `authority_host` differs from the commercial host, the bridge also
turns off the Azure SDK's *instance discovery*, which would otherwise ask
`login.microsoftonline.com` to approve the unknown host. The bridge logs the
effective endpoints at startup whenever any differs from its default, as a
**warning** when `authority_host` is not a Microsoft authority (commercial, US
Government or China): the Entra client secret is sent to that host.

The Azure SDK also reads `AZURE_AUTHORITY_HOST`. The bridge's own setting wins:
if `AZURE_AUTHORITY_HOST` is set to another host, it is ignored and the bridge
logs a warning. Use `intune.authority_host` or `INTUNE_AUTHORITY_HOST` instead.

### Other Microsoft clouds

To target another Microsoft cloud (for example US Government GCC High, DoD, or
China), set the four values for that cloud. Take them from Microsoft's
documentation: the
[national cloud deployments](https://learn.microsoft.com/en-us/graph/deployments)
page lists the Entra and Graph hosts, and the Intune values come from Microsoft's
Intune documentation for that cloud.

> **Only the commercial cloud has been tested.** Microsoft documents the
> third-party CA SCEP API
> ([overview](https://learn.microsoft.com/en-us/intune/fundamentals/certificates/third-party-ca-scep),
> [API reference](https://learn.microsoft.com/en-us/intune/fundamentals/certificates/ref-scep-api))
> for the commercial cloud. Confirm with Microsoft that it's available in your
> cloud before relying on it there.

### Testing without Microsoft

Point `authority_host` and `graph_url` at the bundled Intune mock and leave
`resource_url` and `app_id` at their defaults: see [testing.md](testing.md).

## Webhook secrets

step-ca signs each webhook call with the secret generated when you ran
`step ca provisioner webhook add` (see [step-ca-setup.md](step-ca-setup.md)).
Both secrets are **required**. The bridge refuses to start when either is:

- missing or empty,
- not valid base64,
- shorter than 32 bytes once decoded (step-ca generates 64), or
- identical to the other one (step-ca generates a distinct secret per webhook).

There is no unauthenticated mode. A `ca.json`-managed step-ca provisioner
**cannot store a webhook secret** (the field is `json:"-"`) and signs with an
empty key, so it cannot be used with this bridge: run step-ca in
**remote-management (admin) mode**.

Each signed request also carries step-ca's timestamp, covered by the
signature. Requests whose timestamp is missing, or further than
`webhook.max_request_age` (default 5 minutes) from the bridge's clock in either
direction, are refused, which bounds how long a captured request can be
replayed. Keep step-ca's and the bridge's clocks NTP-synchronised.

## TLS

step-ca requires webhook URLs to be **HTTPS**. Either:

- set `server.tls.enabled: true` with a `cert`/`key`, or
- terminate TLS at a reverse proxy (e.g. Caddy, nginx) in front of the bridge,
  on the same host or in the same pod. The bridge warns when it serves plain
  HTTP on a non-loopback address: webhook bodies carry each device's SCEP
  challenge.

When the bridge serves TLS itself:

- **TLS 1.3** is the minimum by default (step-ca is a Go client and always
  negotiates it). Set `min_version: "1.2"` only for a proxy that can't.
- The certificate and key are **re-read when their files change** (checked
  every minute), so short-lived certificates (step-ca issues 24 h ones by
  default) can be renewed in place, for example by `step ca renew --daemon` or
  cert-manager. A pair that fails to load is logged and the previous one stays
  in use. The bridge warns once the certificate enters the last tenth of its
  lifetime without having been renewed.
- **Mutual TLS** with step-ca: step-ca presents its own TLS certificate to
  webhook servers (unless the webhook was created with
  `--disable-tls-client-auth`). Set `client_ca` to step-ca's root certificate
  and `client_dns_names` to (one of) step-ca's `dnsNames`, and `/validate` and
  `/notify` only answer step-ca: any other client gets `403` before its request
  is read. `/healthz` stays reachable without a certificate, for health probes.
  This is a second, independent factor next to the HMAC secrets.
