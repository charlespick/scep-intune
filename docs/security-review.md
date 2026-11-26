# Security review and hardening (pre-adoption)

Review of this fork of `KerckhoffsLabs/scep-intune` before adopting it in a
certificate authority's issuing path, and the changes made as a result.
Reviewed at upstream `3fbb21b`; dates are as of 2026-11-26.

**Threat model.** The bridge decides whether step-ca issues a certificate to
an Intune device: a `/validate` answer of `allow: true` is, in effect, an
issuance authorisation. It holds the credential that lets it validate any
Intune SCEP challenge for the tenant. Its compromise, or a way around its
checks, means certificates for devices that should not get them. Availability
matters too (enrolment stops), but integrity of the allow decision comes first.

## Summary

| # | Finding (upstream) | Severity | Status |
|---|--------------------|----------|--------|
| 1 | Empty webhook secret accepted with a warning: HMAC with an empty key is computable by anyone, so `/validate` becomes unauthenticated | **High** | Fixed: startup failure |
| 2 | Unknown config keys silently ignored: a misspelt secret key (e.g. `validate_secert`) left the secret empty, which by #1 disabled authentication | Medium (High with #1) | Fixed: strict decoding |
| 3 | No replay protection: a captured signed request is valid forever | Medium | Fixed: signed-timestamp window |
| 4 | Any network client can reach the webhook endpoints; only the HMAC stands between them and Intune | Medium | Fixed (opt-in): mutual TLS with step-ca |
| 5 | Long-lived Entra client secret is the only credential option | Medium | Fixed: workload identity federation |
| 6 | Secrets only inline or in environment variables | Low | Fixed: `*_file` / `*_FILE` |
| 7 | Bearer tokens follow same-domain redirects; upstream responses read without bound; discovered Intune URI may carry credentials/query | Low | Fixed |
| 8 | Oversized bodies silently truncated; method/path matching by hand | Low | Fixed |
| 9 | TLS certificate never reloaded (pushes operators to long-lived certificates); minimum version left to defaults | Low | Fixed: hot reload, TLS 1.3 default |
| 10 | Depends on `gopkg.in/yaml.v3`, archived and unmaintained | Low | Fixed: `go.yaml.in/yaml/v3` |
| 11 | Go 1.27.2 has two reachable stdlib vulnerabilities | Medium | Fixed: Go 1.27.4 |
| 12 | step-ca falls back to **no challenge validation** if the webhook disappears | **High (deployment)** | Documented; outside the bridge's control |
| 13 | Latest step-ca release carries 58 reachable known vulnerabilities | **High (deployment)** | Reported below; see recommendation |

## What was reviewed and found sound

- HMAC verification uses `hmac.Equal` (constant time) over the raw body,
  before anything in the body is parsed or logged.
- Fail-closed decisions: only an Intune reply with `code == "Success"` allows;
  any other code is `allow: false`; transport, auth and non-2xx failures return
  HTTP 502, which step-ca treats as a refusal (after one retry).
- Separate secrets per endpoint (now enforced distinct), so a `/validate`
  request can't be replayed at `/notify` and vice versa.
- Nothing sensitive is logged: not the challenge (which step-ca sends in
  `scepChallenge`), CSR, certificate, tokens or secrets. Endpoint URLs are
  validated to carry no credentials.
- Graph discovery result must be `https`; `app_id` must be a GUID (it goes into
  a URL path); HTTP server timeouts bound slow clients; graceful shutdown.
- `hResult` conversion can't wrap an out-of-range code into a different one.

## Changes

### Empty secrets are a startup failure (#1, #2)

`config.Load` now fails, and the process exits non-zero before listening, when
either webhook secret is missing, not base64, shorter than 32 bytes decoded
(step-ca generates 64), or both secrets are identical. `webhook.New` repeats
the length and distinctness checks, and `verifySignature` refuses an empty key,
so no caller can construct an unauthenticated handler. The YAML decoder rejects
unknown keys. The previous "ca.json provisioner with an empty secret" mode is
gone: step-ca must run in remote-management mode (documented).

### Replay window (#3)

step-ca puts `timestamp` in every webhook body and signs it (verified in
step-ca v0.30.2, `authority/provisioner/webhook.go`). Requests whose timestamp
is missing or more than `webhook.max_request_age` (default 5 min, 30 s–1 h)
from the local clock are refused with 401. step-ca's single retry re-sends the
same body after one second, well within the window. A nonce cache was not
added: it would break that retry, and wouldn't work across replicas.

### Mutual TLS with step-ca (#4)

step-ca presents its own TLS certificate to webhook servers unless the webhook
has `disableTLSClientAuth` (verified in `ca/ca.go`). With
`server.tls.client_ca` (step-ca's root) and optionally `client_dns_names`, the
bridge requires that certificate for `/validate` and `/notify` (403 otherwise,
before the body is read). `/healthz` stays open for probes. Verified end to end
against a real step-ca.

### Workload identity federation (#5)

`intune.auth: workload_identity` uses `azidentity.WorkloadIdentityCredential`
(azidentity v1.15.0): a projected Kubernetes service account token is exchanged
for an Entra app token via a federated identity credential on the app
registration. No Entra secret exists. `client_secret` must be empty in this mode
(refused otherwise), the `AZURE_*` variables the Azure workload identity
webhook injects are used as fallbacks, and the authority-host pinning that
already applied to client secrets applies here too. Guide:
[kubernetes.md](kubernetes.md). The webhook HMAC secrets necessarily remain
(step-ca generates them); they can now be mounted as files.

### Other hardening (#6–#10)

- Secrets from files: `webhook.validate_secret_file`, `notify_secret_file`,
  `intune.client_secret_file` and the `*_FILE` env vars; inline+file is
  refused as ambiguous.
- Outbound: redirects are never followed (every request carries a bearer
  token); Graph/Intune responses capped at 1 MiB; discovery must answer 2xx;
  the discovered Intune URI may not contain userinfo, query or fragment.
- Inbound: `http.MaxBytesReader` (413 for > 1 MiB), Go 1.22 method+path
  patterns (`POST /validate`, `POST /notify`, `GET /healthz`), `scepTransactionID`
  required, `/validate` CSR must parse, `MaxHeaderBytes` 32 KiB,
  `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` on every
  response, `X-Smallstep-Webhook-ID` and `X-Request-Id` logged for correlation.
- TLS: minimum TLS 1.3 by default (`server.tls.min_version: "1.2"` available);
  certificate and key re-read when changed (checked every minute; a bad pair
  keeps the old one); warning near expiry. Plain HTTP on a non-loopback
  address logs a warning (bodies carry the device challenge).
- Build: `make build` is `CGO_ENABLED=0 -trimpath`; `make vuln` and a CI
  `govulncheck` job (pinned v1.10.0); `persist-credentials: false` on every
  checkout.

## Dependencies

Policy: adopt only releases published at least 7 days ago (on or before
2026-11-19), to leave time for a malicious or broken release to be noticed.
Publish times are from `proxy.golang.org` `.info` (Go) and GitHub release pages.

| Dependency | Before | After | Published | Note |
|------------|--------|-------|-----------|------|
| Go toolchain (`go` directive) | 1.27.2 | **1.27.4** | 2026-11-02 | fixes GO-2026-6859, GO-2026-6809 (both reachable) |
| golang.org/x/crypto | v0.58.0 | **v0.59.0** | 2026-11-11 | fixes GO-2026-5932 (module-level, not reachable) |
| golang.org/x/net | v0.62.0 | **v0.63.0** | 2026-11-17 | |
| golang.org/x/sys | v0.49.0 | **v0.50.0** | 2026-11-06 | |
| golang.org/x/text | v0.43.0 | **v0.44.0** | 2026-11-09 | |
| golang.org/x/sync | v0.24.0 | **v0.25.0** | 2026-10-15 | |
| YAML | gopkg.in/yaml.v3 v3.0.1 (archived) | **go.yaml.in/yaml/v3 v3.0.6** | 2026-10-13 | maintained successor, same API. v4.0.0 (2026-11-04) is eligible but a new major line; not needed |
| azcore / azidentity / MSAL | v1.24.0 / v1.15.0 / v1.10.1 | unchanged | — | already latest |
| golangci-lint, step-ca, step, scepclient (CI/e2e) | v2.15.0 / v0.30.2 / v0.31.0 / v2.3.0 | unchanged | — | already latest releases |
| actions/setup-go | v7.0.0 | unchanged | v7.1.0: 2026-11-17 | eligible, no security content; **not bumped here** because the org's `actions.lock` must be regenerated with `gh actions-lock`, which isn't available in this environment. Dependabot (7-day cooldown) will propose it |
| SonarSource/sonarqube-scan-action | v8.5.0 | unchanged | v8.5.1: 2026-11-23 | too new (3 days); release notes list no security fix |

`go mod tidy` also dropped the stale indirect `kr/text` and
`rogpeppe/go-internal` requirements.

## Vulnerabilities fixed only by releases too new to adopt

Method: `govulncheck` v1.10.0 (published 2026-11-17) against a local copy of
the Go vulnerability database (golang/vulndb `d8a8b1a`, 2026-11-24), in symbol
mode; plus a version-range match of **every** module in the build graph
(test-only and unreachable ones included) and the toolchain against every
advisory, which reproduces govulncheck's pre-bump findings exactly.

**The bridge itself: none.** After the bumps, govulncheck reports no
vulnerabilities, and no advisory affects any module version in the graph or
Go 1.27.4. No vulnerability is fixed only by a release newer than the cutoff.
The two newer GitHub Action releases contain no security fixes.

**step-ca: significant.** The SCEP server in front of this bridge (and the e2e
test's) is step-ca, whose latest release, **v0.30.2 (2026-03-19)**, is built
with **go1.26.1**. `govulncheck -mode binary` on the official release binary
finds **58 reachable advisories** (86 in total): 27 in the Go standard library
alone, the rest in its modules (golang.org/x/net, x/crypto, x/text, go-jose,
gRPC, pgx, OpenTelemetry, klauspost/compress). Examples that matter for a CA:

| Advisory | Component | Fixed in |
|----------|-----------|----------|
| GO-2026-4866 name-constraint bypass (case-sensitive excludedSubtrees) | crypto/x509 | Go 1.26.2 |
| GO-2026-6809 distrust compromised intermediates | crypto/x509 | Go 1.26.10 |
| GO-2026-4870, GO-2026-6090 TLS 1.3 KeyUpdate / post-handshake DoS | crypto/tls | Go 1.26.2 / 1.26.6 |
| GO-2026-4945 JWE decryption panic (provisioner tokens) | go-jose v3/v4 | v3.0.5 / v4.1.4 |
| GO-2026-5004 SQL injection via dollar-quoted literals | pgx v5 (PostgreSQL backend only) | v5.9.2 |
| GO-2026-6603, 6611, 6612, 6617 HTTP/2 server DoS/crash | net/http, x/net | Go 1.26.9 / x/net v0.60.0 |
| GO-2026-6974 attribute length limit bypass | OpenTelemetry | `otel/trace` v1.47.0; **no fix** for `otel` |

step-ca's fixes for the module advisories exist only on its **untagged master
branch** (`v0.30.3-0.20261126162457-41fe0e9aecd2`, committed today), which
moves to x/crypto v0.59.0, x/net v0.63.0, gRPC v1.85.0, go-jose v4.1.9, pgx
v5.9.2 and others. **Adopting that is not safe**: it is an unreleased commit
hours old, with no release review, signed checksums or soak time, in the most
sensitive component of the PKI.

Recommendation, without waiting for v0.30.3:

1. Rebuild step-ca **from the `v0.30.2` tag** with a current, patched
   toolchain (go1.26.11 or go1.27.4). That clears the 27 stdlib-only
   advisories, and the stdlib half of the shared ones, with no change to
   step-ca's code.
2. In that build, raise only the affected modules to fixed releases that are
   themselves past the 7-day cutoff (`go get` x/net, x/crypto, x/text,
   go-jose, gRPC, klauspost/compress, otel/trace; pgx if you use PostgreSQL),
   and run step-ca's own test suite.
3. Move to v0.30.3 once released and 7 days old.

The e2e-only `step` CLI (go1.27.1) and `scepclient` (go1.21.3) binaries have
similar stdlib findings; they never run in production.

## Deployment requirements outside the bridge (#12)

In step-ca's SCEP provisioner, if no `SCEPCHALLENGE` webhook applies **and** no
static challenge is set, **no challenge is checked at all** (step-ca v0.30.2,
`selectValidationMethod`). Any `SCEPCHALLENGE` webhook answering `allow: true`
is also sufficient on its own. The bridge cannot detect either situation. The
[provisioner checklist](step-ca-setup.md#provisioner-checklist) covers it:
exactly one challenge webhook, no static challenge, TLS client auth kept on,
template and X.509 policy restricting SANs, validity claims, a dedicated
intermediate, and alerting on provisioner changes.

## Residual risks and possible follow-ups

- **Discovered Intune host not allow-listed.** The bridge trusts Graph (over
  TLS) to name the Intune endpoint, which receives an Intune-scoped token. An
  allow-list (e.g. `*.manage.microsoft.com` for the commercial cloud) would
  add defence in depth but needs per-cloud values and breaks the mock; not
  done.
- **No rate limit.** Unauthenticated requests cost one HMAC; authenticated
  ones fan out to Intune but only step-ca can produce them. Use mutual TLS and
  the NetworkPolicy in [kubernetes.md](kubernetes.md).
- **Clock dependence.** The replay window needs NTP on step-ca and the bridge.
- **Dependabot patch cooldown is 1 day** (`semver-patch-days: 1`, a deliberate
  trade-off documented in `.github/dependabot.yml`), which is shorter than the
  7-day policy applied here. Align it if the 7-day rule should hold for
  patches too.
- **No container image is built** here (removed upstream). Build from
  `make build` on a minimal base, sign it, and deploy by digest.

## Verification

- `go test -race -vet=all ./...`: pass, including new tests for the secret
  rules, secret files, strict keys, workload identity config, replay window,
  cross-endpoint signatures, body limits, method/path routing, redirect
  refusal, response caps, mutual TLS (good, missing, untrusted, wrong-SAN
  client certificates) and certificate hot reload.
- `golangci-lint` v2.15.0 (the CI version): 0 issues; formatters clean.
- `make e2e` against real step-ca v0.30.2: pass. New cases: the bridge refuses
  to start with an empty, shared or short secret; a request without step-ca's
  client certificate gets 403 while step-ca's own calls succeed over mutual TLS;
  a full enrolment succeeds with `intune.auth: workload_identity` and no client
  secret, the mock accepting only the exact projected-token value.
- `govulncheck` v1.10.0: no vulnerabilities.
