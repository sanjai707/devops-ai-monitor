# Security Baseline

## Current controls

- API and dashboard ports are bound to `127.0.0.1`.
- Docker socket access is mounted read-only in application intent, though Docker socket mount permissions must remain restricted.
- Ollama is local and no model beyond `qwen2.5:3b` is introduced.
- Container logs and Docker state strings are redacted for known secret patterns before AI prompts.
- Environment variable values are not included in investigation evidence.
- Investigation remediation is advisory and never executed by the dashboard.
- Optional `API_KEY` middleware can require `X-API-Key` for mutations and knowledge endpoints.
- CORS origins are restricted by `CORS_ALLOWED_ORIGINS`.
- Remediation execution is disabled by `REMEDIATION_DISABLED=true` by default.
- Production Compose requires Ollama URL, CORS origins and API key variables.

## Remaining requirements

- Authentication and role-based authorization.
- CORS policy for production.
- Rate limiting and request-size controls.
- Secure secret injection and database backups.
- Non-root container execution where feasible.
- Explicit audit history for operator actions and remediation approvals.

## Independent audit status

IMPLEMENTED / TESTED:
- Optional API-key enforcement for mutations and knowledge routes.
- CORS origin allowlisting.
- Log, evidence and operator context secret redaction patterns.
- Remediation disabled by default and no infrastructure-changing endpoint.
- Read-only Docker socket mounts in both Compose profiles.
- Pydantic request bounds and FastAPI 400/404/401/503 error responses.
- Incident and knowledge audit/version records.

VERIFIED LIMITATIONS:
- API keys are not user identities and provide no RBAC or MFA.
- Dashboard and diagnostic GET endpoints remain readable unless network
  isolation and a surrounding reverse proxy protect them.
- No TLS termination is included; exposing ports publicly is prohibited.
- No rate limiting or request-size controls at the proxy/application layer.
- Docker socket access remains a privileged capability even when mounted
  read-only.
- Approved knowledge is untrusted supporting context and cannot execute
  remediation; prompt-injection fixtures are covered, but real-model resistance
  is not proven.
- Secret redaction is pattern-based and can miss unknown secret formats.
- Audit history records application actions but does not establish real-user
  identity or approval signatures.

## Runtime authentication audit

- Local Compose: `API_KEY=""`, so optional API-key middleware is not enforcing
  authentication. This was observed directly with unauthenticated mutation and
  knowledge calls receiving application responses rather than `401`.
- Production Compose: `API_KEY` is mandatory and can be tested through the
  middleware unit gate. A real secrets-bearing production deployment was not
  exposed or claimed.
- The browser had no credential prompt or identity session. It does not
  implement login, MFA or RBAC.

## OpenTelemetry local profile

- OTLP receiver ports are published only on loopback (127.0.0.1).
- Collector endpoints bind to the Compose network; do not expose ports 4317 or
  4318 to untrusted networks. This first local profile does not configure
  receiver authentication or TLS.
- FastAPI and HTTPX instrumentation are enabled only when `OTEL_ENABLED=true`.
  No request/response bodies or headers are configured for capture.
- Grafana and Prometheus are localhost-only. Change the default Grafana password
  in `.env` before starting the telemetry profile.
- Prometheus metrics are retained for 7 days in a dedicated named volume.
- Traces are debug-exported to Collector logs, not stored in a trace backend.
