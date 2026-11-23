# Final Engineering Report

## Status

Overall status: **TESTED / BLOCKED FOR PRODUCTION READINESS**

This independent audit does not declare production readiness. The application is
feature-complete for the documented local profile, but authentication, TLS,
authorization, PostgreSQL migration and external infrastructure verification
remain incomplete or unavailable.

Implemented and verified:

- Repository audit and architecture documentation.
- Docker monitoring and event collection.
- Persisted historical metrics, network throughput rates and retention.
- Incident lifecycle states, occurrence counts, comments and audit history.
- Evidence-grounded investigations with explicit evidence IDs and deterministic validation.
- Persistent approved knowledge, version history and Knowledge Center.
- Investigation feedback and correction-to-proposed-knowledge workflow.
- Repeatable deterministic evaluation dataset and stored reports.
- Read-only remediation allowlist with remediation disabled by default.
- Docker provider status and Kubernetes/AWS unconfigured state.
- Optional API-key protection, restricted CORS and production Compose profile.
- SQLite backup and restore scripts.

## Files added or modified

Key additions include:

- `docker_event_collector.py`
- `evaluation.py`
- `evaluation/evaluation_cases.json`
- `providers/base.py`
- `providers/docker_provider.py`
- `scripts/backup-sqlite.ps1`
- `scripts/restore-sqlite.ps1`
- `compose.production.yaml`
- `tests/test_evidence_pipeline.py`
- Dashboard components for investigation evidence, knowledge and feedback.
- Audit documents under `docs/`.

Existing backend and dashboard modules were extended rather than replaced.

## Database changes

SQLite schema version reached 6. Additive tables include:

- `docker_events`
- `metric_samples`
- `operator_actions`
- `incident_audit`
- `knowledge_records`
- `knowledge_versions`
- `investigation_feedback`
- `evaluation_runs`

Existing incident and investigation records were preserved. SQLite integrity was checked as `ok` after migration, restart and restore.

## Exact validation commands

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
Get-ChildItem -Filter "*.py" | ForEach-Object { python -m py_compile $_.FullName }
npm.cmd run typecheck
npm.cmd run build
docker compose config --quiet
docker compose up --build -d
```

Production profile validation used explicit non-secret test values:

```powershell
$env:OLLAMA_URL="http://host.docker.internal:11434"
$env:CORS_ALLOWED_ORIGINS="http://127.0.0.1:3000"
$env:API_KEY="quality-gate-only-placeholder"
docker compose -f compose.production.yaml config --quiet
```

## Actual validation results

- Host backend suite passed 23 tests.
- Python compilation passed.
- Frontend type checking passed.
- Frontend production builds passed.
- Local and production Compose configuration validated.
- Backend health returned API/Docker/Ollama `ok/connected/connected`.
- Compose backend and dashboard services started successfully.
- SQLite integrity was `ok` at schema 6.
- Existing incidents and investigations remained present after migrations and restart.
- Historical metric API returned live persisted samples and network throughput rates.
- Evidence and incident timeline APIs passed.
- Knowledge approval/search/version APIs passed.
- Feedback and correction proposal APIs passed.
- Evaluation API completed 4/4 cases and stored the report.
- Remediation status reported disabled with no autonomous execution.
- Docker provider reported connected; Kubernetes and AWS reported unconfigured.
- Backup and restore scripts both executed successfully; post-restore SQLite integrity was `ok`.
- Desktop browser validation showed live container data, charts and evidence panels.
- A 390 px viewport request was rendered with a 300 px CSS viewport and no document overflow.

## Defects found and fixed

- Host test suite initially found a Windows SQLite connection-cleanup issue. Connections now commit/rollback and close explicitly.
- Frontend lifecycle, knowledge and feedback handler scope defects were found by TypeScript checking and corrected.
- A knowledge type declaration brace was misplaced and corrected.
- A temporary unavailable-log handling defect was corrected so no log payload key is required for missing logs.
- A 422 comment API check used invalid shell JSON and was rerun with valid PowerShell JSON serialization.
- Production Compose correctly rejected missing required environment variables; this is intentional and was resolved by explicit profile validation values.

## Known limitations

## Independent quality audit findings

## Phase A/B/C runtime audit

VERIFIED:
- Docker Desktop daemon was stopped and restarted successfully.
- Docker Engine 29.3.1 and Docker Desktop 4.66.1 were reachable after recovery.
- Ollama remained available separately and Qwen 2.5 3B (`357c53fb659c`) was listed.
- Local Compose started without deleting volumes or resetting SQLite.
- Backend and dashboard containers reported healthy and remained on localhost ports.
- Backend restart, dashboard restart and both-container restart preserved incidents
  and knowledge; metric samples continued accumulating.
- Docker daemon outage was observed with backend ports unavailable and Ollama
  independently reachable.
- Docker recovery restored backend, dashboard, collector and monitor behavior.
- Ollama outage returned timeout, backend health remained API/Docker-ok and
  Ollama-not-connected, and a forced investigation completed after Ollama recovery.
- Invalid Ollama endpoint was tested; health reported connection refused and the
  API remained responsive.
- Event collector was running and deduplicated events after restarts.
- Browser automation verified desktop and 390 px requested viewport rendering
  with no document horizontal overflow. The browser engine rendered a 300 px CSS
  viewport for the narrow layout.
- Browser reload showed no console errors, page errors or failed requests.

VERIFIED real-model:
- Qwen 2.5 3B handled a real `/analyze` request successfully.
- Incident 10 was investigated with real Ollama inference. Investigation 21
  completed with status `completed`, medium confidence, and the result named
  explicit operator context as probable rather than an independently verified fact.
- Investigation 22 was queued during Ollama outage and completed after recovery.

FAILED / defect status:
- No reproducible application defect was found in the Docker/Ollama recovery,
  persistence or browser checks.
- The plain shell `curl` 422 encountered during QA was a malformed PowerShell
  request body, not a backend defect; the valid `Invoke-RestMethod` call passed.
- Local Compose has `API_KEY=""`, so optional API-key middleware is disabled for
  this profile. Production Compose requires an API key.

BLOCKED:
- A browser workflow action that requires a real operator to perform a mutation
  was not claimed if only synthetic API calls were used.
- Production TLS, MFA and RBAC are not implemented.

- SQLite migration is additive and existing-record-preserving; foreign keys,
  WAL and busy timeout are now explicitly enabled. Partial duplicate active
  incident reconciliation remains operator-visible work for legacy data.
- Concurrent incident creation is guarded by a write transaction and a partial
  unique index when the migration can create it safely.
- Incident lifecycle transitions are centrally validated.
- Docker socket mounts are read-only in both Compose profiles.
- API-key middleware protects mutations and knowledge routes; it is not a
  complete authentication or authorization system.
- TLS, MFA, RBAC and secrets-manager integration are not implemented.
- Production Compose remains blocked without real secrets and an externally
  reachable Ollama endpoint.
- Live Docker and Ollama checks returned unavailable while the Docker daemon
  was stopped. Docker, Ollama and full Compose restart recovery are therefore
  BLOCKED, while provider and health failure behavior passed synthetic/unit checks.
- Evaluation is a deterministic fixture regression, not real-model accuracy.
- Browser automation was not performed in this audit. Host dashboard serving
  and `/api/health` proxying were verified with HTTP checks.

- Kubernetes and AWS provider implementations require external credentials/clusters and were not claimed implemented.
- Full role-based authorization, MFA and a secrets manager are not implemented.
- No infrastructure-changing remediation executes.
- Docker event history begins only when the event collector is running.
- Historical metric samples are limited by 7-day/100,000-row retention.
- Ollama is optional external infrastructure and unavailable behavior is handled but external model accuracy cannot be guaranteed.
- Browser tests were local and were not a security or production-readiness assessment.
- PostgreSQL migration guidance is not implemented.
