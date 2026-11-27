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

- Host backend suite passed 44 tests on the latest local run.
- Python compilation passed.
- Frontend type checking passed.
- Frontend production builds passed.
- Local and production Compose configuration validated.
- Backend health returned API/Docker/Ollama `ok/connected/connected`.
- Compose backend and dashboard services started successfully.
- SQLite integrity was `ok` at schema 8 on the latest local run (an earlier
  audit checked schema 6).
- Existing incidents and investigations remained present after migrations and restart.
- Historical metric API returned live persisted samples and network throughput rates.
- Evidence and incident timeline APIs passed.
- Knowledge approval/search/version APIs passed.
- Feedback and correction proposal APIs passed.
- The deterministic evaluation regression passed; the later real-model
  evaluation is recorded separately below.
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

## Latest runtime continuation — 2026-11-26

Status: **VERIFIED locally / NOT PRODUCTION READY**

Exact validation:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
Get-ChildItem -Filter "*.py" | ForEach-Object { python -m py_compile $_.FullName }
Set-Location frontend
npm.cmd run typecheck
npm.cmd run build
Set-Location ..
docker compose config --quiet
docker compose --profile telemetry config --quiet
docker compose -f compose.production.yaml config --quiet
python scripts/evaluate_ollama.py --model qwen2.5:3b --max-cases 5 --output reports/ollama-evaluation.json
```

Results:

- Backend: **44 passed, 0 failed**; Python compilation passed.
- Frontend typecheck and production build passed.
- Core, telemetry and production Compose configurations passed. Production
  configuration used non-secret placeholders and is not evidence of a deployed
  production environment.
- Docker and Ollama were independently connected after backend rebuild. The
  backend and dashboard were healthy; monitor and event collector reported
  running with no errors after cleanup.
- All five labeled Docker scenarios generated corresponding incidents. The
  disposable scenario containers were removed by exact ID after verification;
  their synthetic incidents and evidence remain in SQLite.
- SQLite schema version was 8 and integrity check returned `ok`. Counts at
  capture: 35 incidents, 49 investigations (46 completed, 3 failed), 28,560
  metric samples, 193 Docker events, 2 knowledge records, 3 knowledge versions,
  2 feedback records, 2 evaluation runs and 3 follow-ups. No database rows were
  deleted.
- The requested real-model evaluation completed 5/5 cases using Qwen 2.5 3B.
  `root_cause_accuracy` remains `null` because the fixture labels are not
  independently adjudicated. Completion is not an accuracy claim. The JSON
  output is saved at `reports/ollama-evaluation.json`.
- Existing live browser smoke checks found no console errors, page errors,
  failed requests or horizontal overflow in desktop/narrow layouts. The
  requested 390 px viewport was rendered at 300 px CSS width. Follow-up approval
  was exercised through the local API, not by clicking the dashboard control.

### Follow-up defect and regression

The first live approved log collection returned one item, but reassessment #53
failed with `KeyError: 'line'`. Ordinary log evidence uses `payload.line`, while
approved follow-up evidence stores lines under `payload.result.lines`.
`ai_investigator.py` now reads both forms; a focused regression test exercises
database-backed evidence assembly. The focused 13-test follow-up suite and full
44-test suite passed after the change. The rebuilt live service then completed
approved follow-up reassessment #55 and included the collected synthetic log
marker in its evidence inventory.

The pre-fix failure record remains in the database. Historical failures #7
(invalid model result) and #13 (`KeyError: 'line'`) also remain recorded; they
were not cleared or rewritten. A separate earlier Docker-events approval
remains `unavailable` with zero matching items. These failures are not counted
as passing follow-ups.

The real-model report's five cases produced conservative, low-confidence
assessments for exit-code-137/OOM-false and insufficient-evidence fixtures. The
verified-root-cause fixture received a probable, not confirmed, OOM assessment
with event evidence. These are qualitative observations only; no accuracy,
unsupported-claim or calibration rate is asserted.

### Remaining deployment blockers

- Local `API_KEY` is empty, so authentication was disabled in the live local
  profile. API-key middleware tests passed, but API keys do not provide user
  identity, RBAC or MFA.
- No production secrets, TLS termination, RBAC, MFA, rate limiting, PostgreSQL
  migration or multi-instance deployment was configured or verified.
- The successful five-case Ollama run does not establish real-world model
  accuracy. Human review and independently adjudicated evaluation cases are
  still required.
- Browser smoke checks do not prove the full dashboard approval, feedback and
  recovery workflows end to end.

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
- The dashboard's follow-up approval button was not exercised end-to-end in a
  browser; approval and reassessment were verified through the local API.
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
- Docker and Ollama were unavailable during an earlier outage test and later
  recovered; live Docker/Ollama, Compose startup and the five failure scenarios
  are now VERIFIED for this local run. This does not verify production recovery.
- Evaluation is a deterministic fixture regression, not real-model accuracy.
- Browser automation was performed for a local desktop/narrow smoke check, but
  not for the complete operator approval or feedback workflows.

- Kubernetes and AWS provider implementations require external credentials/clusters and were not claimed implemented.
- Full role-based authorization, MFA and a secrets manager are not implemented.
- No infrastructure-changing remediation executes.
- Docker event history begins only when the event collector is running.
- Historical metric samples are limited by 7-day/100,000-row retention.
- Ollama is optional external infrastructure and unavailable behavior is handled but external model accuracy cannot be guaranteed.
- Browser tests were local and were not a security or production-readiness assessment.
- PostgreSQL migration guidance is not implemented.
