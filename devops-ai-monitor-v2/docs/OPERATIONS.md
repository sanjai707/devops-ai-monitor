# Operations Baseline

## Local startup

```powershell
cd D:\devops-ai-monitor-v2\devops-ai-monitor-v2
docker compose config --quiet
docker compose up --build -d
```

## Health checks

```powershell
curl.exe http://127.0.0.1:8000/health
curl.exe http://127.0.0.1:8000/monitor/status
curl.exe http://127.0.0.1:8000/evidence/status
curl.exe http://127.0.0.1:3000
```

## Persistence

- `monitor-data` is the named volume for `/data/incidents.db`.
- Do not reset or remove the volume during upgrades.
- Back up the volume or database before major migrations.

## Restart behavior

- Processing investigations are reset to pending on worker startup.
- The Docker monitor restarts its polling loop.
- The Docker event collector reconnects with bounded backoff.

## Validation status and evidence

Latest local validation was performed on 2026-11-26 against commit
`1c14e38175caead06a89ce88600fa791cd25a0c5`. These results describe this local
run; they are not a production-readiness claim.

VERIFIED:

- `python -m unittest discover -s tests -p "test_*.py" -v`: **44 tests passed**.
- Top-level Python compilation, `npm.cmd run typecheck`, and `npm.cmd run build`
  passed.
- `docker compose config --quiet`,
  `docker compose --profile telemetry config --quiet`, and production Compose
  validation with explicit non-secret placeholder values passed.
- Core Compose services were healthy on `127.0.0.1:8000` and
  `127.0.0.1:3000`. `/health` reported API, Docker and Ollama connected;
  monitor and event collector were running without errors after scenario cleanup.
- All five labeled Docker scenarios (stopped, restart loop, unhealthy, high CPU
  and high memory) generated matching incidents. Only the disposable labeled
  containers were removed; incident and evidence records were retained.
- A fresh stopped-container investigation received one operator-approved
  timestamped log line and completed reassessment #55. The result included the
  collected marker and retained low confidence / unknown termination intent.
- Real `qwen2.5:3b` evaluation completed five curated cases. It reports actual
  model outputs, but leaves root-cause accuracy unscored because there are no
  independently adjudicated labels.
- Live browser smoke checks covered desktop and narrow layouts; no console,
  page errors, failed requests or horizontal overflow were observed. The
  requested 390 px viewport rendered as 300 px CSS width in this environment.
- Docker daemon outage/recovery and Ollama timeout, invalid endpoint and
  recovery behavior were exercised in the preceding runtime pass.

DEFECT REPRODUCED AND FIXED:

- The first approved log follow-up returned one item, but reassessment #53
  failed with `KeyError: 'line'`: evidence assembly expected `payload.line`
  while approved logs are stored as `payload.result.lines`.
- `ai_investigator.py` now accepts both evidence shapes, and
  `test_collected_followup_logs_are_included_in_reassessment_evidence` covers
  the regression. The focused 13-test follow-up suite and full 44-test suite
  passed. The post-fix live follow-up and reassessment completed successfully.
- The failed pre-fix record is intentionally retained for auditability. The
  previous Docker-events follow-up for incident 22 also remains
  `unavailable` with zero matching items; it was not treated as successful.

DATABASE SNAPSHOT:

- SQLite schema version 8; `PRAGMA integrity_check` returned `ok`.
- Counts at capture: 35 incidents, 49 investigations (46 completed, 3 failed),
  28,560 metric samples, 193 Docker events, 2 knowledge records, 3 knowledge
  versions, 2 feedback records, 2 evaluation runs and 3 follow-ups.
- Failed investigation records include historical model-output validation
  failure #7 and `KeyError: 'line'` records #13 and #53. These rows were not
  deleted; the same follow-up path passed after the fix as investigation #55.

BLOCKED / NOT VERIFIED:

- Root-cause accuracy, confidence calibration and unsupported-claim rates for
  a real deployment model are not established by five fixture inferences.
- The actual dashboard button click for approving a follow-up was not exercised;
  approval and reassessment were verified via the local API. The browser check
  is a UI smoke check, not an end-to-end operator workflow test.
- Local `API_KEY` is empty, so local API-key enforcement is disabled. Production
  validation used a placeholder only; no real production secret, TLS, RBAC or
  MFA deployment was tested.
- Kubernetes/AWS, PostgreSQL migration, multi-instance operation and external
  production recovery remain unverified or unimplemented.

## Current branch validation commands

Run from `devops-ai-monitor-v2`:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
npm.cmd --prefix frontend run typecheck
npm.cmd --prefix frontend run build
docker compose config --quiet
docker compose --profile telemetry config --quiet
```

Python compilation can be checked with:

```powershell
Get-ChildItem -Filter "*.py" | ForEach-Object { python -m py_compile $_.FullName }
```

The GitHub Actions workflow also installs Chromium and runs the Playwright
dashboard test. The local Docker scenario runner and actual Ollama evaluation
are intentionally opt-in because they create load or invoke the local model.

## SQLite production limitations

SQLite is suitable for a single-node local deployment, but is not a
multi-instance transactional database platform. It requires a persistent volume,
bounded writes and coordinated backups. PostgreSQL migration requirements:

- Add per-table migrations and a migration lock/version mechanism.
- Use a PostgreSQL connection pool and transactions with foreign-key constraints.
- Replace SQLite-specific JSON storage and partial indexes with PostgreSQL
  equivalents or compatible indexes.
- Add replication, PITR, monitoring and backup retention.
- Re-run incident/knowledge/evaluation data migration and integrity validation
  against a copy before cutover.

## Optional OpenTelemetry pipeline (local-only)

The telemetry profile is opt-in. Normal Compose startup does not start the
Collector, Prometheus or Grafana.

1. Copy `.env.example` to `.env` if needed.
2. Set `OTEL_ENABLED=true` and change `GRAFANA_ADMIN_PASSWORD`.
3. Start the core stack and telemetry profile:

```powershell
docker compose --profile telemetry up --build -d
docker compose --profile telemetry ps
```

Local interfaces:

- Grafana: http://127.0.0.1:3001
- Prometheus: http://127.0.0.1:9090
- OTLP/HTTP receiver: http://127.0.0.1:4318
- OTLP/gRPC receiver: 127.0.0.1:4317
- API telemetry status: http://127.0.0.1:8000/telemetry/status

The FastAPI service exports HTTP request metrics and traces. Outbound HTTPX
requests, including Ollama API calls, are traced. The Docker monitor also exports
per-container CPU utilization, memory utilization, running state and restart count
gauges; observations expire when a container stops being observed. Prometheus retains metrics for
7 days in the `prometheus-data` volume. Grafana is provisioned with a dashboard
for request rate, p95 latency and HTTP 5xx rate.

Host applications can export OTLP to localhost:4318 (HTTP) or localhost:4317
(gRPC). Containers on this Compose network should use
`http://otel-collector:4318`.

This first phase persists metrics in Prometheus. Traces are debug-exported to
Collector logs and are not yet retained in a trace database. OTLP application
logs are not enabled in this phase.

Stop the optional telemetry services without deleting their data:

```powershell
docker compose --profile telemetry stop grafana prometheus otel-collector
```