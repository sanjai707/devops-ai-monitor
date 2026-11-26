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

The following are dated observations, not a claim that every feature in the
current branch has been exercised:

- On 2026-11-26, before the staged follow-up workflow was added, the developer
  ran the backend unittest discovery command locally: 26 tests passed. The
  command output is the evidence for that checkout only.
- On the same date, both `docker compose config --quiet` and
  `docker compose --profile telemetry config --quiet` completed without
  errors on the local checkout.
- The current feature branch subsequently added the approved follow-up
  collector/API, persistence and dashboard controls, eight follow-up tests,
  two previously undiscovered audit tests, a Playwright browser test, a live
  Ollama evaluation CLI, Docker scenario scripts and CI. These additions have
  **not yet been run in the user's local environment or reported green by CI**.
- Earlier type-check/build and API checks applied to a prior revision. Re-run
  the frontend checks on the current branch before treating the new UI as
  verified.
- Docker end-to-end scenarios and real Ollama inference evaluation remain
  pending. A prior local Docker image pull was interrupted with a CloudFront
  `EOF`; this is a registry/network transfer failure, not evidence that the
  Compose files or application started successfully.
- The browser test uses a controlled API fixture to exercise the dashboard
  interaction path. It is not a live Docker or Ollama test.
- The real-model evaluation returns actual Ollama responses for curated
  evidence fixtures, but does not report root-cause accuracy because there are
  no independently adjudicated labels.

## Current branch validation commands

Run from `devops-ai-monitor-v2`:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
npm.cmd --prefix frontend run typecheck
npm.cmd --prefix frontend run build
docker compose config --quiet
docker compose --profile telemetry config --quiet
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