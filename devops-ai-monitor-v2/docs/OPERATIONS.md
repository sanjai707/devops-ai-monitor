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

## Independent audit status

- 23 backend tests passed using isolated SQLite databases.
- TypeScript typecheck and frontend production build passed.
- Local and production Compose files parsed successfully.
- Host live API returned `api: ok`; Docker and Ollama were unavailable because
  the Docker daemon was stopped and no Ollama service was reachable.
- Host dashboard and `/api/health` proxy returned HTTP 200.
- Docker recovery, Ollama outage/recovery and browser-console validation were
  completed and are VERIFIED.
- Live frontend mutation workflows and external TLS/RBAC deployment remain
  BLOCKED or unimplemented.

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
requests, including Ollama API calls, are traced. Prometheus retains metrics for
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
