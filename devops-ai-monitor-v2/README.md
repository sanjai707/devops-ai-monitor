# DevOps AI Monitor v0.4

Read-only Docker monitoring with local Ollama analysis.

## What's new
- Added a responsive React/Vite NOC dashboard at `http://127.0.0.1:3000`.
- Added a 10-second background Docker monitoring engine.
- Added persistent SQLite incident storage and incident lifecycle APIs.
- Added CPU, memory, stopped-container, restart-count, and Docker health-check detections.
- Newly created incidents are queued for sequential investigation by the configured local Ollama model.
- Docker events and timestamped container metrics are continuously stored in bounded SQLite history for investigation context.
- Investigations combine event history, metrics, sanitized inspection data, bounded timestamped logs, and incident records into a correlated evidence timeline.
- Model findings and recommendations must cite collected evidence; invalid references are removed and confidence is calculated from independent sources and contradictions.
- The investigation panel shows evidence references, timeline, collection limitations, confidence rationale, and risk-rated advisory actions.
- `GET /containers/{container_id}/diagnostics` returns container state, exit code, OOM status, restart count, health status, restart policy, and timestamps.
- `GET /containers/{container_id}/metrics` returns a read-only CPU, memory and cumulative network snapshot for running containers.
- `POST /analyze` now sends both Docker metadata and recent logs to Qwen.
- The analysis prompt distinguishes evidence from hypotheses and avoids claiming the initiator of a SIGTERM without evidence.

## Prerequisites
- Docker Desktop Linux engine running
- Ollama running on Windows
- `qwen2.5:3b` available locally

## Start / update

From the project directory, build the Vite dashboard bundle once, then start both Compose services:

```powershell
cd D:\devops-ai-monitor-v2\devops-ai-monitor-v2\frontend
npm.cmd install
npm.cmd run build
cd ..
docker compose up --build -d
docker compose ps
```

The NOC dashboard is available at http://127.0.0.1:3000. The lightweight frontend service serves the compiled Vite bundle and proxies `/api` requests to the existing backend container; the backend remains available at http://127.0.0.1:8000.

The dashboard includes a live container inventory and details, CPU/memory history charts, cumulative network byte totals, incident filters and lifecycle actions, and AI investigation results/history. It reads all operational data from the existing FastAPI APIs; it does not implement monitoring logic or execute remediation in the browser. The frontend API base defaults to `/api`; in Compose, `BACKEND_API_URL` configures the server-side proxy target.

To run the Vite development server directly on Windows, from `D:\devops-ai-monitor-v2\devops-ai-monitor-v2\frontend`:

```powershell
npm.cmd install
$env:VITE_BACKEND_PROXY_TARGET = "http://127.0.0.1:8000"
npm.cmd run dev -- --host 127.0.0.1
```

For production-like Compose serving, rebuild `frontend\dist` with `npm.cmd run build` before `docker compose up --build -d`. The Compose frontend service serves the compiled bundle and proxies requests to `devops-ai-monitor`; it is bound to localhost on port 3000.

## Test

Automated backend regression:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
npm.cmd --prefix frontend run typecheck
npm.cmd --prefix frontend run build
docker compose config --quiet
```

The backend test suite includes 28 tests covering
database concurrency/migrations/retention/backup, incident and knowledge
lifecycle, feedback, evidence validation, prompt-injection boundaries,
authentication, remediation and expanded deterministic evaluation cases.

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/containers | Format-Table id,name,image,status
Invoke-RestMethod http://127.0.0.1:8000/containers/jenkins/diagnostics | Format-List
Invoke-RestMethod http://127.0.0.1:8000/containers/devops-ai-monitor/metrics | Format-List
```

The metrics endpoint is available only while a container is running. Docker reports cumulative network byte totals since container network interfaces were created.

Analyze Jenkins:

```powershell
$body = @{ container_id = "jenkins"; tail = 150 } | ConvertTo-Json
$result = Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/analyze `
  -ContentType "application/json" `
  -Body $body

$result.diagnostics | Format-List
$result.analysis
```

Swagger UI: http://127.0.0.1:8000/docs

## Optional OpenTelemetry observability

The free, self-hosted telemetry profile adds FastAPI request metrics and traces,
outbound HTTPX traces (including Ollama calls), Docker container CPU/memory,
running-state and restart-count gauges, an OTLP Collector, Prometheus and a
provisioned Grafana dashboard. It is disabled during normal Compose
startup. Prometheus keeps 7 days of metrics; traces are currently debug-exported
to Collector logs and are not persisted to a trace database. Application OTLP
logs are not enabled yet.

Create a local environment file and replace the Grafana password:

```powershell
Copy-Item .env.example .env
notepad .env
```

Set `OTEL_ENABLED=true` and a new `GRAFANA_ADMIN_PASSWORD`, then run:

```powershell
docker compose --profile telemetry up --build -d
Invoke-RestMethod http://127.0.0.1:8000/telemetry/status
```

Open Grafana at http://127.0.0.1:3001, Prometheus at
http://127.0.0.1:9090, and use http://127.0.0.1:4318 as the OTLP/HTTP receiver
for host applications. Containers on the Compose network should export to
`http://otel-collector:4318`. The Collector ports and dashboards are bound to
localhost; do not expose them to untrusted networks.

The profile adds local CPU, memory and disk use, but no hosted telemetry account
or paid service. Use `docker compose --profile telemetry stop grafana prometheus
otel-collector` to stop the optional services without deleting their data.


## Monitoring and incidents

The background monitor polls Docker every 10 seconds by default. It evaluates CPU and memory thresholds, container state transitions, restart-count increases, and Docker health-check status. Newly created incidents are added to a persistent SQLite investigation queue; repeated polls do not submit unchanged incidents again. One background worker runs inference sequentially with a bounded retry count and cooldown. Ollama failures are recorded against the investigation and do not stop Docker polling.

```powershell
Invoke-RestMethod http://127.0.0.1:8000/monitor/status
Invoke-RestMethod http://127.0.0.1:8000/incidents
Invoke-RestMethod http://127.0.0.1:8000/incidents/active
Invoke-RestMethod http://127.0.0.1:8000/investigations/status
Invoke-RestMethod http://127.0.0.1:8000/investigations
Invoke-RestMethod http://127.0.0.1:8000/evidence/status
```

Retrieve or manually queue an incident investigation:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/incidents/1/investigation
Invoke-RestMethod -Method Post http://127.0.0.1:8000/incidents/1/investigate
```

To explicitly create a new investigation attempt for an incident, append `?force=true` to the POST URL. Investigation output is JSON and marks root-cause assessments as unconfirmed. Facts and recommendations without valid collected evidence references are omitted; confidence is constrained by evidence diversity, collection completeness, and contradictions. Corrective actions remain advisory and always require human approval.

The Docker event collector reconnects with bounded backoff and deduplicates replayed events. SQLite retains Docker events for 14 days (maximum 20,000) and metric samples for 7 days (maximum 100,000); these defaults are configurable with `DOCKER_EVENT_RETENTION_DAYS` and `METRIC_RETENTION_DAYS`. Investigation evidence windows default to 10 minutes before and 5 minutes after the incident. Recent stdout/stderr logs are time-bounded, size-limited, and redacted. Container environment variables are never collected. Network metrics remain cumulative byte counters; they are not reported as throughput.

The additive evidence, incident audit, knowledge, feedback and evaluation tables are created automatically on startup; existing incidents and investigation history are preserved. SQLite `user_version` is advanced to 6 for the current schema. When known action intent matters, record an explicit bounded annotation through `POST /incidents/{id}/operator-actions`; a Docker stop/kill event by itself remains intent-unknown.

Example explicit test-harness context (this records a supplied annotation only; it does not stop or change a container):

```powershell
$context = @{
  action = "stop"
  action_result = "succeeded"
  actor = "test harness"
  context = "Container was intentionally stopped by this controlled test."
  source = "test_harness"
  occurred_at = "2026-11-21T15:34:14Z"
} | ConvertTo-Json

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/incidents/10/operator-actions `
  -ContentType "application/json" `
  -Body $context
```

Incident lifecycle:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8000/incidents/1/acknowledge
Invoke-RestMethod -Method Post http://127.0.0.1:8000/incidents/1/resolve
```

SQLite persists in the `monitor-data` Docker named volume at `/data/incidents.db`. Rebuild and restart with:

```powershell
cd D:\devops-ai-monitor-v2\devops-ai-monitor-v2
docker compose up --build -d
docker compose ps
```

## Security
- API binds to `127.0.0.1:8000`.
- Dashboard binds to `127.0.0.1:3000`.
- Docker socket access is powerful. This app currently implements read-only operations; do not expose it publicly.
- Logs may contain secrets or personal data. Review/redact sensitive logs before sending them to a model.
- Treat AI output as a hypothesis, not an authoritative incident finding. Require human approval for remediation.