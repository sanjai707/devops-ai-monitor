# DevOps AI Monitor v0.2

Read-only Docker monitoring with local Ollama analysis.

## What's new
- `GET /containers/{container_id}/diagnostics` returns container state, exit code, OOM status, restart count, restart policy, and timestamps.
- `POST /analyze` now sends both Docker metadata and recent logs to Qwen.
- The analysis prompt distinguishes evidence from hypotheses and avoids claiming the initiator of a SIGTERM without evidence.

## Prerequisites
- Docker Desktop Linux engine running
- Ollama running on Windows
- `qwen2.5:3b` available locally

## Start / update

From this folder in PowerShell:

```powershell
docker compose up --build -d
docker compose ps
```

## Test

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/containers | Format-Table id,name,image,status
Invoke-RestMethod http://127.0.0.1:8000/containers/jenkins/diagnostics | Format-List
```

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

## Security
- API binds to `127.0.0.1:8000`.
- Docker socket access is powerful. This app currently implements read-only operations; do not expose it publicly.
- Logs may contain secrets or personal data. Review/redact sensitive logs before sending them to a model.
- Treat AI output as a hypothesis, not an authoritative incident finding. Require human approval for remediation.
