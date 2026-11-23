# Architecture Baseline

## Runtime

- FastAPI application (`main.py`) exposes monitoring, incident, investigation, evidence, and operator-action APIs.
- `DockerMonitor` polls Docker every 10 seconds and creates incident records through `IncidentManager`.
- `DockerEventCollector` runs as a daemon thread, reconnecting to the Docker event stream with bounded backoff.
- `IncidentInvestigator` uses a single serialized worker thread and calls Ollama `qwen2.5:3b`.
- `IncidentDatabase` owns SQLite persistence in the `monitor-data` volume.
- React/Vite serves the NOC dashboard and accesses FastAPI through the same-origin `/api` proxy.

## Dependency boundaries

- Docker SDK is used by monitor, event collector, and investigation evidence collection.
- Ollama is called only from the investigation/analyze path.
- SQLite is the local persistence and initial knowledge/telemetry store.
- The frontend has no monitoring or incident-detection logic.

## Baseline state

- Docker Desktop and both Compose services were not available at the start of the quality gate.
- Docker Desktop was restarted successfully.
- Compose configuration, health, container, incident, monitor, investigation, evidence, and dashboard proxy APIs are now responding.
- Baseline unit discovery found an SQLite connection-cleanup defect on Windows, which is being corrected in the database compatibility layer.

## Preservation rules

- Existing API fields and endpoints remain available.
- Existing incident and investigation records remain in SQLite.
- Ollama model remains `qwen2.5:3b`.
- Remediation is advisory only until a separately approved allowlisted implementation exists.
