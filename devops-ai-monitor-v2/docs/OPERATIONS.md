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
