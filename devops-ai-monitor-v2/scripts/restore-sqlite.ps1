param(
    [Parameter(Mandatory=$true)]
    [string]$BackupFile,
    [string]$ComposeService = "devops-ai-monitor"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $BackupFile)) {
    throw "Backup file not found: $BackupFile"
}

$resolved = (Resolve-Path $BackupFile).Path
docker cp $resolved "${ComposeService}:/tmp/incidents-restore.db"
docker exec $ComposeService python -c "import sqlite3; source=sqlite3.connect('/tmp/incidents-restore.db'); target=sqlite3.connect('/data/incidents.db'); source.backup(target); target.close(); source.close()"
docker exec $ComposeService rm -f /tmp/incidents-restore.db
docker exec $ComposeService python -c "import sqlite3; db=sqlite3.connect('/data/incidents.db'); result=db.execute('PRAGMA integrity_check').fetchone()[0]; db.close(); print(result); raise SystemExit(0 if result == 'ok' else 1)"

Write-Output "SQLite database restored from $resolved"
