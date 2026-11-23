param(
    [string]$OutputDirectory = ".\backups",
    [string]$ComposeService = "devops-ai-monitor"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$destination = Join-Path (Resolve-Path $OutputDirectory) "incidents-$timestamp.db"

docker exec $ComposeService python -c "import sqlite3; source=sqlite3.connect('/data/incidents.db'); target=sqlite3.connect('/tmp/incidents-backup.db'); source.backup(target); target.close(); source.close()"
docker cp "${ComposeService}:/tmp/incidents-backup.db" $destination
docker exec $ComposeService rm -f /tmp/incidents-backup.db

python -c "import sqlite3,sys; db=sqlite3.connect('file:'+sys.argv[1].replace(chr(92),'/')+'?mode=ro',uri=True); result=db.execute('PRAGMA integrity_check').fetchone()[0]; db.close(); print(result); raise SystemExit(0 if result == 'ok' else 1)" $destination

Write-Output $destination
