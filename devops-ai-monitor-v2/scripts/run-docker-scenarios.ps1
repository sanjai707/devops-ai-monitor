[CmdletBinding()]
param(
    [ValidateRange(10, 180)]
    [int]$ObservationSeconds = 45,
    [string]$Image = "busybox:1.36.1"
)

$ErrorActionPreference = "Stop"
$Label = "devops.ai.monitor.test=true"
$RunId = "$(Get-Date -Format 'yyyyMMddHHmmss')-$([guid]::NewGuid().ToString('N').Substring(0, 6))"
$Prefix = "devops-ai-test-$RunId"

Write-Host "Checking Docker Engine..."
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker Engine is unavailable. Start Docker Desktop and retry."
}

Write-Host "Checking test image $Image..."
$availableImages = @(docker image ls --format "{{.Repository}}:{{.Tag}}")
if ($LASTEXITCODE -ne 0) {
    throw "Unable to list local Docker images."
}
if ($availableImages -notcontains $Image) {
    Write-Host "Image not present locally; pulling $Image..."
    docker pull $Image
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to pull $Image. Check Docker Hub connectivity, proxy, VPN and firewall."
    }
}

function Start-TestContainer {
    param(
        [string]$Scenario,
        [string[]]$ExtraArgs,
        [string[]]$Command
    )

    $name = "$Prefix-$Scenario"
    $dockerArgs = @(
        "run", "-d",
        "--name", $name,
        "--label", $Label,
        "--label", "devops.ai.monitor.scenario=$Scenario"
    ) + $ExtraArgs + @($Image) + $Command

    & docker @dockerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create scenario $Scenario."
    }
    Write-Host "Created $Scenario : $name"
}

Write-Host "Creating isolated, labelled failure scenarios. No existing containers are changed."

Start-TestContainer -Scenario "stopped" -ExtraArgs @() -Command @("sh", "-c", "sleep 600")
# Let the monitor observe the running state before the controlled stop.
Start-Sleep -Seconds 12
docker stop "$Prefix-stopped" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Unable to stop stopped-scenario container." }

Start-TestContainer -Scenario "restart-loop" -ExtraArgs @("--restart", "on-failure:8") -Command @("sh", "-c", "sleep 12; exit 1")

Start-TestContainer -Scenario "unhealthy" -ExtraArgs @(
    "--health-cmd", "exit 1",
    "--health-interval", "5s",
    "--health-timeout", "2s",
    "--health-retries", "1",
    "--health-start-period", "0s"
) -Command @("sh", "-c", "sleep 600")

Start-TestContainer -Scenario "high-cpu" -ExtraArgs @("--cpus", "1.0") -Command @(
    "sh", "-c", "while :; do :; done"
)

Start-TestContainer -Scenario "high-memory" -ExtraArgs @(
    "--memory", "128m",
    "--tmpfs", "/memory:size=120m"
) -Command @(
    "sh", "-c",
    "dd if=/dev/zero of=/memory/probe bs=1M count=112 2>/dev/null; sleep 600"
)

Write-Host ""
Write-Host "Waiting $ObservationSeconds seconds for the monitor to observe scenarios..."
Start-Sleep -Seconds $ObservationSeconds

Write-Host ""
Write-Host "Scenario containers:"
docker ps -a --filter "label=$Label" --format "table {{.Names}}|{{.Status}}|{{.Image}}"

Write-Host ""
Write-Host "Incidents associated with this run:"
try {
    $incidents = Invoke-RestMethod "http://127.0.0.1:8000/incidents"
    $matched = @($incidents | Where-Object { $_.container_name -like "$Prefix-*" })
    if ($matched.Count -gt 0) {
        $matched | Select-Object id, container_name, type, severity, status, event_count |
            Format-Table -AutoSize
    } else {
        Write-Warning "No matching incidents were returned yet. Check /health, /monitor/status, and the scenario container states."
    }
} catch {
    Write-Warning "Could not query the monitor API: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "Run prefix: $Prefix"
Write-Host "Cleanup only these disposable labelled containers with:"
Write-Host "  ./scripts/cleanup-docker-scenarios.ps1"
