[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param()

$ErrorActionPreference = "Stop"
$Label = "devops.ai.monitor.test=true"

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker Engine is unavailable. Start Docker Desktop and retry."
}

$ids = @(docker ps -aq --filter "label=$Label")
if ($LASTEXITCODE -ne 0) {
    throw "Unable to list labelled test containers."
}
if ($ids.Count -eq 0) {
    Write-Host "No labelled DevOps AI Monitor test containers found."
    return
}

foreach ($id in $ids) {
    if ($PSCmdlet.ShouldProcess($id, "Remove labelled test container")) {
        docker rm -f $id
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to remove container $id"
        }
    }
}
