# Run from a source checkout. The dashboard always binds to Windows loopback.
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
uv sync --frozen --no-dev --python 3.12
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Push-Location frontend
try {
    npm.cmd ci
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    npm.cmd run build
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
Write-Host 'NetScope  http://127.0.0.1:8765'
& .\.venv\Scripts\python.exe -m netscope
exit $LASTEXITCODE
