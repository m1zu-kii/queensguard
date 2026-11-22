$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$spec = Join-Path $projectRoot "QueensGuard.spec"

if (!(Test-Path $python)) {
    throw "Project virtual-environment Python was not found: $python"
}
if (!(Test-Path $spec)) {
    throw "PyInstaller spec was not found: $spec"
}

Push-Location $projectRoot
try {
    & $python -m PyInstaller --clean --noconfirm --distpath (Join-Path $projectRoot "dist") --workpath (Join-Path $projectRoot "build") $spec
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
