param([string]$PythonExe)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $projectRoot

if (-not $PythonExe) {
    $localPython = Join-Path $projectRoot '.tools\python\cpython-3.13.9-windows-x86_64-none\python.exe'
    if (Test-Path -LiteralPath $localPython) {
        $PythonExe = $localPython
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        $PythonExe = (Get-Command python).Source
    } else {
        # Bootstrap local: sem instalador global, registro ou alteracao do PATH.
        New-Item -ItemType Directory -Force .tools | Out-Null
        . (Join-Path $PSScriptRoot 'uv-integrity.ps1')
        $verifiedUv = Get-VerifiedUv -ToolsDir (Join-Path $projectRoot '.tools')
        $env:UV_PYTHON_INSTALL_DIR = Join-Path $projectRoot '.tools\python'
        $env:UV_CACHE_DIR = Join-Path $projectRoot '.tools\cache'
        & $verifiedUv python install 3.13.9 --no-bin
        if ($LASTEXITCODE -ne 0) { throw 'Falha na instalacao local do Python.' }
        $PythonExe = $localPython
    }
}

& $PythonExe --version
& $PythonExe -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Falha ao criar ambiente virtual.' }
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) { throw 'Falha ao instalar dependencias.' }
Write-Host 'Ambiente pronto: .\.venv\Scripts\python.exe'
