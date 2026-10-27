param([string]$Url = 'http://localhost:3000/rest/products/search?q=apple')

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $projectRoot
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    throw 'Prepare o ambiente com scripts/setup-python.ps1.'
}

$previousUtf8 = $env:PYTHONUTF8
$env:PYTHONUTF8 = '1'
try {
    Write-Host '1. Verificacao de conectividade e referencias normais'
    & $python main.py $Url --module baseline --samples 2 --output reports/demo-baseline.json
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host "`n2. SQLi controlada: referencias, controles, pares booleanos e recuperacao"
    & $python main.py $Url --module sqli --samples 2 --max-requests 10 --output reports/demo-sqli.json
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $report = Get-Content -Raw -Encoding UTF8 -LiteralPath reports/demo-sqli.json | ConvertFrom-Json
    Write-Host "`n3. Criterios de classificacao registrados no JSON"
    $report.assessment.checks | Format-List | Out-Host
    Write-Host "Resultado observado: $($report.assessment.outcome)"
    Write-Host 'Relatorios: reports/demo-baseline.json e reports/demo-sqli.json'
} finally {
    $env:PYTHONUTF8 = $previousUtf8
}
