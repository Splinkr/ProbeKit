param([switch]$Background)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$juiceRoot = Join-Path $projectRoot 'lab\juice-shop_20.3.0'
$preloader = Join-Path $PSScriptRoot 'loopback-only.cjs'
if (-not (Test-Path -LiteralPath (Join-Path $juiceRoot 'build\app.js'))) {
    throw 'Execute scripts/setup-juice-shop.ps1 antes de iniciar.'
}
if ((& node --version) -notmatch '^v24\.') { throw 'Use Node.js 24.x.' }
if (Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue) {
    throw 'A porta 3000 ja esta ocupada. Verifique o processo antes de iniciar outra instancia.'
}

$previousPort = $env:PORT
$env:PORT = '3000'
try {
    if ($Background) {
        $log = Join-Path $projectRoot 'lab\juice-shop.stdout.log'
        $errorLog = Join-Path $projectRoot 'lab\juice-shop.stderr.log'
        $process = Start-Process -FilePath (Get-Command node).Source `
            -ArgumentList @('--require', ('"' + $preloader + '"'), 'build/app') `
            -WorkingDirectory $juiceRoot -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $log -RedirectStandardError $errorLog
        $process.Id | Set-Content -LiteralPath (Join-Path $projectRoot 'lab\juice-shop.pid')
        Write-Host "Juice Shop iniciado com PID $($process.Id). URL: http://localhost:3000"
        Write-Host "Logs: $log e $errorLog"
    } else {
        Push-Location -LiteralPath $juiceRoot
        try { & node --require $preloader build/app }
        finally { Pop-Location }
    }
} finally {
    $env:PORT = $previousPort
}
