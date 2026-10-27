$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $projectRoot

if ((& node --version) -notmatch '^v24\.') {
    throw 'Este pacote requer Node.js 24.x.'
}
if ((& node -p 'process.arch') -ne 'x64') { throw 'Este pacote requer Windows x64.' }

New-Item -ItemType Directory -Force lab | Out-Null
$archive = Join-Path $projectRoot 'lab\juice-shop-20.3.0_node24_win32_x64.zip'
$expectedHash = 'a25fc33b3b3565aae52381f63e6c9727790f67e8443ead02803a8eec7bdb7f57'
if (-not (Test-Path -LiteralPath $archive)) {
    & curl.exe --fail --location --retry 2 `
        'https://github.com/juice-shop/juice-shop/releases/download/v20.3.0/juice-shop-20.3.0_node24_win32_x64.zip' `
        --output $archive
    if ($LASTEXITCODE -ne 0) { throw 'Falha no download do Juice Shop.' }
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
    throw 'SHA-256 incorreto. Remova o arquivo ZIP e repita o download.'
}

if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    throw 'Execute scripts/setup-python.ps1 antes de instalar o laboratorio.'
}
if (Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue) {
    throw 'Encerre a instancia da porta 3000 antes de reinstalar o laboratorio.'
}
# zipfile preserva nomes Unicode que o tar nativo omite nesta distribuicao.
& .\.venv\Scripts\python.exe -m zipfile -e $archive lab
if ($LASTEXITCODE -ne 0) { throw 'Falha ao extrair o Juice Shop.' }
Write-Host 'Juice Shop instalado em lab. Execute scripts/start-juice-shop.ps1.'
