# Hash ZIP: API oficial astral-sh/uv, release 0.9.7.
# Hash EXE: entrada uv.exe derivada desse ZIP verificado.
function Get-VerifiedUv {
    param([Parameter(Mandatory=$true)][string]$ToolsDir)
    $ErrorActionPreference = 'Stop'
    $zipHash = '5d250c32d3604e28dbe18dc65c668ff628c53e00dde2c642576e831e4a60da64'
    $exeHash = '83e0f3a8b7aaf0224fe7e915c3249b085b41c7a1ab00aeba95fc52c05334a3db'
    $archive = Join-Path $ToolsDir 'uv.zip'
    $executable = Join-Path $ToolsDir 'uv\uv.exe'
    if ((Test-Path -LiteralPath $archive) -and (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash -ne $zipHash) {
        throw 'Integridade do ZIP uv invalida; arquivo nao sera extraido.'
    }
    if (Test-Path -LiteralPath $executable) {
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $executable).Hash -ne $exeHash) {
            throw 'Integridade do executavel uv invalida; arquivo nao sera executado.'
        }
        return $executable
    }
    New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
    if (-not (Test-Path -LiteralPath $archive)) {
        $download = Join-Path $ToolsDir ('uv-' + [guid]::NewGuid().ToString() + '.download')
        try {
            & curl.exe --fail --location --retry 2 'https://github.com/astral-sh/uv/releases/download/0.9.7/uv-x86_64-pc-windows-msvc.zip' --output $download
            if ($LASTEXITCODE -ne 0) { throw 'Falha no download do uv.' }
            if ((Get-FileHash -Algorithm SHA256 -LiteralPath $download).Hash -ne $zipHash) {
                throw 'Integridade do download uv invalida.'
            }
            Move-Item -LiteralPath $download -Destination $archive
        } finally {
            if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download }
        }
    }
    Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $ToolsDir 'uv') -Force
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $executable).Hash -ne $exeHash) {
        throw 'Integridade do uv extraido invalida.'
    }
    return $executable
}
