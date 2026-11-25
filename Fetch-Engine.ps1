param([string]$Destination = (Join-Path $PSScriptRoot 'engine.zip'))

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')
$Destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)
$expected = $script:EngineDigest
if (Test-Path -LiteralPath $Destination) {
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash -ine $expected) {
        throw 'Existing engine archive failed the SHA-256 check. Choose a fresh destination.'
    }
    Write-Output $Destination
    return
}

$version = $script:EngineVersion
$uri = "https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-windows-amd64.zip"
$temporary = $Destination + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
try {
    Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $temporary -TimeoutSec 600
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $temporary).Hash -ine $expected) {
        throw 'Downloaded engine archive failed the pinned SHA-256 check.'
    }
    [IO.File]::Move($temporary, $Destination)
    Write-Output $Destination
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
}
