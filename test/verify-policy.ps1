$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Policy.ps1')

function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -cne $Expected) { throw ('Failed: ' + $Message + '. Actual: ' + $Actual) }
}

$now = [DateTimeOffset]::UtcNow
$observed = [pscustomobject]@{
    Fingerprint='current'; Country='JP'; IP='1.2.3.4'; At=$now.ToString('o'); Tun=45; Core=1234
}
Assert-Equal (Get-ProtectionReason 'current' 45 1234 $observed $now) '' 'allow Japanese exit with live TUN'
if (!(Get-ProtectionReason 'current' 45 0 $observed $now)) { throw 'No VPN opened' }
if (!(Get-ProtectionReason 'current' 0 1234 $observed $now)) { throw 'TUN disabled opened' }
if (!(Get-ProtectionReason '' 45 1234 $observed $now)) { throw 'Stale OS adapter opened with TUN switched off' }
if (!(Get-ProtectionReason 'different' 45 1234 $observed $now)) { throw 'Changed node opened' }
if (!(Get-ProtectionReason 'current' 46 1234 $observed $now)) { throw 'Changed TUN opened' }
if (!(Get-ProtectionReason 'current' 45 1235 $observed $now)) { throw 'Restarted core opened' }
if (!(Get-ProtectionReason 'current' 45 1234 $observed ($now.AddSeconds(8)))) { throw 'Expired sample opened' }
$observed.Country = 'US'
if (!(Get-ProtectionReason 'current' 45 1234 $observed $now)) { throw 'Wrong country opened' }
if (!(Get-ProtectionReason 'current' 45 1234 $null $now)) { throw 'Missing proof opened' }
$proof = Read-ExitTrace ('loc=JP' + [Environment]::NewLine + 'ip=1.2.3.4')
Assert-Equal $proof.Country 'JP' 'parse two trace fields'
if (Read-ExitTrace 'ip=1.2.3.4') { throw 'Invalid trace accepted' }

$path = Join-Path $PSScriptRoot ('guard-policy-test-' + [Guid]::NewGuid().ToString('N') + '.json')
try {
    $preferences = @{
        'flutter.selectedNodeUUID' = 'node-one'
        'flutter.proMode' = $false
        'flutter.tunMode' = $true
        'flutter.autoSysProxy' = $true
        'flutter.mode' = 1
    }
    Write-AtomicJson $path $preferences
    $before = Read-ViewTurboMode $path
    if (!$before) { throw 'Valid preferences rejected' }
    $preferences['flutter.autoSysProxy'] = $false
    Write-AtomicJson $path $preferences
    if ((Read-ViewTurboMode $path) -ne $before) { throw 'Changing system proxy required a manual pin' }
    $preferences['flutter.selectedNodeUUID'] = 'node-two'
    Write-AtomicJson $path $preferences
    if ((Read-ViewTurboMode $path) -eq $before) { throw 'Node switch undetected' }
    $preferences['flutter.tunMode'] = $false
    Write-AtomicJson $path $preferences
    if (Read-ViewTurboMode $path) { throw 'Disabled TUN accepted' }
} finally {
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
}
$config = New-EngineConfig (Read-Policy) 'test' 59832 59833
$tun = $config.inbounds | Where-Object tag -eq 'guard-tun'
if ($tun.dns_mode -ne 'disabled' -or '0.0.0.0/0' -in $tun.route_address -or '::/0' -in $tun.route_address -or
    '8.8.8.0/24' -notin $tun.route_address -or $script:FakeV4 -notin $tun.route_address) {
    throw 'Selective TUN routing policy changed.'
}
Write-Output 'PASS four-state policy, client toggle and route changes, stale/foreign proof, selective routes.'
