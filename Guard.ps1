param(
    [ValidateSet('Install','Status','Uninstall','Run')]
    [string]$Action = 'Status',
    [string]$EngineArchive
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')
$installation = Join-Path $env:ProgramFiles 'GoogleJpGuard'
$taskName = 'GoogleJpGuard'
$dnsRule = 'GoogleJpGuard: protected domains'
$policyFile = Join-Path $installation 'policy.json'
$statusFile = Join-Path $installation 'status.json'
$engine = Join-Path $installation 'bin\sing-box.exe'
$proxyPort = 15732
$corePath = Join-Path $env:ProgramFiles 'ViewTurboLite\ViewTurboCore-x86_64-pc-windows-msvc.exe'
$markFile = Join-Path $installation 'install.json'
$script:engineProcess = $null
$script:engineJob = $null
$script:engineException = [IntPtr]::Zero
$script:tunException = [IntPtr]::Zero
$script:selector = 'closed'
$script:token = ''
$script:controlPort = 0
$script:proofPort = 0
$viewTurboAddress = '127.0.0.1:15732'
$managedAddress = '127.0.0.1:' + $script:ManagedProxyPort
$proxyRegistry = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$script:checkedCore = 0
$script:trustedCore = $false

function Read-Json([string]$Path) {
    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        try {
            $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
            $reader = [IO.StreamReader]::new([IO.File]::Open($Path, 'Open', 'Read', $share))
            try { return ($reader.ReadToEnd() | ConvertFrom-Json) } finally { $reader.Dispose() }
        } catch [IO.IOException] {
            if ($attempt -eq 4) { throw }
            Start-Sleep -Milliseconds 35
        }
    }
}

function Require-Admin {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this command in an Administrator PowerShell window.'
    }
}

function Set-PrivateDirectory([string]$Path) {
    [IO.Directory]::CreateDirectory($Path) | Out-Null
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        $aclRule = [Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $security.AddAccessRule($aclRule)
    }
    Set-Acl -LiteralPath $Path -AclObject $security
}

function Publish-Status([string]$State, [string]$Reason, $Observation) {
    Write-AtomicJson $statusFile ([ordered]@{
        State = $State
        Reason = $Reason
        Updated = [DateTimeOffset]::UtcNow.ToString('o')
        VerifiedAt = $(if ($Observation) { $Observation.At } else { '' })
        ObservedCountry = $(if ($Observation) { $Observation.Country } else { '' })
        ObservedIP = $(if ($Observation) { $Observation.IP } else { '' })
    })
}

function Get-LoopbackPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return $listener.LocalEndpoint.Port
    } finally { $listener.Stop() }
}

function Invoke-GuardApi([string]$Method, [string]$Target = '') {
    $url = 'http://127.0.0.1:' + $script:controlPort + '/proxies/google-gate'
    $request = [Net.HttpWebRequest]::Create($url)
    $request.Proxy = $null
    $request.Method = $Method
    $request.Headers['Authorization'] = 'Bearer ' + $script:token
    $request.Timeout = 1000
    $request.ReadWriteTimeout = 1000
    if ($Target) {
        $body = [Text.Encoding]::UTF8.GetBytes(('{"name":"' + $Target + '"}'))
        $request.ContentType = 'application/json'
        $request.ContentLength = $body.Length
        $stream = $request.GetRequestStream()
        try { $stream.Write($body, 0, $body.Length) } finally { $stream.Dispose() }
    }
    $response = $request.GetResponse()
    try {
        if ($Method -eq 'GET') {
            $reader = [IO.StreamReader]::new($response.GetResponseStream())
            try { return ($reader.ReadToEnd() | ConvertFrom-Json).now } finally { $reader.Dispose() }
        }
    } finally { $response.Dispose() }
}

function Set-Selector([string]$Target) {
    if ($script:selector -eq $Target) { return }
    Invoke-GuardApi 'PUT' $Target
    if ((Invoke-GuardApi 'GET') -ne $Target) { throw 'Engine did not confirm the selected route.' }
    $script:selector = $Target
}

function Start-Child([string]$Executable, [string]$Arguments, [switch]$Capture) {
    $info = [Diagnostics.ProcessStartInfo]::new($Executable, $Arguments)
    $info.WorkingDirectory = $installation
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $Capture
    $info.RedirectStandardError = $Capture
    $info.EnvironmentVariables['GOMAXPROCS'] = '4'
    $process = [Diagnostics.Process]::Start($info)
    try { $process.PriorityClass = [Diagnostics.ProcessPriorityClass]::BelowNormal } catch {}
    return $process
}

function Stop-Engine {
    if ($script:engineJob) {
        $script:engineJob.Dispose()
        $script:engineJob = $null
    }
    if ($script:engineProcess) {
        if (!$script:engineProcess.HasExited) {
            try { $script:engineProcess.Kill() } catch {}
            $null = $script:engineProcess.WaitForExit(3000)
        }
        $script:engineProcess.Dispose()
        $script:engineProcess = $null
    }
    if ($script:tunException -ne [IntPtr]::Zero) {
        try { [PacketGuard]::Close($script:tunException) } catch {}
        $script:tunException = [IntPtr]::Zero
    }
    if ($script:engineException -ne [IntPtr]::Zero) {
        try { [PacketGuard]::Close($script:engineException) } catch {}
        $script:engineException = [IntPtr]::Zero
    }
    $script:selector = 'closed'
}

function Start-Engine($Policy) {
    $script:engineException = [PacketGuard]::AllowEngine($proxyPort, $engine)
    $script:engineJob = [EngineJob]::new()
    $script:token = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
    $script:controlPort = Get-LoopbackPort
    do { $script:proofPort = Get-LoopbackPort } while ($script:proofPort -eq $script:controlPort)
    $path = Join-Path $installation 'data\engine.json'
    Write-AtomicJson $path (New-EngineConfig $Policy $script:token $script:controlPort $script:proofPort)
    $script:engineProcess = Start-Child $engine ('run -c "' + $path + '"')
    $script:engineJob.Add($script:engineProcess)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(18)
    do {
        if ($script:engineProcess.HasExited) { throw ('Network engine exited with code ' + $script:engineProcess.ExitCode + '.') }
        $adapter = Get-NetAdapter -Name $script:TunName -ErrorAction SilentlyContinue
        if ($adapter -and $adapter.Status -eq 'Up') {
            try { $answer = Invoke-GuardApi 'GET' } catch { $answer = '' }
            if ($answer -eq 'closed') {
                $script:tunException = [PacketGuard]::AllowTun($adapter.ifIndex)
                return
            }
        }
        Start-Sleep -Milliseconds 450
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'Network engine did not start the protected network adapter.'
}

function Get-ViewTurboProcess {
    $candidateId = [WindowsNetwork]::LoopbackListener($proxyPort)
    if (!$candidateId) {
        $script:checkedCore = 0
        $script:trustedCore = $false
        return 0
    }
    if ($script:checkedCore -ne $candidateId -or !$script:trustedCore) {
        $candidate = Get-Process -Id $candidateId -ErrorAction SilentlyContinue
        $script:trustedCore = [bool]($candidate -and $candidate.Path -ieq $corePath)
        $script:checkedCore = $candidateId
    }
    if ($script:trustedCore) { return $candidateId }
    return 0
}

function Sync-SystemProxy([bool]$Restore = $false) {
    $current = Get-ItemProperty -Path $proxyRegistry -ErrorAction SilentlyContinue
    if (!$current -or !$current.PSObject.Properties['ProxyServer']) { return }
    if ($Restore) {
        if ($current.ProxyServer -eq $managedAddress) { [WindowsNetwork]::SetProxyServer($viewTurboAddress) }
        return
    }
    if ($current.ProxyServer -eq $viewTurboAddress -and $current.PSObject.Properties['ProxyEnable'] -and
        $current.ProxyEnable -eq 1) {
        [WindowsNetwork]::SetProxyServer($managedAddress)
        $actual = Get-ItemProperty -Path $proxyRegistry
        if ($actual.ProxyEnable -eq 1 -and $actual.ProxyServer -eq $viewTurboAddress) {
            throw 'Windows did not apply the local ViewTurbo proxy bridge.'
        }
    }
}

function Start-ExitCheck {
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    $arguments = '-q --noproxy "*" --connect-timeout 2 --max-time 4 --silent --show-error --fail --max-filesize 4096 ' +
        '--connect-to one.one.one.one:443:127.0.0.1:' + $script:proofPort + ' https://one.one.one.one/cdn-cgi/trace'
    $child = Start-Child $curl $arguments -Capture
    try { $script:engineJob.Add($child) } catch {
        if (!$child.HasExited) {
            $child.Kill()
            $child.Dispose()
            throw
        }
    }
    return [pscustomobject]@{
        Process = $child
        Output = $child.StandardOutput.ReadToEndAsync()
        Error = $child.StandardError.ReadToEndAsync()
    }
}

function Monitor-Engine($Policy, [string]$Preferences) {
    $check = $null
    $observation = $null
    $link = [LinkWatch]::new()
    $lastVersion = $link.Version
    $lastNode = ''
    $lastTun = 0
    $lastCore = 0
    $nextCheck = [DateTimeOffset]::MinValue
    $nextStatus = [DateTimeOffset]::MinValue
    $nextRules = [DateTimeOffset]::UtcNow.AddMinutes(3)
    try {
        while (!$script:engineProcess.HasExited) {
            $now = [DateTimeOffset]::UtcNow
            $node = Read-ViewTurboMode $Preferences
            $coreId = Get-ViewTurboProcess
            $tunIndex = if ($node -and $coreId) { [WindowsNetwork]::ViewTurboTunIndex() } else { 0 }
            $version = $link.Version
            $changed = $node -ne $lastNode -or $version -ne $lastVersion -or $tunIndex -ne $lastTun -or $coreId -ne $lastCore
            if ($changed) {
                Set-Selector 'closed'
                $observation = $null
                $nextCheck = [DateTimeOffset]::MinValue
                $lastNode = $node
                $lastVersion = $version
                $lastTun = $tunIndex
                $lastCore = $coreId
                if ($check) {
                    if (!$check.Process.HasExited) { try { $check.Process.Kill() } catch {} }
                    $check.Process.Dispose()
                    $check = $null
                }
            }
            if ($check -and $check.Process.HasExited) {
                $trace = if ($check.Process.ExitCode -eq 0) { Read-ExitTrace ($check.Output.GetAwaiter().GetResult()) } else { $null }
                $check.Process.Dispose()
                $check = $null
                if ($trace) {
                    $observation = [pscustomobject]@{
                        At = $now.ToString('o'); Country = $trace.Country; IP = $trace.IP
                        Fingerprint = $node; Tun = $tunIndex; Core = $coreId
                    }
                } else { $observation = $null }
            }
            $oldSelector = $script:selector
            $reason = Get-ProtectionReason $node $tunIndex $coreId $observation $now
            if ($reason) { Set-Selector 'closed' } else { Set-Selector 'viewturbo' }
            Sync-SystemProxy
            if ($now -ge $nextRules) {
                if (![PacketGuard]::HasRules([string[]]$Policy.guardPrefixes)) {
                    Set-Selector 'closed'
                    throw 'Persistent filter rules are missing.'
                }
                $nextRules = $now.AddMinutes(3)
            }
            if ($node -and $tunIndex -and $coreId -and !$check -and $now -ge $nextCheck) {
                $check = Start-ExitCheck
                $nextCheck = $now.AddSeconds(2)
            }
            if ($changed -or $oldSelector -ne $script:selector -or $now -ge $nextStatus) {
                $state = if ($script:selector -eq 'viewturbo') { 'Japan verified' } else { 'Google blocked' }
                Publish-Status $state $reason $observation
                $nextStatus = $now.AddSeconds(2)
            }
            Start-Sleep -Milliseconds 250
        }
        throw ('Network engine stopped with code ' + $script:engineProcess.ExitCode + '.')
    } finally {
        $link.Dispose()
        if ($check) {
            if (!$check.Process.HasExited) { try { $check.Process.Kill() } catch {} }
            $check.Process.Dispose()
        }
    }
}

function Add-BrowserDnsPolicy {
    foreach ($entry in @('Google\Chrome','Microsoft\Edge')) {
        $key = Join-Path 'HKLM:\SOFTWARE\Policies' $entry
        $previous = Get-ItemProperty -Path $key -Name DnsOverHttpsMode -ErrorAction SilentlyContinue
        if ($previous -and $previous.DnsOverHttpsMode -ne 'off') {
            throw ('Existing managed DNS over HTTPS policy in ' + $entry + '.')
        }
    }
    $registryChanges = @()
    foreach ($entry in @('Google\Chrome','Microsoft\Edge')) {
        $key = Join-Path 'HKLM:\SOFTWARE\Policies' $entry
        $previous = Get-ItemProperty -Path $key -Name DnsOverHttpsMode -ErrorAction SilentlyContinue
        if (!$previous) {
            $registryChanges += $key
            Write-AtomicJson (Join-Path $installation 'data\browser-policy.json') @{ Owned = @($registryChanges) }
            $null = New-Item -Path $key -Force
            $null = New-ItemProperty -Path $key -Name DnsOverHttpsMode -PropertyType String -Value 'off'
        }
    }
}

function Remove-BrowserDnsPolicy {
    $path = Join-Path $installation 'data\browser-policy.json'
    if (!(Test-Path -LiteralPath $path)) { return }
    foreach ($key in (Read-Json $path).Owned) {
        $previous = Get-ItemProperty -Path $key -Name DnsOverHttpsMode -ErrorAction SilentlyContinue
        if ($previous -and $previous.DnsOverHttpsMode -eq 'off') {
            Remove-ItemProperty -Path $key -Name DnsOverHttpsMode
        }
    }
}

function Remove-MachineSettings {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq 'Running') { Stop-ScheduledTask -TaskName $taskName }
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    Sync-SystemProxy $true
    Get-DnsClientNrptRule | Where-Object DisplayName -eq $dnsRule |
        ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
    Remove-BrowserDnsPolicy
    $rules = Read-Json $policyFile
    $prefixes = @(Get-GuardPrefixes $rules)
    [PacketGuard]::SetRules([string[]]$prefixes, $proxyPort, $corePath, $false)
    Clear-DnsClientCache
}

function Remove-InstallationFiles {
    $expected = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'GoogleJpGuard'))
    $resolved = (Resolve-Path -LiteralPath $installation).Path
    if ($resolved -ine $expected -or ((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Refusing to remove an unexpected installation path.'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Install-Guard {
    if (Test-Path -LiteralPath $installation) { throw 'GoogleJpGuard installation directory already exists. Run Uninstall before reinstalling.' }
    if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'The package requires Windows x64.' }
    $preferences = Join-Path $env:APPDATA 'VIEWTURBO PTE. LTD\ViewTurboLite\shared_preferences.json'
    if (!(Test-Path -LiteralPath $corePath) -or !(Test-Path -LiteralPath $preferences)) {
        throw 'ViewTurbo Lite was not found in the standard install location for this account.'
    }
    if ([WindowsNetwork]::LoopbackListener($script:ManagedProxyPort)) { throw 'The local guard proxy port is already in use.' }
    $archive = if ($EngineArchive) { $EngineArchive } else { Join-Path $PSScriptRoot 'engine.zip' }
    if (!(Test-Path -LiteralPath $archive)) { throw 'The official engine.zip is missing. See README.md.' }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash -ine $script:EngineDigest) {
        throw 'Network engine archive SHA-256 does not match the pinned official release.'
    }
    if (@(Get-DnsClientNrptRule).Count) { throw 'Existing Windows DNS routing policy found. Installation stopped before editing it.' }
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'A task with the same name already exists.' }
    $null = New-Item -ItemType Directory -Path $installation
    $settingsMayExist = $false
    try {
        Set-PrivateDirectory (Join-Path $installation 'data')
        $null = New-Item -ItemType Directory -Path (Join-Path $installation 'bin')
        foreach ($name in @('Guard.ps1','Policy.ps1','PacketGuard.cs','EngineJob.cs','WindowsNetwork.cs','policy.json','Guard.cmd')) {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $installation
        }
        $launcher = Join-Path $installation 'RunHidden.exe'
        Add-Type -Path @((Join-Path $PSScriptRoot 'RunHidden.cs'), (Join-Path $PSScriptRoot 'EngineJob.cs')) -OutputAssembly $launcher -OutputType WindowsApplication
        $user = [Security.Principal.WindowsIdentity]::GetCurrent()
        Write-AtomicJson $markFile @{ Preferences = $preferences; UserSid = $user.User.Value }
        $tar = Join-Path $env:SystemRoot 'System32\tar.exe'
        $archive = (Resolve-Path -LiteralPath $archive).Path
        $engineFolder = 'sing-box-' + $script:EngineVersion + '-windows-amd64'
        $entries = @('sing-box.exe','libcronet.dll','LICENSE') | ForEach-Object { $engineFolder + '/' + $_ }
        $result = & $tar -xf $archive --strip-components 1 -C (Join-Path $installation 'bin') @entries 2>&1
        if ($LASTEXITCODE -or !(Test-Path -LiteralPath $engine)) { throw ('Could not extract engine: ' + ($result -join ' ')) }
        $policy = Read-Policy
        $checkPath = Join-Path $installation 'data\config-check.json'
        Write-AtomicJson $checkPath (New-EngineConfig $policy ('check-' + [Guid]::NewGuid().ToString('N')) 56921 56922)
        try {
            $errors = & $engine check -c $checkPath 2>&1
            if ($LASTEXITCODE) { throw ('Network engine config check failed: ' + ($errors -join ' ')) }
        } finally { Remove-Item -LiteralPath $checkPath -Force }
        $settingsMayExist = $true
        [PacketGuard]::SetRules([string[]]@(Get-GuardPrefixes $policy), $proxyPort, $corePath, $true)
        $namespaces = foreach ($domain in $policy.domains) { $domain; '.' + $domain }
        Add-DnsClientNrptRule -DisplayName $dnsRule -Namespace $namespaces -NameServers $script:DnsAddress
        Add-BrowserDnsPolicy
        Clear-DnsClientCache
        $run = New-ScheduledTaskAction -Execute $launcher -WorkingDirectory $installation
        $startup = New-ScheduledTaskTrigger -AtLogOn -User $user.Name
        $identity = New-ScheduledTaskPrincipal -UserId $user.Name -LogonType Interactive -RunLevel Highest
        $options = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $taskName -Action $run -Trigger $startup -Principal $identity -Settings $options | Out-Null
        Start-ScheduledTask -TaskName $taskName
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 500
            if (Test-Path -LiteralPath $statusFile) {
                $status = Read-Json $statusFile
                if ($status.State -in @('Google blocked','Japan verified')) {
                    $answers = @(Resolve-DnsName 'gemini.google.com' -Type A -DnsOnly -NoHostsFile -ErrorAction Stop |
                        Where-Object Type -eq 'A')
                    if (!$answers.Count -or @($answers | Where-Object IPAddress -notlike '198.19.*').Count) {
                        throw 'Windows did not use protected DNS. Installation will roll back.'
                    }
                    Write-Output 'Installed. Google is automatically allowed with an active ViewTurbo TUN and a verified Japanese exit.'
                    return
                }
                if ($status.State -eq 'Engine stopped') { throw $status.Reason }
            }
        } while ([DateTimeOffset]::UtcNow -lt $deadline)
        throw 'Guard did not report a ready state before the timeout.'
    } catch {
        $installError = $_
        if ($settingsMayExist) {
            try { Remove-MachineSettings } catch { throw ('Installation failed: ' + $installError + ' Rollback failed: ' + $_ + '. Run Uninstall as administrator.') }
        }
        Remove-InstallationFiles
        throw $installError
    }
}

try {
    if ($Action -eq 'Status') {
        if (!(Test-Path -LiteralPath $statusFile)) { Write-Output 'Google JP Guard is not running. See README.md.'; return }
        $status = Read-Json $statusFile
        if (([DateTimeOffset]::UtcNow - [DateTimeOffset]::Parse($status.Updated)).TotalSeconds -gt 12) {
            Write-Output ('Guard status is stale. Last state: ' + $status.State)
            return
        }
        $status | Select-Object State,Reason,VerifiedAt,ObservedCountry,ObservedIP | Format-List
        return
    }
    Require-Admin
    Add-Type -Path (Join-Path $PSScriptRoot 'PacketGuard.cs')
    Add-Type -Path (Join-Path $PSScriptRoot 'WindowsNetwork.cs')
    if ($Action -eq 'Install') { Install-Guard; return }
    if (!(Test-Path -LiteralPath $markFile)) { throw 'Google JP Guard is not installed.' }
    $machineState = Read-Json $markFile
    if ($machineState.UserSid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
        throw 'Run from the same Windows account used for installation.'
    }
    switch ($Action) {
        'Run' {
            if ($PSScriptRoot -ine $installation) { throw 'Use the installed copy for Run.' }
            Add-Type -Path (Join-Path $PSScriptRoot 'EngineJob.cs')
            $policy = Read-Policy
            $policy | Add-Member NoteProperty guardPrefixes @(Get-GuardPrefixes $policy)
            [string]$preferences = $machineState.Preferences
            [Diagnostics.Process]::GetCurrentProcess().PriorityClass = 'BelowNormal'
            while ($true) {
                try {
                    if (![PacketGuard]::HasRules([string[]]$policy.guardPrefixes)) {
                        [PacketGuard]::SetRules([string[]]$policy.guardPrefixes, $proxyPort, $corePath, $true)
                    }
                    Start-Engine $policy
                    Monitor-Engine $policy $preferences
                } catch {
                    Stop-Engine
                    Publish-Status 'Engine stopped' $_.Exception.Message $null
                    Start-Sleep -Seconds 5
                } finally { Stop-Engine }
            }
        }
        'Uninstall' {
            Remove-MachineSettings
            Remove-InstallationFiles
            Write-Output 'Google JP Guard has been removed.'
        }
    }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
