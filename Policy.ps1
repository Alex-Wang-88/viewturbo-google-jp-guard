Set-StrictMode -Version Latest

$script:TunName = 'GoogleJpGuardScope'
$script:DnsAddress = '198.18.255.254'
$script:DnsPrefix = $script:DnsAddress + '/32'
$script:FakeV4 = '198.19.0.0/16'
$script:FakeV6 = 'fd63:aa85:1470:2::/96'
$script:ManagedProxyPort = 18732
$script:EngineVersion = '1.14.4'
$script:EngineDigest = '99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df'

function Read-Policy {
    Get-Content -LiteralPath (Join-Path $PSScriptRoot 'policy.json') -Raw | ConvertFrom-Json
}

function Get-GuardPrefixes($Policy) {
    @($Policy.prefixes) + @($script:FakeV4,$script:FakeV6,$script:DnsPrefix)
}

function Write-AtomicJson([string]$Path, [object]$Value) {
    $temp = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $content = $Value | ConvertTo-Json -Depth 35
    try {
        [IO.File]::WriteAllText($temp, $content, [Text.UTF8Encoding]::new($false))
        for ($attempt = 0; $attempt -lt 5; $attempt++) {
            try {
                if ([IO.File]::Exists($Path)) {
                    [IO.File]::Replace($temp, $Path, [Management.Automation.Language.NullString]::Value)
                } else {
                    [IO.File]::Move($temp, $Path)
                }
                break
            } catch [IO.IOException] {
                if ($attempt -eq 4) { throw }
                Start-Sleep -Milliseconds 40
            }
        }
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
}

function Read-ViewTurboMode([string]$Preferences) {
    try {
        $settings = Get-Content -LiteralPath $Preferences -Raw | ConvertFrom-Json
        $node = [string]$settings.'flutter.selectedNodeUUID'
        if (!$node -or $settings.'flutter.tunMode' -ne $true) { return $null }
        $hash = [Security.Cryptography.SHA256]::Create()
        try {
            $relay = if ($settings.'flutter.proMode' -and $settings.PSObject.Properties['flutter.selectedRelayUUID']) {
                [string]$settings.'flutter.selectedRelayUUID'
            } else { '' }
            $text = $node + '|' + $settings.'flutter.mode' + '|' + $relay
            return [Convert]::ToBase64String($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))
        } finally { $hash.Dispose() }
    } catch {
        return $null
    }
}

function Read-ExitTrace([string]$Text) {
    $country = @($Text -split '\r?\n' | Where-Object { $_ -cmatch '^loc=[A-Z]{2}$' })
    $lines = @($Text -split '\r?\n' | Where-Object { $_ -cmatch '^ip=[0-9a-fA-F:.]+$' })
    $ip = $null
    if ($country.Count -ne 1 -or $lines.Count -ne 1 -or
        ![Net.IPAddress]::TryParse($lines[0].Substring(3), [ref]$ip) -or
        [Net.IPAddress]::IsLoopback($ip)) {
        return $null
    }
    [pscustomobject]@{ Country = $country[0].Substring(4); IP = $ip.ToString() }
}

function Get-ProtectionReason([string]$Node, [int]$TunIndex, [int]$CoreId, $Observation, [DateTimeOffset]$Now) {
    if (!$CoreId) { return 'ViewTurbo local proxy is offline.' }
    if (!$Node -or !$TunIndex) { return 'ViewTurbo TUN is off or has no active route.' }
    if (!$Observation -or ($Now - [DateTimeOffset]::Parse($Observation.At)).TotalSeconds -gt 6 -or
        $Observation.Fingerprint -ne $Node -or $Observation.Tun -ne $TunIndex -or $Observation.Core -ne $CoreId) {
        return 'Waiting for Japanese exit verification through ViewTurbo.'
    }
    if ($Observation.Country -cne 'JP') { return ('ViewTurbo exit country is ' + $Observation.Country + '.') }
    return ''
}

function New-EngineConfig($Policy, [string]$Token, [int]$ControlPort, [int]$ProbePort,
    [int]$ViewTurboPort = 15732, [int]$ProxyListener = $script:ManagedProxyPort, [int]$LabDns = 0) {
    $guardPrefixes = @(Get-GuardPrefixes $Policy)
    $inbounds = @(
        @{ type = 'mixed'; tag = 'managed-proxy'; listen = '127.0.0.1'; listen_port = $ProxyListener },
        @{ type = 'direct'; tag = 'proof'; listen = '127.0.0.1'; listen_port = $ProbePort; network = 'tcp';
            override_address = 'one.one.one.one'; override_port = 443 }
    )
    if ($LabDns) {
        $inbounds += @{ type = 'direct'; tag = 'dns-in'; listen = '127.0.0.53'; listen_port = $LabDns }
        $dnsInboundRule = @{ inbound = 'dns-in'; action = 'hijack-dns' }
    } else {
        $inbounds += @{
            type = 'tun'
            tag = 'guard-tun'
            interface_name = $script:TunName
            address = @('172.30.198.1/30','fd63:aa85:1470:1::1/126')
            auto_route = $true
            strict_route = $false
            route_address = $guardPrefixes
            dns_mode = 'disabled'
            stack = 'gvisor'
        }
        $dnsInboundRule = @{ inbound = 'guard-tun'; ip_cidr = $script:DnsPrefix; port = 53; action = 'hijack-dns' }
    }
    $protected = @{
        type = 'logical'; mode = 'or'; rules = @(
            @{ domain_suffix = @($Policy.domains) },
            @{ ip_cidr = @($Policy.prefixes) }
        )
    }
    $config = [ordered]@{
        log = @{ disabled = $true }
        dns = @{
            servers = @(
                @{ type = 'local'; tag = 'unused-local' },
                @{ type = 'fakeip'; tag = 'google-fake'; inet4_range = $script:FakeV4; inet6_range = $script:FakeV6 }
            )
            rules = @(
                @{ domain_suffix = @($Policy.domains); query_type = @('A','AAAA'); action = 'route'; server = 'google-fake' },
                @{ domain_suffix = @($Policy.domains); action = 'predefined'; rcode = 'NOERROR' },
                @{ action = 'predefined'; rcode = 'REFUSED' }
            )
            final = 'unused-local'
        }
        inbounds = $inbounds
        outbounds = @(
            @{ type = 'block'; tag = 'closed' },
            @{ type = 'socks'; tag = 'viewturbo'; server = '127.0.0.1'; server_port = $ViewTurboPort;
                version = '5'; network = 'tcp' },
            @{ type = 'selector'; tag = 'google-gate'; outbounds = @('closed','viewturbo');
                default = 'closed'; interrupt_exist_connections = $true }
        )
        route = @{
            rules = @(
                $dnsInboundRule,
                @{ inbound = 'proof'; action = 'route'; outbound = 'viewturbo' },
                @{ inbound = 'guard-tun'; action = 'sniff'; timeout = '250ms' },
                # Keep DNS sent to Google Public DNS in the protected TCP path.
                @{ type = 'logical'; mode = 'and'; rules = @(@{ network = 'udp' }, $protected); action = 'reject' },
                ($protected + @{ action = 'route'; outbound = 'google-gate' }),
                @{ ip_cidr = @($script:FakeV4,$script:FakeV6); action = 'reject' },
                @{ inbound = 'managed-proxy'; action = 'route'; outbound = 'viewturbo' }
            )
            final = 'closed'
        }
        experimental = @{ clash_api = @{ external_controller = ('127.0.0.1:' + $ControlPort); secret = $Token } }
    }
    return $config
}
