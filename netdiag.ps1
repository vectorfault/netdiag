# netdiag.ps1
# Lightweight Windows network and host diagnostics utility
# Outputs JSON or human-readable text
# No admin rights required for core functionality

[CmdletBinding()]
param(
    [ValidateSet("json","text")]
    [string]$Format = "json",

    # DNS resolution tests
    [string[]]$TestDns = @(
        "github.com",
        "chocolatey.org"
    ),

    # Optional features
    [switch]$IncludePublicIp,
    [switch]$IncludeListeningPorts
)

$ErrorActionPreference = "Stop"

function Get-Uptime {
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $uptime = (Get-Date) - $os.LastBootUpTime
        return @{
            lastBoot = $os.LastBootUpTime.ToString("o")
            uptimeSeconds = [int]$uptime.TotalSeconds
        }
    } catch {
        return $null
    }
}

function Get-NetworkAdapters {
    $out = @()
    try {
        $configs = Get-NetIPConfiguration | Where-Object {
            $_.NetAdapter -and $_.NetAdapter.Status -eq "Up"
        }

        foreach ($c in $configs) {
            $out += @{
                name       = $c.InterfaceAlias
                ifIndex    = $c.InterfaceIndex
                mac        = $c.NetAdapter.MacAddress
                ipv4       = @($c.IPv4Address | ForEach-Object { $_.IPAddress })
                ipv6       = @($c.IPv6Address | ForEach-Object { $_.IPAddress })
                gateway    = @($c.IPv4DefaultGateway | ForEach-Object { $_.NextHop })
                dnsServers = @($c.DnsServer.ServerAddresses)
            }
        }
    } catch {}
    return $out
}

function Get-WifiInfo {
    try {
        $raw = netsh wlan show interfaces 2>$null
        if (-not $raw) { return $null }

        $ssidMatch = ($raw | Select-String '^\s*SSID\s*:\s*(.+)$' | Select-Object -First 1)
        if (-not $ssidMatch) { return $null }

        $ssid = $ssidMatch.Matches.Groups[1].Value
        if ([string]::IsNullOrWhiteSpace($ssid)) { return $null }

        $bssidMatch  = ($raw | Select-String '^\s*BSSID\s*:\s*(.+)$' | Select-Object -First 1)
        $signalMatch = ($raw | Select-String '^\s*Signal\s*:\s*(.+)$' | Select-Object -First 1)
        $radioMatch  = ($raw | Select-String '^\s*Radio type\s*:\s*(.+)$' | Select-Object -First 1)

        return @{
            ssid      = $ssid.Trim()
            bssid     = if ($bssidMatch) { $bssidMatch.Matches.Groups[1].Value.Trim() } else { $null }
            signal    = if ($signalMatch) { $signalMatch.Matches.Groups[1].Value.Trim() } else { $null }
            radioType = if ($radioMatch) { $radioMatch.Matches.Groups[1].Value.Trim() } else { $null }
        }
    } catch {
        return $null
    }
}

function Resolve-DnsNameSafe {
    param([string]$Name)
    try {
        $ips = [System.Net.Dns]::GetHostAddresses($Name) |
            ForEach-Object { $_.IPAddressToString }

        return @{
            name = $Name
            ok = $true
            addresses = $ips
        }
    } catch {
        return @{
            name = $Name
            ok = $false
            error = $_.Exception.Message
        }
    }
}

function Get-PublicIp {
    try {
        $resp = Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 5
        return @{ ip = $resp.ip }
    } catch {
        return @{ error = $_.Exception.Message }
    }
}

function Get-ListeningTcpPorts {
    try {
        $ports = Get-NetTCPConnection -State Listen |
            Sort-Object LocalPort -Unique |
            Select-Object LocalAddress, LocalPort, OwningProcess

        return @($ports | ForEach-Object {
            @{
                localAddress = $_.LocalAddress
                localPort    = $_.LocalPort
                pid          = $_.OwningProcess
            }
        })
    } catch {
        return $null
    }
}

# -------------------------------
# Build output
# -------------------------------

$os = $null
try { $os = Get-CimInstance Win32_OperatingSystem } catch {}

$arch = $null
try { $arch = (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty AddressWidth) } catch {}

$result = @{
    generatedAt  = (Get-Date).ToString("o")
    computerName = $env:COMPUTERNAME
    userName     = "$env:USERDOMAIN\$env:USERNAME"
    os = if ($os) {
        @{
            caption      = $os.Caption
            version      = $os.Version
            buildNumber  = $os.BuildNumber
            architecture = $arch
        }
    } else { $null }
    uptime   = Get-Uptime
    adapters = Get-NetworkAdapters
    wifi     = Get-WifiInfo
    dnsTests = @($TestDns | ForEach-Object { Resolve-DnsNameSafe $_ })
}

if ($IncludePublicIp) {
    $result.publicIp = Get-PublicIp
}

if ($IncludeListeningPorts) {
    $result.listeningTcp = Get-ListeningTcpPorts
}

# -------------------------------
# Output
# -------------------------------

if ($Format -eq "json") {
    $result | ConvertTo-Json -Depth 6
} else {
    Write-Host "netdiag - $( $result.generatedAt )"
    Write-Host "Host: $( $result.computerName )"
    Write-Host "User: $( $result.userName )"

    if ($result.os) {
        Write-Host "OS: $( $result.os.caption )  Version: $( $result.os.version )  Build: $( $result.os.buildNumber )  Arch: $( $result.os.architecture )"
    }

    if ($result.uptime) {
        Write-Host "Last Boot: $( $result.uptime.lastBoot )"
        Write-Host "Uptime (s): $( $result.uptime.uptimeSeconds )"
    }

    Write-Host "`nNetwork Adapters:"
    foreach ($a in $result.adapters) {
        Write-Host " - $($a.name) (MAC $($a.mac))"
        Write-Host "   IPv4: $([string]::Join(', ', $a.ipv4))"
        Write-Host "   GW:   $([string]::Join(', ', $a.gateway))"
        Write-Host "   DNS:  $([string]::Join(', ', $a.dnsServers))"
    }

    if ($result.wifi) {
        Write-Host "`nWi-Fi:"
        Write-Host " SSID:   $($result.wifi.ssid)"
        if ($result.wifi.signal)    { Write-Host " Signal: $($result.wifi.signal)" }
        if ($result.wifi.radioType) { Write-Host " Radio:  $($result.wifi.radioType)" }
    }

    Write-Host "`nDNS Tests:"
    foreach ($d in $result.dnsTests) {
        if ($d.ok) {
            Write-Host " - $($d.name): $([string]::Join(', ', $d.addresses))"
        } else {
            Write-Host " - $($d.name): FAILED ($($d.error))"
        }
    }

    if ($IncludePublicIp -and $result.publicIp) {
        Write-Host "`nPublic IP:"
        if ($result.publicIp.ip) { Write-Host " - $($result.publicIp.ip)" }
        elseif ($result.publicIp.error) { Write-Host " - ERROR: $($result.publicIp.error)" }
    }

    if ($IncludeListeningPorts -and $result.listeningTcp) {
        Write-Host "`nListening TCP Ports:"
        foreach ($p in $result.listeningTcp) {
            Write-Host " - $($p.localAddress):$($p.localPort) (PID $($p.pid))"
        }
    }
}
