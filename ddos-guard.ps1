param(
    [string]$ConfigPath = ".\config\ddos-guard.json",
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-GuardLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $logDir = Join-Path $PSScriptRoot "logs"
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory | Out-Null
    }

    $line = "{0} [{1}] {2}" -f (Get-Date).ToString("s"), $Level, $Message
    $line | Tee-Object -FilePath (Join-Path $logDir "ddos-guard.log") -Append
}

function Get-GuardConfig {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Config file not found: $Path"
    }

    $config = Get-Content -Path $Path -Raw | ConvertFrom-Json

    if ($config.SampleIntervalSeconds -lt 1) {
        throw "SampleIntervalSeconds must be at least 1."
    }
    if ($config.WindowSeconds -lt $config.SampleIntervalSeconds) {
        throw "WindowSeconds must be greater than or equal to SampleIntervalSeconds."
    }
    if ($config.MaxConnectionsPerWindow -lt 1 -or $config.MaxNewConnectionsPerWindow -lt 1) {
        throw "Connection thresholds must be positive."
    }
    if ($config.BlockMinutes -lt 1) {
        throw "BlockMinutes must be positive."
    }

    return $config
}

function Test-IsAllowedAddress {
    param(
        [string]$Address,
        [object]$Config
    )

    if ([string]::IsNullOrWhiteSpace($Address)) {
        return $true
    }
    if ($Address -eq "0.0.0.0" -or $Address -eq "::") {
        return $true
    }

    return @($Config.AllowList) -contains $Address
}

function Get-InboundConnections {
    param([object]$Config)

    $connections = Get-NetTCPConnection -State SynReceived, Established -ErrorAction SilentlyContinue |
        Where-Object {
            $_.RemoteAddress -and
            $_.RemoteAddress -ne "0.0.0.0" -and
            $_.RemoteAddress -ne "::" -and
            $_.RemoteAddress -ne "127.0.0.1" -and
            $_.RemoteAddress -ne "::1"
        }

    $ports = @($Config.ProtectedLocalPorts)
    if ($ports.Count -gt 0) {
        $portSet = @{}
        foreach ($port in $ports) {
            $portSet[[int]$port] = $true
        }
        $connections = $connections | Where-Object { $portSet.ContainsKey([int]$_.LocalPort) }
    }

    return @($connections)
}

function New-ConnectionKey {
    param($Connection)
    return "{0}|{1}|{2}|{3}" -f $Connection.RemoteAddress, $Connection.RemotePort, $Connection.LocalAddress, $Connection.LocalPort
}

function Add-TemporaryBlock {
    param(
        [string]$RemoteAddress,
        [object]$Config,
        [hashtable]$BlockedUntil,
        [switch]$DryRun
    )

    $expiresAt = (Get-Date).AddMinutes([int]$Config.BlockMinutes)
    $BlockedUntil[$RemoteAddress] = $expiresAt

    $ruleName = "{0}-{1}" -f $Config.FirewallRulePrefix, ($RemoteAddress -replace "[:\.]", "-")
    $message = "Blocking $RemoteAddress until $($expiresAt.ToString("s")) because it exceeded thresholds."

    if ($DryRun) {
        Write-GuardLog "$message DRY-RUN: firewall rule was not created." "WARN"
        return
    }

    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existingRule) {
        Set-NetFirewallRule -DisplayName $ruleName -Enabled True -Action Block | Out-Null
        Set-NetFirewallAddressFilter -AssociatedNetFirewallRule $existingRule -RemoteAddress $RemoteAddress | Out-Null
    }
    else {
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -Action Block `
            -RemoteAddress $RemoteAddress `
            -Profile Any `
            -Description "Temporary block created by PC DDoS Guard." | Out-Null
    }

    Write-GuardLog $message "WARN"
}

function Remove-ExpiredBlocks {
    param(
        [object]$Config,
        [hashtable]$BlockedUntil,
        [switch]$DryRun
    )

    $now = Get-Date
    $expired = @($BlockedUntil.Keys | Where-Object { $BlockedUntil[$_] -le $now })

    foreach ($remoteAddress in $expired) {
        $ruleName = "{0}-{1}" -f $Config.FirewallRulePrefix, ($remoteAddress -replace "[:\.]", "-")
        if (-not $DryRun) {
            Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        }
        $BlockedUntil.Remove($remoteAddress)
        Write-GuardLog "Removed expired block for $remoteAddress."
    }
}

if (-not (Test-IsAdministrator)) {
    throw "Run this script from an Administrator PowerShell session so it can manage Windows Firewall rules."
}

$config = Get-GuardConfig -Path $ConfigPath
$observations = @{}
$seenConnectionKeys = @{}
$blockedUntil = @{}
$window = [TimeSpan]::FromSeconds([int]$config.WindowSeconds)

Write-GuardLog "PC DDoS Guard started. DryRun=$DryRun WindowSeconds=$($config.WindowSeconds) BlockMinutes=$($config.BlockMinutes)"
Write-Host "PC DDoS Guard is running. Press Ctrl+C to stop."

while ($true) {
    $now = Get-Date
    Remove-ExpiredBlocks -Config $config -BlockedUntil $blockedUntil -DryRun:$DryRun

    foreach ($key in @($seenConnectionKeys.Keys)) {
        if ($seenConnectionKeys[$key] -lt $now.Subtract($window)) {
            $seenConnectionKeys.Remove($key)
        }
    }

    $connections = Get-InboundConnections -Config $config
    foreach ($connection in $connections) {
        $remoteAddress = [string]$connection.RemoteAddress
        if (Test-IsAllowedAddress -Address $remoteAddress -Config $config) {
            continue
        }
        if ($blockedUntil.ContainsKey($remoteAddress)) {
            continue
        }

        if (-not $observations.ContainsKey($remoteAddress)) {
            $observations[$remoteAddress] = New-Object System.Collections.Generic.List[object]
        }

        $connectionKey = New-ConnectionKey -Connection $connection
        $isNewConnection = -not $seenConnectionKeys.ContainsKey($connectionKey)
        $seenConnectionKeys[$connectionKey] = $now

        $observations[$remoteAddress].Add([pscustomobject]@{
            Time = $now
            IsNewConnection = $isNewConnection
        })
    }

    foreach ($remoteAddress in @($observations.Keys)) {
        $recent = @($observations[$remoteAddress] | Where-Object { $_.Time -ge $now.Subtract($window) })
        if ($recent.Count -eq 0) {
            $observations.Remove($remoteAddress)
            continue
        }

        $observations[$remoteAddress] = [System.Collections.Generic.List[object]]$recent
        $newConnectionCount = @($recent | Where-Object { $_.IsNewConnection }).Count

        if ($recent.Count -ge [int]$config.MaxConnectionsPerWindow -or
            $newConnectionCount -ge [int]$config.MaxNewConnectionsPerWindow) {
            Add-TemporaryBlock -RemoteAddress $remoteAddress -Config $config -BlockedUntil $blockedUntil -DryRun:$DryRun
            $observations.Remove($remoteAddress)
        }
    }

    Start-Sleep -Seconds ([int]$config.SampleIntervalSeconds)
}
