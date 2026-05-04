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

if (-not (Test-IsAdministrator)) {
    throw "Run this script from an Administrator PowerShell session so it can remove Windows Firewall rules."
}

if (Test-Path $ConfigPath) {
    $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    $prefix = [string]$config.FirewallRulePrefix
}
else {
    $prefix = "PCDDoSGuard"
}

$rules = @(Get-NetFirewallRule -DisplayName "$prefix-*" -ErrorAction SilentlyContinue)
if ($rules.Count -eq 0) {
    Write-Host "No $prefix firewall rules were found."
    return
}

if ($DryRun) {
    $rules | Select-Object DisplayName, Enabled, Direction, Action
    return
}

$rules | Remove-NetFirewallRule
Write-Host "Removed $($rules.Count) $prefix firewall rule(s)."
