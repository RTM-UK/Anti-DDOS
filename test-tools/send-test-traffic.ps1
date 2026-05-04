param(
    [Parameter(Mandatory = $true)]
    [string]$TargetIp,

    [int]$Port = 8088,
    [int]$Connections = 60,
    [int]$DelayMilliseconds = 25,
    [switch]$HoldOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$clients = New-Object System.Collections.Generic.List[System.Net.Sockets.TcpClient]

try {
    for ($i = 1; $i -le $Connections; $i++) {
        $client = [System.Net.Sockets.TcpClient]::new()
        $client.Connect($TargetIp, $Port)

        if ($HoldOpen) {
            $clients.Add($client)
        }
        else {
            $client.Dispose()
        }

        Write-Host "Opened connection $i of $Connections"
        Start-Sleep -Milliseconds $DelayMilliseconds
    }

    if ($HoldOpen) {
        Write-Host "Holding $($clients.Count) connection(s) open. Press Ctrl+C to close them."
        while ($true) {
            Start-Sleep -Seconds 1
        }
    }
}
finally {
    foreach ($client in $clients) {
        $client.Dispose()
    }
}
