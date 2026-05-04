param(
    [int]$Port = 8088
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
$clients = New-Object System.Collections.Generic.List[System.Net.Sockets.TcpClient]

try {
    $listener.Start()
    Write-Host "Listening on TCP port $Port. Press Ctrl+C to stop."

    while ($true) {
        while ($listener.Pending()) {
            $client = $listener.AcceptTcpClient()
            $clients.Add($client)
            Write-Host "Accepted connection from $($client.Client.RemoteEndPoint)"
        }

        for ($i = $clients.Count - 1; $i -ge 0; $i--) {
            if (-not $clients[$i].Connected) {
                $clients[$i].Dispose()
                $clients.RemoveAt($i)
            }
        }

        Start-Sleep -Milliseconds 100
    }
}
finally {
    foreach ($client in $clients) {
        $client.Dispose()
    }
    $listener.Stop()
}
