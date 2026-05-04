# Anti-DDOS

Anti-DDOS is a Windows PC-hosted defensive tool that monitors inbound TCP connection activity and temporarily blocks source IP addresses that exceed configured traffic thresholds.

It includes two ways to run:

- `ddos-guard-gui.ps1`: graphical dashboard with live status, events, blocks, top source IPs, and a traffic graph.
- `ddos-guard.ps1`: command-line monitor for simple background-style use.

## Important Limitations

This tool protects the Windows PC it runs on. A normal PC cannot protect your entire home network unless it is acting as the router, gateway, bridge, or inline firewall.

For large volumetric DDoS attacks, traffic can fill your internet connection before it reaches your PC. Those attacks are best handled upstream by:

- your ISP
- your router/firewall
- a cloud DDoS protection provider
- hosting providers with built-in DDoS mitigation

Anti-DDOS is useful for learning, local testing, and reducing repeated inbound connection pressure against services hosted on your Windows machine.

## How It Works

Anti-DDOS samples inbound TCP connections using Windows networking information from `Get-NetTCPConnection`.

For each remote source IP, it tracks:

- total connection observations inside a rolling time window
- new connection observations inside that same window
- whether the source IP is allowlisted
- whether the source IP is already temporarily blocked

When a source IP crosses your configured threshold, Anti-DDOS creates a temporary inbound Windows Firewall block rule for that IP.

If `Dry run` is enabled, it reports what it would block without creating firewall rules.

## Files

- `ddos-guard-gui.ps1`: main graphical app.
- `ddos-guard.ps1`: command-line monitor.
- `run-ddos-guard.bat`: quick launcher for the GUI.
- `uninstall-ddos-guard.ps1`: removes firewall rules created by the tool.
- `config/ddos-guard.json`: thresholds, allowlist, protected ports, and block duration.
- `test-tools/start-test-listener.ps1`: opens a harmless local TCP listener for testing.
- `test-tools/send-test-traffic.ps1`: sends harmless test TCP connections.
- `logs/ddos-guard.log`: runtime event log.

## Requirements

- Windows 10 or Windows 11.
- Windows PowerShell 5.1.
- Administrator PowerShell session for real blocking.

If you are not running as Administrator, the GUI can still be used in `Dry run`, but it cannot create firewall rules.

## Start The GUI

Open PowerShell as Administrator.

Go to the project folder:

```powershell
cd C:\Users\raffe\Documents\Codex\2026-05-04\Anti-DDOS
```

Start the GUI:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ddos-guard-gui.ps1
```

You can also run:

```powershell
.\run-ddos-guard.bat
```

Keep the GUI open while you want monitoring active.

## GUI Controls

- `Dry run`: reports detections without creating firewall rules.
- `Pause`: temporarily stops monitoring.
- `Resume`: starts monitoring again after pausing.

The dashboard shows:

- `Status`: whether the tool is monitoring, paused, or reporting an error.
- `Current Connections`: current inbound TCP connections matching your config.
- `Active Blocks`: number of temporary blocks currently active.
- `Last Sample`: last time the tool checked network activity.
- `Inbound Connection Pressure`: live graph of connection activity.
- `Top Sources`: remote IPs with the most observed activity.
- `Attack and Block Events`: detection and block events.
- `Temporary Blocks`: IPs currently blocked and when their block expires.

## Recommended First Configuration

Before real use, edit:

```powershell
notepad .\config\ddos-guard.json
```

For safer testing, monitor only the test port:

```json
"ProtectedLocalPorts": [8088]
```

For general use, you can leave it empty to monitor all inbound TCP ports:

```json
"ProtectedLocalPorts": []
```

Be careful with low thresholds when monitoring all ports, because normal software may talk to cloud services and trigger alerts.

## Configuration Reference

`SampleIntervalSeconds`

How often Anti-DDOS samples inbound TCP activity.

`WindowSeconds`

The rolling time window used for counting connection observations.

`MaxConnectionsPerWindow`

Blocks an IP if total observations in the window reach this number.

`MaxNewConnectionsPerWindow`

Blocks an IP if new connection observations in the window reach this number.

`BlockMinutes`

How long a temporary block stays active.

`ProtectedLocalPorts`

Ports to monitor. Example:

```json
"ProtectedLocalPorts": [80, 443, 8088]
```

Use an empty list to monitor all inbound TCP ports:

```json
"ProtectedLocalPorts": []
```

`AllowList`

IP addresses that should never be blocked.

Example:

```json
"AllowList": [
  "127.0.0.1",
  "::1",
  "192.168.1.1"
]
```

`FirewallRulePrefix`

Prefix used for firewall rules created by the app. The uninstall script uses this prefix to remove created rules.

## Safe Test Procedure

Use three PowerShell windows.

Before testing, edit `config/ddos-guard.json`:

```json
"ProtectedLocalPorts": [8088],
"MaxConnectionsPerWindow": 10,
"MaxNewConnectionsPerWindow": 5
```

Restart the GUI after saving the config.

### Window 1: Start Test Listener

```powershell
cd C:\Users\raffe\Documents\Codex\2026-05-04\Anti-DDOS
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-tools\start-test-listener.ps1 -Port 8088
```

You should see:

```text
Listening on TCP port 8088
```

Leave this window open.

### Window 2: Start Anti-DDOS GUI

```powershell
cd C:\Users\raffe\Documents\Codex\2026-05-04\Anti-DDOS
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ddos-guard-gui.ps1
```

Turn on `Dry run` for the first test.

### Window 3: Send Test Traffic

Find your local IP address:

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "169.254*" -and $_.IPAddress -ne "127.0.0.1"} | Select-Object IPAddress, InterfaceAlias
```

Use the IP address shown for your active network adapter. Example:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-tools\send-test-traffic.ps1 -TargetIp 10.100.101.69 -Port 8088 -Connections 60 -HoldOpen
```

If the test works, the listener window will show accepted connections, and the GUI should show:

- the connection graph rising
- the source IP in `Top Sources`
- a new event in `Attack and Block Events`
- an entry in `Temporary Blocks`

Because `Dry run` is enabled, the tool will report the block but will not create a real firewall rule.

## Test Real Blocking

Only do this after dry-run testing works.

1. Start the listener.
2. Start the GUI as Administrator.
3. Turn `Dry run` off.
4. Send test traffic again.

Anti-DDOS should create a Windows Firewall rule that blocks the source IP temporarily.

To remove created rules manually:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall-ddos-guard.ps1
```

## Command-Line Mode

Run the non-GUI monitor:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ddos-guard.ps1
```

Run command-line mode safely without creating firewall rules:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ddos-guard.ps1 -DryRun
```

## Logs

Events are written to:

```text
logs/ddos-guard.log
```

View the latest log entries:

```powershell
Get-Content .\logs\ddos-guard.log -Tail 30
```

## Troubleshooting

`running scripts is disabled on this system`

Use the launch command with execution policy bypass:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ddos-guard-gui.ps1
```

`No such host is known`

You probably used placeholder text like `YOUR_PC_IP`. Replace it with your real local IP address.

`Connection attempt failed`

Check that the test listener is running and that you are using the right IP and port.

Run:

```powershell
Test-NetConnection YOUR_REAL_IP -Port 8088
```

You want:

```text
TcpTestSucceeded : True
```

Legitimate IPs are being blocked

Raise the thresholds or set `ProtectedLocalPorts` to only the ports you actually want to protect.

Need to remove blocks

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall-ddos-guard.ps1
```
