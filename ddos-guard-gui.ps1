param(
    [string]$ConfigPath = ".\config\ddos-guard.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms.DataVisualization

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
    Add-Content -Path (Join-Path $logDir "ddos-guard.log") -Value $line
    return $line
}

function Get-GuardConfig {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Config file not found: $Path"
    }

    $config = Get-Content -Path $Path -Raw | ConvertFrom-Json
    if ($config.SampleIntervalSeconds -lt 1) { throw "SampleIntervalSeconds must be at least 1." }
    if ($config.WindowSeconds -lt $config.SampleIntervalSeconds) { throw "WindowSeconds must be greater than or equal to SampleIntervalSeconds." }
    if ($config.MaxConnectionsPerWindow -lt 1 -or $config.MaxNewConnectionsPerWindow -lt 1) { throw "Connection thresholds must be positive." }
    if ($config.BlockMinutes -lt 1) { throw "BlockMinutes must be positive." }

    return $config
}

function Test-IsAllowedAddress {
    param(
        [string]$Address,
        [object]$Config
    )

    if ([string]::IsNullOrWhiteSpace($Address)) { return $true }
    if ($Address -eq "0.0.0.0" -or $Address -eq "::") { return $true }
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

function New-Label {
    param(
        [string]$Text,
        [int]$X,
        [int]$Y,
        [int]$Width,
        [int]$Height,
        [int]$Size = 10,
        [System.Drawing.Color]$Color
    )

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point($X, $Y)
    $label.Size = New-Object System.Drawing.Size($Width, $Height)
    $label.ForeColor = $Color
    $label.Font = New-Object System.Drawing.Font("Segoe UI", $Size, [System.Drawing.FontStyle]::Regular)
    $label.BackColor = [System.Drawing.Color]::Transparent
    return $label
}

function New-Panel {
    param(
        [int]$X,
        [int]$Y,
        [int]$Width,
        [int]$Height
    )

    $panel = New-Object System.Windows.Forms.Panel
    $panel.Location = New-Object System.Drawing.Point($X, $Y)
    $panel.Size = New-Object System.Drawing.Size($Width, $Height)
    $panel.BackColor = [System.Drawing.Color]::FromArgb(24, 32, 44)
    return $panel
}

function Set-GridStyle {
    param([System.Windows.Forms.DataGridView]$Grid)

    $Grid.BackgroundColor = [System.Drawing.Color]::FromArgb(16, 24, 34)
    $Grid.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $Grid.EnableHeadersVisualStyles = $false
    $Grid.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(32, 43, 59)
    $Grid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::FromArgb(230, 237, 247)
    $Grid.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $Grid.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(16, 24, 34)
    $Grid.DefaultCellStyle.ForeColor = [System.Drawing.Color]::FromArgb(220, 228, 238)
    $Grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(49, 92, 130)
    $Grid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $Grid.GridColor = [System.Drawing.Color]::FromArgb(43, 55, 72)
    $Grid.RowHeadersVisible = $false
    $Grid.AllowUserToAddRows = $false
    $Grid.AllowUserToDeleteRows = $false
    $Grid.AllowUserToResizeRows = $false
    $Grid.ReadOnly = $true
    $Grid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $Grid.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
}

function Add-EventRow {
    param(
        [string]$Level,
        [string]$Message
    )

    $script:eventsGrid.Rows.Insert(0, (Get-Date).ToString("HH:mm:ss"), $Level, $Message)
    while ($script:eventsGrid.Rows.Count -gt 200) {
        $script:eventsGrid.Rows.RemoveAt($script:eventsGrid.Rows.Count - 1)
    }
}

function Refresh-BlocksGrid {
    $script:blocksGrid.Rows.Clear()
    foreach ($address in ($script:blockedUntil.Keys | Sort-Object)) {
        $script:blocksGrid.Rows.Add($address, $script:blockedUntil[$address].ToString("HH:mm:ss"))
    }
    $script:blockedLabel.Text = [string]$script:blockedUntil.Count
}

function Refresh-TopTalkersGrid {
    $script:talkersGrid.Rows.Clear()
    $rows = foreach ($address in $script:observations.Keys) {
        $recent = @($script:observations[$address])
        [pscustomobject]@{
            Address = $address
            Total = $recent.Count
            New = @($recent | Where-Object { $_.IsNewConnection }).Count
        }
    }

    foreach ($row in @($rows | Sort-Object Total -Descending | Select-Object -First 8)) {
        $script:talkersGrid.Rows.Add($row.Address, $row.Total, $row.New)
    }
}

function Add-TemporaryBlock {
    param([string]$RemoteAddress)

    $expiresAt = (Get-Date).AddMinutes([int]$script:config.BlockMinutes)
    $script:blockedUntil[$RemoteAddress] = $expiresAt
    $ruleName = "{0}-{1}" -f $script:config.FirewallRulePrefix, ($RemoteAddress -replace "[:\.]", "-")
    $message = "Blocking $RemoteAddress until $($expiresAt.ToString("s")) because it exceeded thresholds."

    if ($script:dryRunCheck.Checked) {
        $line = Write-GuardLog "$message DRY-RUN: firewall rule was not created." "WARN"
        Add-EventRow -Level "DRY-RUN" -Message $line
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
            -Description "Temporary block created by PC DDoS Guard GUI." | Out-Null
    }

    $line = Write-GuardLog $message "WARN"
    Add-EventRow -Level "BLOCK" -Message $line
}

function Remove-ExpiredBlocks {
    $now = Get-Date
    $expired = @($script:blockedUntil.Keys | Where-Object { $script:blockedUntil[$_] -le $now })
    foreach ($remoteAddress in $expired) {
        $ruleName = "{0}-{1}" -f $script:config.FirewallRulePrefix, ($remoteAddress -replace "[:\.]", "-")
        if (-not $script:dryRunCheck.Checked) {
            Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        }
        $script:blockedUntil.Remove($remoteAddress)
        $line = Write-GuardLog "Removed expired block for $remoteAddress."
        Add-EventRow -Level "INFO" -Message $line
    }
}

function Update-Chart {
    param([int]$ConnectionCount)

    $pointIndex = $script:trafficSeries.Points.Count
    $script:trafficSeries.Points.AddXY($pointIndex, $ConnectionCount) | Out-Null
    while ($script:trafficSeries.Points.Count -gt 60) {
        $script:trafficSeries.Points.RemoveAt(0)
    }

    for ($i = 0; $i -lt $script:trafficSeries.Points.Count; $i++) {
        $script:trafficSeries.Points[$i].XValue = $i
    }
}

function Invoke-GuardSample {
    try {
        $now = Get-Date
        $window = [TimeSpan]::FromSeconds([int]$script:config.WindowSeconds)
        Remove-ExpiredBlocks

        foreach ($key in @($script:seenConnectionKeys.Keys)) {
            if ($script:seenConnectionKeys[$key] -lt $now.Subtract($window)) {
                $script:seenConnectionKeys.Remove($key)
            }
        }

        $connections = Get-InboundConnections -Config $script:config
        $script:connectionLabel.Text = [string]$connections.Count
        Update-Chart -ConnectionCount $connections.Count

        foreach ($connection in $connections) {
            $remoteAddress = [string]$connection.RemoteAddress
            if (Test-IsAllowedAddress -Address $remoteAddress -Config $script:config) { continue }
            if ($script:blockedUntil.ContainsKey($remoteAddress)) { continue }

            if (-not $script:observations.ContainsKey($remoteAddress)) {
                $script:observations[$remoteAddress] = New-Object System.Collections.Generic.List[object]
            }

            $connectionKey = New-ConnectionKey -Connection $connection
            $isNewConnection = -not $script:seenConnectionKeys.ContainsKey($connectionKey)
            $script:seenConnectionKeys[$connectionKey] = $now

            $script:observations[$remoteAddress].Add([pscustomobject]@{
                Time = $now
                IsNewConnection = $isNewConnection
            })
        }

        foreach ($remoteAddress in @($script:observations.Keys)) {
            $recent = @($script:observations[$remoteAddress] | Where-Object { $_.Time -ge $now.Subtract($window) })
            if ($recent.Count -eq 0) {
                $script:observations.Remove($remoteAddress)
                continue
            }

            $script:observations[$remoteAddress] = [System.Collections.Generic.List[object]]$recent
            $newConnectionCount = @($recent | Where-Object { $_.IsNewConnection }).Count

            if ($recent.Count -ge [int]$script:config.MaxConnectionsPerWindow -or
                $newConnectionCount -ge [int]$script:config.MaxNewConnectionsPerWindow) {
                Add-TemporaryBlock -RemoteAddress $remoteAddress
                $script:observations.Remove($remoteAddress)
            }
        }

        Refresh-TopTalkersGrid
        Refresh-BlocksGrid
        $script:lastSampleLabel.Text = (Get-Date).ToString("HH:mm:ss")
        $script:statusLabel.Text = "Monitoring"
        $script:statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(88, 214, 141)
    }
    catch {
        $script:statusLabel.Text = "Error"
        $script:statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 107, 107)
        Add-EventRow -Level "ERROR" -Message $_.Exception.Message
    }
}

$script:config = Get-GuardConfig -Path $ConfigPath
$script:observations = @{}
$script:seenConnectionKeys = @{}
$script:blockedUntil = @{}

$isAdmin = Test-IsAdministrator

$dark = [System.Drawing.Color]::FromArgb(10, 16, 24)
$panel = [System.Drawing.Color]::FromArgb(24, 32, 44)
$text = [System.Drawing.Color]::FromArgb(229, 236, 246)
$muted = [System.Drawing.Color]::FromArgb(151, 164, 183)
$accent = [System.Drawing.Color]::FromArgb(56, 189, 248)
$danger = [System.Drawing.Color]::FromArgb(255, 107, 107)

$form = New-Object System.Windows.Forms.Form
$form.Text = "PC DDoS Guard"
$form.Size = New-Object System.Drawing.Size(1120, 760)
$form.MinimumSize = New-Object System.Drawing.Size(980, 680)
$form.StartPosition = "CenterScreen"
$form.BackColor = $dark
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$title = New-Label -Text "PC DDoS Guard" -X 24 -Y 18 -Width 300 -Height 34 -Size 20 -Color $text
$subtitle = New-Label -Text "Live inbound connection monitoring and temporary firewall blocking" -X 26 -Y 54 -Width 540 -Height 24 -Size 10 -Color $muted
$form.Controls.AddRange(@($title, $subtitle))

$script:dryRunCheck = New-Object System.Windows.Forms.CheckBox
$script:dryRunCheck.Text = "Dry run"
$script:dryRunCheck.Checked = $false
$script:dryRunCheck.ForeColor = $text
$script:dryRunCheck.BackColor = $dark
$script:dryRunCheck.Location = New-Object System.Drawing.Point(920, 32)
$script:dryRunCheck.Size = New-Object System.Drawing.Size(90, 28)
$form.Controls.Add($script:dryRunCheck)

$startButton = New-Object System.Windows.Forms.Button
$startButton.Text = "Pause"
$startButton.Location = New-Object System.Drawing.Point(1015, 30)
$startButton.Size = New-Object System.Drawing.Size(72, 32)
$startButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$startButton.FlatAppearance.BorderColor = $accent
$startButton.ForeColor = $text
$startButton.BackColor = [System.Drawing.Color]::FromArgb(18, 44, 62)
$form.Controls.Add($startButton)

$statusPanel = New-Panel -X 24 -Y 94 -Width 250 -Height 106
$statusCaption = New-Label -Text "Status" -X 16 -Y 14 -Width 200 -Height 22 -Size 9 -Color $muted
$script:statusLabel = New-Label -Text "Starting" -X 16 -Y 42 -Width 210 -Height 34 -Size 20 -Color $accent
$statusPanel.Controls.AddRange(@($statusCaption, $script:statusLabel))

$connectionsPanel = New-Panel -X 292 -Y 94 -Width 250 -Height 106
$connectionsCaption = New-Label -Text "Current Connections" -X 16 -Y 14 -Width 210 -Height 22 -Size 9 -Color $muted
$script:connectionLabel = New-Label -Text "0" -X 16 -Y 42 -Width 210 -Height 34 -Size 20 -Color $text
$connectionsPanel.Controls.AddRange(@($connectionsCaption, $script:connectionLabel))

$blockedPanel = New-Panel -X 560 -Y 94 -Width 250 -Height 106
$blockedCaption = New-Label -Text "Active Blocks" -X 16 -Y 14 -Width 210 -Height 22 -Size 9 -Color $muted
$script:blockedLabel = New-Label -Text "0" -X 16 -Y 42 -Width 210 -Height 34 -Size 20 -Color $danger
$blockedPanel.Controls.AddRange(@($blockedCaption, $script:blockedLabel))

$samplePanel = New-Panel -X 828 -Y 94 -Width 260 -Height 106
$sampleCaption = New-Label -Text "Last Sample" -X 16 -Y 14 -Width 210 -Height 22 -Size 9 -Color $muted
$script:lastSampleLabel = New-Label -Text "--:--:--" -X 16 -Y 42 -Width 210 -Height 34 -Size 20 -Color $text
$samplePanel.Controls.AddRange(@($sampleCaption, $script:lastSampleLabel))
$form.Controls.AddRange(@($statusPanel, $connectionsPanel, $blockedPanel, $samplePanel))

$chartPanel = New-Panel -X 24 -Y 218 -Width 690 -Height 230
$chartTitle = New-Label -Text "Inbound Connection Pressure" -X 16 -Y 12 -Width 300 -Height 24 -Size 11 -Color $text
$chartPanel.Controls.Add($chartTitle)

$chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
$chart.Location = New-Object System.Drawing.Point(12, 42)
$chart.Size = New-Object System.Drawing.Size(666, 176)
$chart.BackColor = $panel
$chartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
$chartArea.BackColor = $panel
$chartArea.AxisX.Enabled = [System.Windows.Forms.DataVisualization.Charting.AxisEnabled]::False
$chartArea.AxisY.LabelStyle.ForeColor = $muted
$chartArea.AxisY.MajorGrid.LineColor = [System.Drawing.Color]::FromArgb(45, 58, 76)
$chartArea.AxisY.LineColor = [System.Drawing.Color]::FromArgb(45, 58, 76)
$chart.ChartAreas.Add($chartArea)
$script:trafficSeries = New-Object System.Windows.Forms.DataVisualization.Charting.Series
$script:trafficSeries.Name = "Connections"
$script:trafficSeries.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::SplineArea
$script:trafficSeries.Color = [System.Drawing.Color]::FromArgb(110, 56, 189, 248)
$script:trafficSeries.BorderColor = $accent
$script:trafficSeries.BorderWidth = 2
$chart.Series.Add($script:trafficSeries)
$chartPanel.Controls.Add($chart)

$talkersPanel = New-Panel -X 732 -Y 218 -Width 356 -Height 230
$talkersTitle = New-Label -Text "Top Sources" -X 14 -Y 12 -Width 260 -Height 24 -Size 11 -Color $text
$talkersPanel.Controls.Add($talkersTitle)
$script:talkersGrid = New-Object System.Windows.Forms.DataGridView
$script:talkersGrid.Location = New-Object System.Drawing.Point(12, 42)
$script:talkersGrid.Size = New-Object System.Drawing.Size(332, 176)
Set-GridStyle -Grid $script:talkersGrid
$script:talkersGrid.Columns.Add("Address", "Source IP") | Out-Null
$script:talkersGrid.Columns.Add("Total", "Total") | Out-Null
$script:talkersGrid.Columns.Add("New", "New") | Out-Null
$talkersPanel.Controls.Add($script:talkersGrid)
$form.Controls.AddRange(@($chartPanel, $talkersPanel))

$eventsPanel = New-Panel -X 24 -Y 466 -Width 690 -Height 230
$eventsTitle = New-Label -Text "Attack and Block Events" -X 14 -Y 12 -Width 320 -Height 24 -Size 11 -Color $text
$eventsPanel.Controls.Add($eventsTitle)
$script:eventsGrid = New-Object System.Windows.Forms.DataGridView
$script:eventsGrid.Location = New-Object System.Drawing.Point(12, 42)
$script:eventsGrid.Size = New-Object System.Drawing.Size(666, 176)
Set-GridStyle -Grid $script:eventsGrid
$script:eventsGrid.Columns.Add("Time", "Time") | Out-Null
$script:eventsGrid.Columns.Add("Level", "Level") | Out-Null
$script:eventsGrid.Columns.Add("Message", "Message") | Out-Null
$script:eventsGrid.Columns["Time"].FillWeight = 14
$script:eventsGrid.Columns["Level"].FillWeight = 18
$script:eventsGrid.Columns["Message"].FillWeight = 68
$eventsPanel.Controls.Add($script:eventsGrid)

$blocksPanel = New-Panel -X 732 -Y 466 -Width 356 -Height 230
$blocksTitle = New-Label -Text "Temporary Blocks" -X 14 -Y 12 -Width 260 -Height 24 -Size 11 -Color $text
$blocksPanel.Controls.Add($blocksTitle)
$script:blocksGrid = New-Object System.Windows.Forms.DataGridView
$script:blocksGrid.Location = New-Object System.Drawing.Point(12, 42)
$script:blocksGrid.Size = New-Object System.Drawing.Size(332, 176)
Set-GridStyle -Grid $script:blocksGrid
$script:blocksGrid.Columns.Add("Address", "Blocked IP") | Out-Null
$script:blocksGrid.Columns.Add("Expires", "Expires") | Out-Null
$blocksPanel.Controls.Add($script:blocksGrid)
$form.Controls.AddRange(@($eventsPanel, $blocksPanel))

if (-not $isAdmin) {
    $script:dryRunCheck.Checked = $true
    $script:dryRunCheck.Enabled = $false
    Add-EventRow -Level "WARN" -Message "Not running as Administrator. Dry run is enabled because firewall rules cannot be changed."
}

$ports = @($script:config.ProtectedLocalPorts)
$portText = if ($ports.Count -eq 0) { "all inbound TCP ports" } else { "ports: $($ports -join ', ')" }
Add-EventRow -Level "INFO" -Message "Monitoring $portText. Window=$($script:config.WindowSeconds)s Block=$($script:config.BlockMinutes)m"
Write-GuardLog "PC DDoS Guard GUI started. WindowSeconds=$($script:config.WindowSeconds) BlockMinutes=$($script:config.BlockMinutes)"

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = [int]$script:config.SampleIntervalSeconds * 1000
$timer.Add_Tick({ Invoke-GuardSample })
$timer.Start()

$startButton.Add_Click({
    if ($timer.Enabled) {
        $timer.Stop()
        $startButton.Text = "Resume"
        $script:statusLabel.Text = "Paused"
        $script:statusLabel.ForeColor = $muted
    }
    else {
        $timer.Start()
        $startButton.Text = "Pause"
        $script:statusLabel.Text = "Monitoring"
        $script:statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(88, 214, 141)
    }
})

$form.Add_Shown({ Invoke-GuardSample })
[void]$form.ShowDialog()
