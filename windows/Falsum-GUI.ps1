<#
.SYNOPSIS
    Falsum — Windows Application (GUI) v2
    Rewritten properly. No shortcuts. No excuses.

.DESCRIPTION
    Gregg's order: "learn how to fucking code and then do it"
    This version:
    - Proper error handling on every action
    - Buttons disable during execution (no double-click)
    - Progress shown in status bar
    - Output trimmed to prevent memory leak
    - Admin check at startup
    - Module load verification
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:InstallDir = Split-Path -Parent $PSCommandPath
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:ModulesLoaded = $false

# ============================================================================
# Helper: Write to output with trimming
# ============================================================================
$script:MaxOutputLines = 5000

function Write-FalsumOutput {
    param(
        [string]$Text,
        [string]$ColorName = "LightGreen"
    )
    try {
        # Trim if too many lines (prevent memory leak - pain point #84)
        if ($outputBox.Lines.Count -gt $script:MaxOutputLines) {
            $lines = $outputBox.Lines
            $newLines = $lines[($lines.Count - $script:MaxOutputLines)..($lines.Count - 1)]
            $outputBox.Lines = $newLines
        }
        
        $color = [System.Drawing.Color]::$ColorName
        $outputBox.SelectionColor = $color
        $timestamp = Get-Date -Format "HH:mm:ss"
        $outputBox.AppendText("[$timestamp] $Text`r`n")
        $outputBox.ScrollToCaret()
    }
    catch {
        # If output fails, at least try console
        Write-Host "[$timestamp] $Text"
    }
}

function Set-ButtonsEnabled {
    param([bool]$Enabled)
    foreach ($ctrl in $buttonPanel.Controls) {
        if ($ctrl -is [System.Windows.Forms.Button]) {
            $ctrl.Enabled = $Enabled
        }
    }
    if ($Enabled) {
        $statusLabel.Text = "Ready"
    }
    else {
        $statusLabel.Text = "Working..."
    }
    [System.Windows.Forms.Application]::DoEvents()
}

function Invoke-ModuleSafely {
    param(
        [string]$ModuleName,
        [scriptblock]$Action,
        [bool]$RequiresAdmin = $false
    )
    
    # Pain point #118 FIX: Check admin before running
    if ($RequiresAdmin -and -not $script:IsAdmin) {
        Write-FalsumOutput "ERROR: '$ModuleName' requires administrator. Right-click -> Run as administrator." "Red"
        [System.Windows.Forms.MessageBox]::Show(
            "'$ModuleName' requires administrator privileges.`n`nRight-click Falsum and choose 'Run as administrator'.",
            "Admin Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    # Pain point #86 FIX: Disable buttons during execution
    Set-ButtonsEnabled $false
    
    try {
        Write-FalsumOutput "=== Starting: $ModuleName ===" "Cyan"
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        
        # Run the action
        & $Action
        
        $sw.Stop()
        Write-FalsumOutput "=== Complete: $ModuleName ($([math]::Round($sw.Elapsed.TotalSeconds, 1))s) ===" "Green"
    }
    catch {
        Write-FalsumOutput "ERROR in $ModuleName : $($_.Exception.Message)" "Red"
        Write-FalsumOutput "Stack: $($_.ScriptStackTrace)" "DarkRed"
    }
    finally {
        # Pain point #86 FIX: Re-enable buttons
        Set-ButtonsEnabled $true
    }
}

# ============================================================================
# Load core modules with error handling (pain point #81 FIX)
# ============================================================================
function Initialize-Falsum {
    Write-FalsumOutput "Initializing Falsum..." "Cyan"
    
    $coreFiles = @(
        @{ Dir = '00-coherence-core'; File = 'Falsum-Coherence.ps1' },
        @{ Dir = '00-coherence-core'; File = 'Falsum-Unified.ps1' },
        @{ Dir = '12-timeline-vault'; File = 'Falsum-Vault.ps1' }
    )
    
    foreach ($cf in $coreFiles) {
        $path = Join-Path $script:InstallDir "modules\$($cf.Dir)\$($cf.File)"
        if (-not (Test-Path $path)) {
            Write-FalsumOutput "MISSING: $($cf.File)" "Red"
            return $false
        }
        try {
            . $path
            Write-FalsumOutput "Loaded: $($cf.File)" "Gray"
        }
        catch {
            Write-FalsumOutput "FAILED to load $($cf.File): $($_.Exception.Message)" "Red"
            return $false
        }
    }
    
    # Admin check (pain point #118)
    if ($script:IsAdmin) {
        Write-FalsumOutput "Running as Administrator — full capabilities." "Green"
    }
    else {
        Write-FalsumOutput "Not running as Administrator — some modules limited." "Yellow"
    }
    
    $script:ModulesLoaded = $true
    return $true
}

# ============================================================================
# Build the form
# ============================================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "Falsum — Unified Security Application"
$form.Size = New-Object System.Drawing.Size(1024, 720)
$form.MinimumSize = New-Object System.Drawing.Size(800, 600)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$form.ForeColor = [System.Drawing.Color]::White

# Title
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "SENTINEL"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 24, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::Cyan
$titleLabel.Location = New-Object System.Drawing.Point(20, 10)
$titleLabel.Size = New-Object System.Drawing.Size(300, 40)
$titleLabel.Anchor = "Top, Left"
$form.Controls.Add($titleLabel)

$subtitleLabel = New-Object System.Windows.Forms.Label
$adminText = if ($script:IsAdmin) { " [ADMIN]" } else { "" }
$subtitleLabel.Text = "Transparent. Local. Yours.$adminText"
$subtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$subtitleLabel.ForeColor = [System.Drawing.Color]::Gray
$subtitleLabel.Location = New-Object System.Drawing.Point(20, 50)
$subtitleLabel.Size = New-Object System.Drawing.Size(400, 20)
$subtitleLabel.Anchor = "Top, Left"
$form.Controls.Add($subtitleLabel)

# Button panel with scrollbar (pain point #105 FIX)
$buttonPanel = New-Object System.Windows.Forms.Panel
$buttonPanel.Location = New-Object System.Drawing.Point(20, 80)
$buttonPanel.Size = New-Object System.Drawing.Size(260, 560)
$buttonPanel.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
$buttonPanel.AutoScroll = $true
$buttonPanel.Anchor = "Top, Bottom, Left"
$form.Controls.Add($buttonPanel)

# Output box (pain point #103 FIX: larger font, pain point #107 FIX: context menu)
$outputBox = New-Object System.Windows.Forms.RichTextBox
$outputBox.Location = New-Object System.Drawing.Point(290, 80)
$outputBox.Size = New-Object System.Drawing.Size(700, 560)
$outputBox.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$outputBox.ForeColor = [System.Drawing.Color]::LightGreen
$outputBox.Font = New-Object System.Drawing.Font("Consolas", 10)  # Larger for readability
$outputBox.ReadOnly = $true
$outputBox.WordWrap = $false
$outputBox.ScrollBars = "Both"
$outputBox.Anchor = "Top, Bottom, Left, Right"

# Add context menu with Copy All (pain point #107 FIX)
$ctxMenu = New-Object System.Windows.Forms.ContextMenuStrip
$copyAllItem = $ctxMenu.Items.Add("Copy All")
$copyAllItem.Add_Click({
    if ($outputBox.Text.Length -gt 0) {
        [System.Windows.Forms.Clipboard]::SetText($outputBox.Text)
    }
})
$clearItem = $ctxMenu.Items.Add("Clear")
$clearItem.Add_Click({ $outputBox.Clear() })
$outputBox.ContextMenuStrip = $ctxMenu

$form.Controls.Add($outputBox)

# Status bar
$statusBar = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = "Initializing..."
$statusLabel.ForeColor = [System.Drawing.Color]::White
$statusBar.Items.Add($statusLabel) | Out-Null
$statusBar.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
$form.Controls.Add($statusBar)

# ============================================================================
# Button factory with tooltip (pain point #102 FIX)
# ============================================================================
$toolTip = New-Object System.Windows.Forms.ToolTip

function New-FalsumButton {
    param(
        [string]$Text,
        [string]$Tooltip,
        [int]$Y,
        [scriptblock]$Action,
        [bool]$RequiresAdmin = $false
    )
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = if ($RequiresAdmin -and -not $script:IsAdmin) { "$Text ⚠" } else { $Text }
    $btn.Location = New-Object System.Drawing.Point(10, $Y)
    $btn.Size = New-Object System.Drawing.Size(230, 32)
    $btn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
    $btn.ForeColor = [System.Drawing.Color]::White
    $btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btn.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btn.Anchor = "Top, Left, Right"
    
    # Tooltip (pain point #102)
    $tipText = $Tooltip
    if ($RequiresAdmin) { $tipText += "`n⚠ Requires administrator" }
    $toolTip.SetToolTip($btn, $tipText)
    
    # Click handler with safety wrapper
    $btn.Add_Click({
        Invoke-ModuleSafely -ModuleName $Text -Action $Action -RequiresAdmin $RequiresAdmin
    }.GetNewClosure())
    
    $buttonPanel.Controls.Add($btn)
    return $btn
}

# ============================================================================
# Create buttons
# ============================================================================
$y = 10
$step = 37

# Unified
New-FalsumButton "RUN EVERYTHING" "Run evidence, network, vuln, malware, and defender scans in sequence" $y {
    $modules = @(
        @{ Name = "Evidence Sweep"; Fn = "Invoke-EvidenceSweepWorkflow" },
        @{ Name = "Network Scan"; Fn = "Invoke-NetScanWorkflow" },
        @{ Name = "Vulnerability Check"; Fn = "Invoke-VulnMenu" },
        @{ Name = "Malware Hunt"; Fn = "Invoke-MalwareHunterWorkflow" },
        @{ Name = "Defender Watch"; Fn = "Invoke-DefenderWatchWorkflow" }
    )
    foreach ($m in $modules) {
        Write-FalsumOutput "`n--- $($m.Name) ---" "Yellow"
        try {
            $fn = Get-Command $m.Fn -ErrorAction Stop
            & $fn
        }
        catch {
            Write-FalsumOutput "Failed: $($_.Exception.Message)" "Red"
        }
    }
}
$y += $step

New-FalsumButton "Unified Scan" "Cross-module threat correlation using shared evidence pool" $y {
    Import-LauncherModule -DirName '00-coherence-core' -FileName 'Falsum-Unified.ps1' | Out-Null
    $result = Invoke-UnifiedScan
    $pic = Get-UnifiedThreatPicture
    if ($pic) {
        Write-FalsumOutput $pic.Summary "White"
    }
}
$y += $step

# Evidence
New-FalsumButton "Evidence Sweep" "44-step system evidence collection" $y {
    Import-LauncherModule -DirName '01-evidence-sweep' -FileName 'Falsum-Sweep.ps1' | Out-Null
    Invoke-EvidenceSweepWorkflow
}
$y += $step

# Network (requires admin for packet capture)
New-FalsumButton "Network Scan" "Discover devices on your network" $y {
    Import-LauncherModule -DirName '03-netscan' -FileName 'Falsum-NetScan.ps1' | Out-Null
    Invoke-NetScanWorkflow
}
$y += $step

New-FalsumButton "Packet Witness" "Capture network traffic (pktmon)" $y {
    Import-LauncherModule -DirName '02-packet-witness' -FileName 'Falsum-PacketWitness.ps1' | Out-Null
    Invoke-PacketWitnessMenu
} -RequiresAdmin $true
$y += $step

# Defense
New-FalsumButton "Vulnerability Check" "Find weak configs + apply fixes" $y {
    Import-LauncherModule -DirName '06-vuln-check' -FileName 'Falsum-VulnCheck.ps1' | Out-Null
    Invoke-VulnMenu
}
$y += $step

New-FalsumButton "Malware Hunter" "Find stealers, RATs, PUPs" $y {
    Import-LauncherModule -DirName '21-malware-hunter' -FileName 'Falsum-MalwareHunter.ps1' | Out-Null
    Invoke-MalwareHunterWorkflow
} -RequiresAdmin $true
$y += $step

New-FalsumButton "Purge Binaries" "Delete unattributed binaries + log" $y {
    Import-LauncherModule -DirName '25-purge' -FileName 'Falsum-Purge.ps1' | Out-Null
    Invoke-PurgeWorkflow
} -RequiresAdmin $true
$y += $step

New-FalsumButton "Fix Registry" "Remove empty/orphaned registry entries" $y {
    Import-LauncherModule -DirName '29-registry-fix' -FileName 'Falsum-RegistryFix.ps1' | Out-Null
    Invoke-RegistryFixWorkflow
} -RequiresAdmin $true
$y += $step

New-FalsumButton "Defender Watch" "Log everything Windows Defender does" $y {
    Import-LauncherModule -DirName '26-defender-watch' -FileName 'Falsum-DefenderWatch.ps1' | Out-Null
    Invoke-DefenderWatchWorkflow
} -RequiresAdmin $true
$y += $step

New-FalsumButton "Memory Forensics" "Deep RAM analysis" $y {
    Import-LauncherModule -DirName '27-memory-forensics' -FileName 'Falsum-MemoryForensics.ps1' | Out-Null
    Invoke-MemoryForensicsWorkflow
} -RequiresAdmin $true
$y += $step

New-FalsumButton "Task Killer" "Kill background bloatware" $y {
    Import-LauncherModule -DirName '28-task-killer' -FileName 'Falsum-TaskKiller.ps1' | Out-Null
    Invoke-TaskKillerWorkflow
} -RequiresAdmin $true
$y += $step

# Privacy
New-FalsumButton "Data Brokers" "Opt out from 958 data brokers" $y {
    Import-LauncherModule -DirName '09-broker-eradicator' -FileName 'Falsum-BrokerEradicator.ps1' | Out-Null
    Invoke-BrokerWorkflow
}
$y += $step

New-FalsumButton "Breach Check" "Check if your data was breached" $y {
    Import-LauncherModule -DirName '08-breach-cleaner' -FileName 'Falsum-BreachClean.ps1' | Out-Null
    Invoke-BreachWorkflow
}
$y += $step

# EIUAE
New-FalsumButton "EIUAE Coherence" "Gregg's math: Intent/Utterance/Action/Evidence alignment" $y {
    $test = Test-EIUAE
    if ($test.Passed) {
        Write-FalsumOutput "EIUAE self-test: PASSED" "Green"
        Write-FalsumOutput "Formula: EIUAE(k) = SUM beta * D_KL(P_m || P_n)" "Gray"
    }
    else {
        Write-FalsumOutput "EIUAE issues: $($test.Issues -join '; ')" "Red"
    }
}
$y += $step

# ============================================================================
# Initialize and show
# ============================================================================
$form.Add_Shown({
    if (Initialize-Falsum) {
        $statusLabel.Text = "Ready"
        Write-FalsumOutput "" 
        Write-FalsumOutput "Falsum GUI v2 loaded." "Cyan"
        Write-FalsumOutput "Select a module from the left." "Gray"
        if (-not $script:IsAdmin) {
            Write-FalsumOutput "Tip: Right-click -> Run as administrator for full capabilities." "Yellow"
        }
    }
    else {
        $statusLabel.Text = "Init failed"
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to initialize. Check output for details.",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})

[void]$form.ShowDialog()
