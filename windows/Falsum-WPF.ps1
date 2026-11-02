<#
.SYNOPSIS
    Falsum — WPF Application v3
    Modern UI using WPF/XAML. Pattern from Windows-Maintenance-Tool (GitHub).

.DESCRIPTION
    Gregg: "a trillion dollar app doesn't look like a piece of shit"
    This uses WPF with XAML for a modern, visually appealing interface:
    - Rounded corners, dynamic theming
    - Sidebar navigation (like WMT)
    - Search box
    - Log panel
    - Segoe UI Variable font (Windows 11)
#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$script:InstallDir = Split-Path -Parent $PSCommandPath
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ============================================================================
# XAML — Modern dark theme, rounded corners, sidebar layout
# Pattern: Windows-Maintenance-Tool (ios12checker/GitHub)
# ============================================================================
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Falsum — Unified Security" Width="1100" Height="750"
        WindowStartupLocation="CenterScreen"
        Background="#1E1E1E" Foreground="#FFFFFF"
        FontFamily="Segoe UI Variable Display, Segoe UI, Arial" FontSize="13">
    <Window.Resources>
        <!-- Colors -->
        <SolidColorBrush x:Key="BgDark" Color="#1E1E1E"/>
        <SolidColorBrush x:Key="BgPanel" Color="#2D2D2D"/>
        <SolidColorBrush x:Key="BgCard" Color="#383838"/>
        <SolidColorBrush x:Key="TextPrimary" Color="#FFFFFF"/>
        <SolidColorBrush x:Key="TextSecondary" Color="#CCCCCC"/>
        <SolidColorBrush x:Key="TextMuted" Color="#888888"/>
        <SolidColorBrush x:Key="Accent" Color="#00D4FF"/>
        <SolidColorBrush x:Key="AccentDark" Color="#0099CC"/>
        <SolidColorBrush x:Key="Success" Color="#4CAF50"/>
        <SolidColorBrush x:Key="Warning" Color="#FF9800"/>
        <SolidColorBrush x:Key="Error" Color="#F44336"/>
        
        <!-- Navigation Button Style -->
        <Style x:Key="NavBtn" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="{StaticResource TextSecondary}"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="16,10"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" 
                                CornerRadius="8" 
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}"
                                            VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="{StaticResource BgCard}"/>
                                <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter Property="Background" Value="{StaticResource AccentDark}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        
        <!-- Action Button Style -->
        <Style x:Key="ActionBtn" TargetType="Button">
            <Setter Property="Background" Value="{StaticResource Accent}"/>
            <Setter Property="Foreground" Value="#000000"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="20,12"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" 
                                CornerRadius="8" 
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="{StaticResource AccentDark}"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#555555"/>
                                <Setter Property="Foreground" Value="#888888"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        
        <!-- SubHeader Style -->
        <Style x:Key="SubHeader" TargetType="TextBlock">
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Foreground" Value="{StaticResource TextMuted}"/>
        </Style>
    </Window.Resources>
    
    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="280"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        
        <!-- Sidebar -->
        <Border Grid.Column="0" Background="{StaticResource BgPanel}" BorderThickness="0">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                
                <!-- Header -->
                <StackPanel Grid.Row="0" Margin="20,24,20,16">
                    <TextBlock Text="SENTINEL" FontSize="28" FontWeight="Bold" 
                               Foreground="{StaticResource Accent}"/>
                    <TextBlock Text="Transparent. Local. Yours." FontSize="12" 
                               Foreground="{StaticResource TextMuted}" Margin="0,4,0,0"/>
                    <TextBlock Name="txtAdminBadge" FontSize="11" Margin="0,8,0,0"/>
                </StackPanel>
                
                <!-- Search -->
                <Border Grid.Row="1" Background="{StaticResource BgDark}" 
                        Margin="16,0,16,12" CornerRadius="8">
                    <TextBox Name="txtSearch" Height="36" 
                             Background="Transparent" Foreground="{StaticResource TextPrimary}"
                             BorderThickness="0" Padding="12,0"
                             VerticalContentAlignment="Center"/>
                </Border>
                
                <!-- Navigation -->
                <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto" Margin="8,0">
                    <StackPanel Name="pnlNav">
                        <TextBlock Text="UNIFIED" Style="{StaticResource SubHeader}" Margin="12,8,0,4"/>
                        <Button Name="btnRunAll" Content="⚡ Run Everything" Style="{StaticResource NavBtn}"/>
                        <Button Name="btnUnified" Content="◈ Unified Scan" Style="{StaticResource NavBtn}"/>
                        
                        <TextBlock Text="DEFENSE" Style="{StaticResource SubHeader}" Margin="12,16,0,4"/>
                        <Button Name="btnVuln" Content="🛡 Vulnerability Check" Style="{StaticResource NavBtn}"/>
                        <Button Name="btnMalware" Content="🦠 Malware Hunter" Style="{StaticResource NavBtn}"/>
                        <Button Name="btnPurge" Content="🗑 Purge Binaries" Style="{StaticResource NavBtn}"/>
                        <Button Name="btnRegistry" Content="🔧 Fix Registry" Style="{StaticResource NavBtn}"/>
                        <Button Name="btnDefender" Content="👁 Defender Watch" Style="{StaticResource NavBtn}"/>
                        <Button Name="btnMemory" Content="🧠 Memory Forensics" Style="{StaticResource NavBtn}"/>
                        <Button Name="btnTask" Content="⚙ Task Killer" Style="{StaticResource NavBtn}"/>
                        
                        <TextBlock Text="NETWORK" Style="{StaticResource SubHeader}" Margin="12,16,0,4"/>
                        <Button Name="btnNetScan" Content="🌐 Network Scan" Style="{StaticResource NavBtn}"/>
                        <Button Name="btnPacket" Content="📡 Packet Witness" Style="{StaticResource NavBtn}"/>
                        
                        <TextBlock Text="PRIVACY" Style="{StaticResource SubHeader}" Margin="12,16,0,4"/>
                        <Button Name="btnBroker" Content="🏢 Data Brokers" Style="{StaticResource NavBtn}"/>
                        <Button Name="btnBreach" Content="💔 Breach Check" Style="{StaticResource NavBtn}"/>
                        <Button Name="btnEvidence" Content="📋 Evidence Sweep" Style="{StaticResource NavBtn}"/>
                        
                        <TextBlock Text="INTELLIGENCE" Style="{StaticResource SubHeader}" Margin="12,16,0,4"/>
                        <Button Name="btnEIUAE" Content="∑ EIUAE Coherence" Style="{StaticResource NavBtn}"/>
                        
                        <TextBlock Text="CONTROL" Style="{StaticResource SubHeader}" Margin="12,16,0,4"/>
                        <Button Name="btnGate" Content="🚪 Automation Gate" Style="{StaticResource NavBtn}"/>
                        <Button Name="btnPorts" Content="🔌 Port Control" Style="{StaticResource NavBtn}"/>
                        <Button Name="btnCmd" Content="💻 Command Center" Style="{StaticResource NavBtn}"/>
                    </StackPanel>
                </ScrollViewer>
                
                <!-- Status -->
                <Border Grid.Row="3" Background="{StaticResource BgDark}" 
                        Margin="12" CornerRadius="8" Padding="12,8">
                    <TextBlock Name="txtStatus" Text="Ready" FontSize="12" 
                               Foreground="{StaticResource TextSecondary}"/>
                </Border>
            </Grid>
        </Border>
        
        <!-- Main Content -->
        <Grid Grid.Column="1" Margin="24">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
            </Grid.RowDefinitions>
            
            <TextBlock Grid.Row="0" Name="txtTitle" Text="Select a module" 
                       FontSize="24" FontWeight="SemiBold" Margin="0,0,0,16"/>
            
            <Border Grid.Row="1" Background="{StaticResource BgDark}" CornerRadius="12">
                <RichTextBox Name="txtOutput" Background="Transparent" 
                             Foreground="{StaticResource TextPrimary}"
                             BorderThickness="0" Padding="16"
                             FontFamily="Cascadia Code, Consolas, monospace" FontSize="12"
                             IsReadOnly="True" VerticalScrollBarVisibility="Auto"/>
            </Border>
        </Grid>
    </Grid>
</Window>
"@

# ============================================================================
# Load XAML and wire up
# ============================================================================
try {
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml.OuterXml))
    $window = [System.Windows.Markup.XamlReader]::Load($reader)
}
catch {
    Write-Host "XAML parse error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Get controls
$txtOutput = $window.FindName("txtOutput")
$txtStatus = $window.FindName("txtStatus")
$txtTitle = $window.FindName("txtTitle")
$txtAdminBadge = $window.FindName("txtAdminBadge")
$txtSearch = $window.FindName("txtSearch")
$pnlNav = $window.FindName("pnlNav")

# Admin badge
if ($script:IsAdmin) {
    $txtAdminBadge.Text = "● ADMINISTRATOR"
    $txtAdminBadge.Foreground = [System.Windows.Media.Brushes]::LightGreen
}
else {
    $txtAdminBadge.Text = "○ Standard user (some features limited)"
    $txtAdminBadge.Foreground = [System.Windows.Media.Brushes]::Orange
}

function Write-Log {
    param([string]$Text, [string]$Color = "White")
    $run = New-Object System.Windows.Documents.Run($Text)
    $brush = switch ($Color) {
        "Cyan" { [System.Windows.Media.Brushes]::Cyan }
        "Green" { [System.Windows.Media.Brushes]::LightGreen }
        "Red" { [System.Windows.Media.Brushes]::Red }
        "Yellow" { [System.Windows.Media.Brushes]::Yellow }
        "Gray" { [System.Windows.Media.Brushes]::Gray }
        default { [System.Windows.Media.Brushes]::White }
    }
    $run.Foreground = $brush
    $para = New-Object System.Windows.Documents.Paragraph($run)
    $para.Margin = [System.Windows.Thickness]::new(0, 2, 0, 2)
    $txtOutput.Document.Blocks.Add($para)
    $txtOutput.ScrollToEnd()
}

function Set-Working {
    param([bool]$Working, [string]$Status = "Ready")
    $txtStatus.Text = $Status
    foreach ($child in $pnlNav.Children) {
        if ($child -is [System.Windows.Controls.Button]) {
            $child.IsEnabled = -not $Working
        }
    }
    [System.Windows.Forms.Application]::DoEvents()
}

function Invoke-FalsumModule {
    param(
        [string]$Name,
        [string]$ModuleDir,
        [string]$ModuleFile,
        [string]$Function,
        [bool]$RequiresAdmin = $false
    )
    if ($RequiresAdmin -and -not $script:IsAdmin) {
        Write-Log "ERROR: '$Name' requires administrator." "Red"
        return
    }
    Set-Working $true "Running $Name..."
    $txtTitle.Text = $Name
    try {
        Write-Log "=== $Name ===" "Cyan"
        $path = Join-Path $script:InstallDir "modules\$ModuleDir\$ModuleFile"
        . $path
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        & $Function
        $sw.Stop()
        Write-Log "Complete in $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" "Green"
    }
    catch {
        Write-Log "ERROR: $($_.Exception.Message)" "Red"
    }
    finally {
        Set-Working $false "Ready"
    }
}

# Wire buttons
($window.FindName("btnRunAll")).Add_Click({
    Set-Working $true "Running full scan..."
    $txtTitle.Text = "Full Scan"
    $mods = @(
        @("Evidence Sweep", "01-evidence-sweep", "Falsum-Sweep.ps1", "Invoke-EvidenceSweepWorkflow", $false),
        @("Network Scan", "03-netscan", "Falsum-NetScan.ps1", "Invoke-NetScanWorkflow", $false),
        @("Vulnerability Check", "06-vuln-check", "Falsum-VulnCheck.ps1", "Invoke-VulnMenu", $false)
    )
    foreach ($m in $mods) {
        Write-Log "`n--- $($m[0]) ---" "Yellow"
        Invoke-FalsumModule -Name $m[0] -ModuleDir $m[1] -ModuleFile $m[2] -Function $m[3]
    }
    Set-Working $false "Ready"
})

($window.FindName("btnEIUAE")).Add_Click({
    $txtTitle.Text = "EIUAE Coherence"
    Set-Working $true "Testing EIUAE..."
    try {
        . (Join-Path $script:InstallDir "modules\00-coherence-core\Falsum-Coherence.ps1")
        $test = Test-EIUAE
        if ($test.Passed) {
            Write-Log "EIUAE self-test: PASSED" "Green"
            Write-Log "Formula: EIUAE(k) = SUM beta_mn * D_KL(P_m || P_n)" "Gray"
            Write-Log "Channels: I=Intent, U=Utterance, A=Action, E=Evidence" "Gray"
        }
        else {
            Write-Log "Issues: $($test.Issues -join '; ')" "Red"
        }
    }
    catch { Write-Log "ERROR: $($_.Exception.Message)" "Red" }
    Set-Working $false "Ready"
})

# Wire remaining buttons (simplified - full wiring in production)
$buttonMap = @{
    "btnUnified" = @("Unified Scan", "00-coherence-core", "Falsum-Unified.ps1", "Invoke-UnifiedScan", $false)
    "btnVuln" = @("Vulnerability Check", "06-vuln-check", "Falsum-VulnCheck.ps1", "Invoke-VulnMenu", $false)
    "btnMalware" = @("Malware Hunter", "21-malware-hunter", "Falsum-MalwareHunter.ps1", "Invoke-MalwareHunterWorkflow", $true)
    "btnPurge" = @("Purge Binaries", "25-purge", "Falsum-Purge.ps1", "Invoke-PurgeWorkflow", $true)
    "btnRegistry" = @("Fix Registry", "29-registry-fix", "Falsum-RegistryFix.ps1", "Invoke-RegistryFixWorkflow", $true)
    "btnDefender" = @("Defender Watch", "26-defender-watch", "Falsum-DefenderWatch.ps1", "Invoke-DefenderWatchWorkflow", $true)
    "btnMemory" = @("Memory Forensics", "27-memory-forensics", "Falsum-MemoryForensics.ps1", "Invoke-MemoryForensicsWorkflow", $true)
    "btnTask" = @("Task Killer", "28-task-killer", "Falsum-TaskKiller.ps1", "Invoke-TaskKillerWorkflow", $true)
    "btnNetScan" = @("Network Scan", "03-netscan", "Falsum-NetScan.ps1", "Invoke-NetScanWorkflow", $false)
    "btnPacket" = @("Packet Witness", "02-packet-witness", "Falsum-PacketWitness.ps1", "Invoke-PacketWitnessMenu", $true)
    "btnBroker" = @("Data Brokers", "09-broker-eradicator", "Falsum-BrokerEradicator.ps1", "Invoke-BrokerWorkflow", $false)
    "btnBreach" = @("Breach Check", "08-breach-cleaner", "Falsum-BreachClean.ps1", "Invoke-BreachWorkflow", $false)
    "btnEvidence" = @("Evidence Sweep", "01-evidence-sweep", "Falsum-Sweep.ps1", "Invoke-EvidenceSweepWorkflow", $false)
    "btnGate" = @("Automation Gate", "31-gate", "Falsum-Gate.ps1", "Invoke-GateAudit", $true)
    "btnPorts" = @("Port Control", "32-port-control", "Falsum-PortControl.ps1", "Invoke-PortControlWorkflow", $true)
    "btnCmd" = @("Command Center", "33-command-center", "Falsum-CommandCenter.ps1", "Get-SystemDashboard", $false)
}

foreach ($btnName in $buttonMap.Keys) {
    $btn = $window.FindName($btnName)
    $cfg = $buttonMap[$btnName]
    $btn.Add_Click({
        Invoke-FalsumModule -Name $cfg[0] -ModuleDir $cfg[1] -ModuleFile $cfg[2] -Function $cfg[3] -RequiresAdmin $cfg[4]
    }.GetNewClosure())
}

# Search filter
$txtSearch.Add_TextChanged({
    $query = $txtSearch.Text.ToLower()
    foreach ($child in $pnlNav.Children) {
        if ($child -is [System.Windows.Controls.Button]) {
            $visible = ($query -eq "") -or ($child.Content.ToString().ToLower().Contains($query))
            $child.Visibility = if ($visible) { "Visible" } else { "Collapsed" }
        }
        elseif ($child -is [System.Windows.Controls.TextBlock]) {
            # Keep headers visible if any button below is visible
            $child.Visibility = "Visible"
        }
    }
})

# Check for AI model on startup
$window.Add_Loaded({
    $modelDir = Join-Path $script:InstallDir "models"
    $hasModel = (Test-Path $modelDir) -and ((Get-ChildItem $modelDir -Filter "*.gguf" -ErrorAction SilentlyContinue).Count -gt 0)
    if (-not $hasModel) {
        $result = [System.Windows.MessageBox]::Show(
            "No local AI model found.`n`nDownload now? (~600MB, one-time)",
            "AI Setup",
            [System.Windows.MessageBoxButton]::YesNo,
            [System.Windows.MessageBoxImage]::Question
        )
        if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
            Write-Log "Starting AI model download..." "Cyan"
            try {
                & (Join-Path $script:InstallDir "Setup-AI.ps1")
                Write-Log "AI setup complete." "Green"
            }
            catch {
                Write-Log "AI setup failed: $($_.Exception.Message)" "Red"
            }
        }
    }
})

# Bridge polling: check for extension messages every 5 seconds
. (Join-Path $script:InstallDir "modules\30-bridge\Falsum-Bridge.ps1")
Initialize-Bridge

$bridgeTimer = New-Object System.Windows.Threading.DispatcherTimer
$bridgeTimer.Interval = [TimeSpan]::FromSeconds(5)
$bridgeTimer.Add_Tick({
    try {
        $msgs = Receive-FromExtension
        foreach ($m in $msgs) {
            Write-Log "📡 Extension: $($m.type) - $($m.data.message)" "Cyan"
            # Alert on threats
            if ($m.type -eq "browser-threat" -or $m.type -eq "gate-alert") {
                Write-Log "⚠ ALERT from extension: $($m.data.message)" "Red"
            }
        }
    }
    catch { }
})
$bridgeTimer.Start()

# Wikipedia mechanism: check for updates on launch (free, always current)
try {
    . (Join-Path $script:InstallDir "tools\Falsum-Updater.ps1")
    $hasUpdate = Test-FalsumUpdateAvailable
    if ($hasUpdate) {
        Write-Log "⬆ Update available! Run tools\Falsum-Updater.ps1 to update." "Yellow"
    }
} catch { }

# Show
Write-Host "Launching Falsum WPF..." -ForegroundColor Cyan
$window.ShowDialog() | Out-Null
$bridgeTimer.Stop()
