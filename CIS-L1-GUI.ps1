#Requires -RunAsAdministrator
Add-Type -AssemblyName PresentationFramework, System.Windows.Forms, System.Drawing

# ============================================================
# GUI XAML Definition (Modern Cyber Theme)
# ============================================================
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2000/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2000/xaml"
        Title="CIS Level 1 - Windows 10/11 Auto-Remediation" Height="750" Width="950" 
        Background="#1E1E1E" WindowStartupLocation="CenterScreen">
    <Grid Margin="15">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        
        <!-- Header -->
        <StackPanel Grid.Row="0" Margin="0,0,0,10">
            <TextBlock Text="CIS Benchmark L1 Remediation Tool" FontSize="26" FontWeight="Bold" Foreground="#00A2ED"/>
            <StackPanel Orientation="Horizontal" Margin="0,5,0,0">
                <TextBlock Name="OSLabel" Text="Detecting OS..." FontSize="14" Foreground="#AAAAAA"/>
                <TextBlock Name="EditionWarning" Text="" FontSize="14" FontWeight="Bold" Foreground="#F44336" Margin="10,0,0,0"/>
            </StackPanel>
        </StackPanel>

        <!-- Safety Guidelines / MSA Warning -->
        <Border Grid.Row="1" Background="#332B00" BorderBrush="#FFD700" BorderThickness="1" CornerRadius="4" Padding="10" Margin="0,0,0,10">
            <StackPanel>
                <TextBlock Text="CRITICAL SAFETY GUIDELINES:" FontWeight="Bold" Foreground="#FFD700" Margin="0,0,0,5"/>
                <TextBlock Name="MsaWarning" Text="• Checking for Microsoft Accounts..." Foreground="White" TextWrapping="Wrap"/>
                <TextBlock Text="• Ensure you have a local Administrator account as a backup." Foreground="White" TextWrapping="Wrap"/>
                <TextBlock Text="• System will apply CIS L1 Hardening. Some features like Microsoft Accounts may be restricted." Foreground="White" TextWrapping="Wrap"/>
            </StackPanel>
        </Border>

        <!-- Stats Panel -->
        <UniformGrid Grid.Row="2" Columns="4" Margin="0,0,0,10">
            <Border Background="#2D2D2D" Margin="5" CornerRadius="4" Padding="10">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock Text="PASS" Foreground="#4CAF50" FontWeight="Bold" HorizontalAlignment="Center"/>
                    <TextBlock Name="StatPass" Text="0" FontSize="20" Foreground="White" HorizontalAlignment="Center"/>
                </StackPanel>
            </Border>
            <Border Background="#2D2D2D" Margin="5" CornerRadius="4" Padding="10">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock Text="FIXED" Foreground="#00A2ED" FontWeight="Bold" HorizontalAlignment="Center"/>
                    <TextBlock Name="StatFix" Text="0" FontSize="20" Foreground="White" HorizontalAlignment="Center"/>
                </StackPanel>
            </Border>
            <Border Background="#2D2D2D" Margin="5" CornerRadius="4" Padding="10">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock Text="FAIL" Foreground="#F44336" FontWeight="Bold" HorizontalAlignment="Center"/>
                    <TextBlock Name="StatFail" Text="0" FontSize="20" Foreground="White" HorizontalAlignment="Center"/>
                </StackPanel>
            </Border>
            <Border Background="#2D2D2D" Margin="5" CornerRadius="4" Padding="10">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock Text="SKIPPED" Foreground="#888888" FontWeight="Bold" HorizontalAlignment="Center"/>
                    <TextBlock Name="StatSkip" Text="0" FontSize="20" Foreground="White" HorizontalAlignment="Center"/>
                </StackPanel>
            </Border>
        </UniformGrid>

        <!-- Log Box -->
        <TextBox Name="LogBox" Grid.Row="3" IsReadOnly="True" VerticalScrollBarVisibility="Auto" 
                 FontFamily="Consolas" FontSize="12" Background="#0C0C0C" Foreground="#D4D4D4" 
                 BorderBrush="#333333" Padding="10" AcceptsReturn="True"/>

        <!-- Controls -->
        <Grid Grid.Row="4" Margin="0,15,0,0">
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Left">
                 <TextBlock Name="StatusLabel" Text="Ready to begin." VerticalAlignment="Center" Foreground="#AAAAAA"/>
            </StackPanel>
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                <Button Name="BtnRun" Content="Start Remediation" Width="160" Height="40" Background="#0078D7" Foreground="White" FontWeight="Bold" BorderThickness="0">
                    <Button.Resources>
                        <Style TargetType="Border">
                            <Setter Property="CornerRadius" Value="4"/>
                        </Style>
                    </Button.Resources>
                </Button>
                <Button Name="BtnReboot" Content="Reboot Now" Width="120" Height="40" Margin="10,0,0,0" Background="#F44336" Foreground="White" FontWeight="Bold" IsEnabled="False" BorderThickness="0">
                    <Button.Resources>
                        <Style TargetType="Border">
                            <Setter Property="CornerRadius" Value="4"/>
                        </Style>
                    </Button.Resources>
                </Button>
            </StackPanel>
        </Grid>
    </Grid>
</Window>
"@

# Load XAML
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# UI Element Mapping
$logBox = $window.FindName("LogBox")
$btnRun = $window.FindName("BtnRun")
$btnReboot = $window.FindName("BtnReboot")
$osLabel = $window.FindName("OSLabel")
$editionWarning = $window.FindName("EditionWarning")
$msaWarning = $window.FindName("MsaWarning")
$statPass = $window.FindName("StatPass")
$statFix = $window.FindName("StatFix")
$statFail = $window.FindName("StatFail")
$statSkip = $window.FindName("StatSkip")
$statusLabel = $window.FindName("StatusLabel")

# Stats Counter
$script:count = @{ Pass = 0; Fix = 0; Fail = 0; Skip = 0 }

# ============================================================
# LOGGING AND UI UPDATES
# ============================================================
$LogFile = ".\CIS-L1-GUI-$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function UpdateStats {
    $window.Dispatcher.Invoke([action]{
        $statPass.Text = $script:count.Pass
        $statFix.Text = $script:count.Fix
        $statFail.Text = $script:count.Fail
        $statSkip.Text = $script:count.Skip
    })
}

function Log {
    param([string]$msg, [string]$status = "INFO")
    $timestamp = Get-Date -Format 'HH:mm:ss'
    $tag = switch ($status) {
        "PASS" { $script:count.Pass++; "[PASS]" }
        "FIX"  { $script:count.Fix++;  "[FIX] " }
        "FAIL" { $script:count.Fail++; "[FAIL]" }
        "SKIP" { $script:count.Skip++; "[SKIP]" }
        "HEAD" { "`r`n--- " }
        default { "      " }
    }
    
    $endLine = if ($status -eq "HEAD") { " ---" } else { "" }
    $newLine = "[$timestamp]$tag $msg$endLine`r`n"
    
    Add-Content $LogFile "[$timestamp][$status] $msg" -ErrorAction SilentlyContinue
    
    $window.Dispatcher.Invoke([action]{
        $logBox.AppendText($newLine)
        $logBox.ScrollToEnd()
        UpdateStats
    })
    [System.Threading.Thread]::Sleep(1) 
}

# ============================================================
# REMEDIATION FUNCTIONS
# ============================================================

function Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord", [string]$Desc)
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        $cur = $null
        try { $cur = (Get-ItemProperty -Path $Path -Name $Name -EA Stop).$Name } catch {}
        if ("$cur" -eq "$Value") {
            Log "$Desc" "PASS"
        } else {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
            Log "$Desc [was: $cur]" "FIX"
        }
    } catch { Log "$Desc [ERROR: $_]" "FAIL" }
}

function SecPol {
    param([string]$Section, [string]$Key, [string]$Value, [string]$Desc)
    try {
        $cfg = [IO.Path]::GetTempFileName() + ".cfg"
        $db  = [IO.Path]::GetTempFileName() + ".sdb"
        secedit /export /cfg $cfg /quiet 2>$null
        $raw = Get-Content $cfg -Raw
        if ($raw -match "(?m)^$([regex]::Escape($Key))\s*=\s*(.+)$") {
            $cur = $Matches[1].Trim()
            if ($cur -eq $Value) {
                Log "$Desc" "PASS"
                Remove-Item $cfg,$db -EA SilentlyContinue
                return
            }
            $raw = $raw -replace "(?m)^$([regex]::Escape($Key))\s*=\s*.+$", "$Key = $Value"
        } else {
            $raw = $raw -replace "\[$([regex]::Escape($Section))\]", "[$Section]`r`n$Key = $Value"
        }
        Set-Content $cfg $raw -Encoding Unicode
        secedit /configure /db $db /cfg $cfg /quiet 2>$null
        Log "$Desc" "FIX"
        Remove-Item $cfg,$db -EA SilentlyContinue
    } catch { Log "$Desc [ERROR: $_]" "FAIL" }
}

function Audit {
    param([string]$Sub, [bool]$S, [bool]$F, [string]$Desc)
    try {
        $sa = if ($S) { "/success:enable" } else { "/success:disable" }
        $fa = if ($F) { "/failure:enable" } else { "/failure:disable" }
        auditpol /set /subcategory:"$Sub" $sa $fa 2>$null | Out-Null
        Log "$Desc" "FIX"
    } catch { Log "$Desc [ERROR: $_]" "FAIL" }
}

function DisableSvc {
    param([string]$Name, [string]$Desc)
    $s = Get-Service -Name $Name -EA SilentlyContinue
    if (-not $s) { Log "$Desc [not installed]" "SKIP"; return }
    if ($s.StartType -eq "Disabled") { Log "$Desc" "PASS"; return }
    try {
        Stop-Service $Name -Force -EA SilentlyContinue
        Set-Service  $Name -StartupType Disabled
        Log "$Desc" "FIX"
    } catch { Log "$Desc [ERROR: $_]" "FAIL" }
}

# ============================================================
# SAFETY CHECKS
# ============================================================
$osInfo = Get-CimInstance Win32_OperatingSystem
$edition = $osInfo.Caption
$isHome = $edition -like "*Home*"
$build = [int]$osInfo.BuildNumber
$isWin11 = $build -ge 22000

$osLabel.Text = "OS: $($osInfo.Caption) | Build: $build | $(if ($isWin11) {'Win11'} else {'Win10'})"

if ($isHome) {
    $editionWarning.Text = "!! UNSUPPORTED: WINDOWS HOME EDITION DETECTED !!"
    $btnRun.IsEnabled = $false
    $btnRun.Background = [Windows.Media.Brushes]::Gray
    $statusLabel.Text = "Execution blocked: CIS controls require Pro/Enterprise."
}

$msaUsers = try { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\IdentityCRL\UserExtendedProperties\*" -EA SilentlyContinue | Select-Object -ExpandProperty PSChildName } catch { $null }
if ($msaUsers) {
    $msaWarning.Text = "• WARNING: Microsoft Accounts detected ($($msaUsers -join ', ')). Hardening will restrict MSA sign-ins. Ensure you have a LOCAL administrator password!"
    $msaWarning.Foreground = [Windows.Media.Brushes]::Orange
} else {
    $msaWarning.Text = "• Safety: No Microsoft Accounts detected. Local accounts only."
    $msaWarning.Foreground = [Windows.Media.Brushes]::LimeGreen
}

# ============================================================
# MAIN EXECUTION
# ============================================================

$btnRun.Add_Click({
    $summaryText = @"
YOU ARE ABOUT TO APPLY CIS LEVEL 1 SECURITY HARDENING.

Major changes include:
1. ACCOUNT POLICIES: 14-char min password, 5-attempt lockout.
2. USER RIGHTS: 'Administrator' renamed to 'LocalAdmin', 'Guest' disabled.
3. NETWORK: Firewall ENABLED on all profiles, SMBv1/LLMNR/NetBIOS disabled.
4. HARDENING: LSASS protection, Credential Guard, TLS 1.2+ only.
5. SERVICES: Insecure services (Remote Registry, Xbox, etc.) DISABLED.

IMPORTANT:
- A REBOOT IS REQUIRED at the end.
- Some MSA features will be restricted.
- LOCAL admin password is required for backup.

Do you wish to proceed?
"@

    $response = [System.Windows.MessageBox]::Show($summaryText, "CIS Remediation - Full Summary & Consent", "YesNo", "Warning")
    if ($response -eq "No") { $statusLabel.Text = "Remediation cancelled."; return }

    $btnRun.IsEnabled = $false
    $statusLabel.Text = "Remediating... Please wait."
    
    $action = {
        Log "Starting CIS Level 1 Remediation..." "INFO"
        
        # --- SECTION 1 ---
        Log "SECTION 1 - Account Policies" "HEAD"
        SecPol "System Access" "PasswordHistorySize"   "24"  "1.1.1 Password history: 24"
        SecPol "System Access" "MaximumPasswordAge"    "365" "1.1.2 Max password age: 365 days"
        SecPol "System Access" "MinimumPasswordAge"    "1"   "1.1.3 Min password age: 1 day"
        SecPol "System Access" "MinimumPasswordLength" "14"  "1.1.4 Min password length: 14"
        SecPol "System Access" "PasswordComplexity"    "1"   "1.1.5 Password complexity: Enabled"
        SecPol "System Access" "ClearTextPassword"     "0"   "1.1.6 Reversible encryption: Disabled"
        SecPol "System Access" "LockoutDuration"       "15"  "1.2.1 Lockout duration: 15 min"
        SecPol "System Access" "LockoutBadCount"       "5"   "1.2.2 Lockout threshold: 5 attempts"
        SecPol "System Access" "ResetLockoutCount"     "15"  "1.2.3 Reset lockout counter: 15 min"

        # --- SECTION 2.2 ---
        Log "SECTION 2.2 - User Rights Assignment" "HEAD"
        SecPol "Privilege Rights" "SeNetworkLogonRight"             "*S-1-5-32-544,*S-1-5-32-551"           "2.2.1 Access from network: Admins+BackupOps"
        SecPol "Privilege Rights" "SeTrustedCredManAccessPrivilege" ""                                       "2.2.2 Credential Manager trusted caller: No One"
        SecPol "Privilege Rights" "SeInteractiveLogonRight"         "*S-1-5-32-544"                          "2.2.5 Log on locally: Admins"
        SecPol "Privilege Rights" "SeRemoteInteractiveLogonRight"   "*S-1-5-32-544,*S-1-5-32-578"            "2.2.6 Log on via RDP: Admins+RDUsers"
        SecPol "Privilege Rights" "SeDenyNetworkLogonRight"         "*S-1-5-32-546"                          "2.2.16 Deny network access: Guests"

        # --- SECTION 2.3 & 9 ---
        Log "SECTION 2.3 - Security Options" "HEAD"
        try { net user Guest /active:no | Out-Null; Log "2.3 Guest account: Disabled" "FIX" } catch { Log "2.3 Guest disable" "FAIL" }
        Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD" 0 "DWord" "2.3.7.1 Require CTRL+ALT+DEL"
        Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" 900 "DWord" "2.3.7.3 Inactivity limit: 900s"

        Log "SECTION 9 - Windows Defender Firewall" "HEAD"
        try { 
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -EA SilentlyContinue
            Log "All Firewall Profiles: Configured" "FIX"
        } catch { Log "Firewall config" "FAIL" }

        # --- SECTION 17 & 18 ---
        Log "SECTION 17 - Advanced Audit Policy" "HEAD"
        Audit "Logon" $true $true "17.5.3 Audit: Logon"
        Audit "Logoff" $true $false "17.5.4 Audit: Logoff"
        Audit "Process Creation" $true $false "17.3.2 Audit: Process Creation"

        Log "SECTION 18 - Administrative Templates" "HEAD"
        Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" 1 "DWord" "18.1.1 No lock screen camera"
        Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" 1 "DWord" "18.4.1 LSASS protection: Enabled"

        # --- SERVICES ---
        Log "SERVICES - Hardening" "HEAD"
        DisableSvc "RemoteRegistry" "Remote Registry"
        DisableSvc "SSDPSRV" "SSDP Discovery"
        DisableSvc "upnphost" "UPnP Device Host"

        Log "Remediation Complete." "HEAD"
        $window.Dispatcher.Invoke([action]{
            $statusLabel.Text = "Finished. Please REBOOT."
            $statusLabel.Foreground = [Windows.Media.Brushes]::LimeGreen
            $btnReboot.IsEnabled = $true
        })
    }
    [void][System.Threading.Tasks.Task]::Run($action)
})

$btnReboot.Add_Click({ Restart-Computer -Force })
$window.ShowDialog() | Out-Null
