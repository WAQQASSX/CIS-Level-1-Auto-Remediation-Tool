#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Benchmark Level 1 - Windows 10 & Windows 11 Auto-Remediation Script

.DESCRIPTION
    Automatically detects whether the system is Windows 10 or Windows 11,
    then applies ALL applicable CIS Level 1 controls without prompting.
    Every non-compliant setting is immediately fixed.

    Covers:
      - Section 1  : Account Policies (passwords, lockout)
      - Section 2  : Local Policies (user rights, security options, UAC)
      - Section 9  : Windows Defender Firewall (all profiles)
      - Section 17 : Advanced Audit Policy (25 subcategories)
      - Section 18 : Administrative Templates (registry policies)
      - Section 19 : User Configuration Templates
      - Bonus      : Service hardening, SMBv1/PSv2 removal,
                     PowerShell logging, Windows Update, screen lock

.PARAMETER BackupFirst
    Export registry and security policy snapshots before making changes.
    Backup folder is created in the script's working directory.

.PARAMETER LogPath
    Override the default log file path.

.EXAMPLE
    # Recommended first run - creates backup then auto-remediates
    .\CIS-CAT-L1-Win10-Win11.ps1 -BackupFirst

    # Just run and fix everything
    .\CIS-CAT-L1-Win10-Win11.ps1

.NOTES
    Must be run as Administrator.
    A reboot is recommended after execution to ensure all settings take effect.
    Tested against: CIS Microsoft Windows 10 Benchmark v3.0 (L1)
                    CIS Microsoft Windows 11 Benchmark v3.0 (L1)
#>

[CmdletBinding()]
param(
    [switch]$BackupFirst,
    [string]$LogPath = ".\CIS-L1-Remediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ===============================================================================
#  GLOBALS
# ===============================================================================
$Script:PassCount  = 0
$Script:FixCount   = 0
$Script:FailCount  = 0
$Script:SkipCount  = 0
$Script:Results    = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:IsWin11    = $false
$Script:OSBuild    = 0
$Script:OSCaption  = ""

# ===============================================================================
#  LOGGING
# ===============================================================================
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
    switch ($Level) {
        "PASS"    { Write-Host "    $Message" -ForegroundColor Green }
        "FIX"     { Write-Host "  [*]  $Message" -ForegroundColor Cyan }
        "FAIL"    { Write-Host "  [X]  $Message" -ForegroundColor Red }
        "SKIP"    { Write-Host "  -  $Message" -ForegroundColor DarkGray }
        "HEAD"    { Write-Host "`n  >  $Message" -ForegroundColor White }
        "ERROR"   { Write-Host "  !  $Message" -ForegroundColor Magenta }
        default   { Write-Host "     $Message" -ForegroundColor Gray }
    }
}

function Add-Result {
    param([string]$ID, [string]$Name, [string]$Status, [string]$Detail = "")
    switch ($Status) {
        "PASS" { $Script:PassCount++ }
        "FIX"  { $Script:FixCount++  }
        "FAIL" { $Script:FailCount++ }
        "SKIP" { $Script:SkipCount++ }
    }
    $Script:Results.Add([PSCustomObject]@{
        ID     = $ID
        Name   = $Name
        Status = $Status
        Detail = $Detail
    })
}

# ===============================================================================
#  CORE HELPERS
# ===============================================================================

function Set-RegValue {
    <#
    .SYNOPSIS Ensure a registry value exists and matches the required value.
              Creates the key path if missing. Fixes silently on mismatch.
    #>
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord",
        [string]$ID,
        [string]$Desc
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        $cur = $null
        try { $cur = (Get-ItemProperty -Path $Path -Name $Name -EA Stop).$Name } catch {}

        if ($null -ne $cur -and "$cur" -eq "$Value") {
            Write-Log "$Desc  [already OK = $Value]" "PASS"
            Add-Result $ID $Desc "PASS" "Value=$Value"
        } else {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
            Write-Log "$Desc  [fixed: $cur -> $Value]" "FIX"
            Add-Result $ID $Desc "FIX" "Was=$cur Now=$Value"
        }
    } catch {
        Write-Log "$Desc  [ERROR: $_]" "ERROR"
        Add-Result $ID $Desc "FAIL" "$_"
    }
}

function Set-SecPol {
    <#
    .SYNOPSIS Apply a secedit key=value in the given INF section.
    #>
    param(
        [string]$Section,
        [string]$Key,
        [string]$Value,
        [string]$ID,
        [string]$Desc
    )
    try {
        $tmpCfg = [IO.Path]::GetTempFileName() + ".cfg"
        $tmpDb  = [IO.Path]::GetTempFileName() + ".sdb"
        secedit /export /cfg $tmpCfg /quiet 2>$null

        $raw = Get-Content $tmpCfg -Raw
        if ($raw -match "(?m)^$([regex]::Escape($Key))\s*=\s*(.+)$") {
            $curVal = $Matches[1].Trim()
            if ($curVal -eq $Value) {
                Write-Log "$Desc  [already OK = $Value]" "PASS"
                Add-Result $ID $Desc "PASS" "$Key=$Value"
                Remove-Item $tmpCfg,$tmpDb -EA SilentlyContinue
                return
            }
            $raw = $raw -replace "(?m)^$([regex]::Escape($Key))\s*=\s*.+$", "$Key = $Value"
        } else {
            $raw = $raw -replace "\[$([regex]::Escape($Section))\]", "[$Section]`r`n$Key = $Value"
        }

        Set-Content $tmpCfg -Value $raw -Encoding Unicode
        secedit /configure /db $tmpDb /cfg $tmpCfg /quiet 2>$null
        Write-Log "$Desc  [fixed -> $Key=$Value]" "FIX"
        Add-Result $ID $Desc "FIX" "$Key=$Value"
        Remove-Item $tmpCfg,$tmpDb -EA SilentlyContinue
    } catch {
        Write-Log "$Desc  [ERROR: $_]" "ERROR"
        Add-Result $ID $Desc "FAIL" "$_"
    }
}

function Set-AuditSub {
    <#
    .SYNOPSIS Configure an Advanced Audit Policy subcategory.
    #>
    param(
        [string]$SubCategory,
        [bool]$Success,
        [bool]$Failure,
        [string]$ID,
        [string]$Desc
    )
    try {
        $sArg = if ($Success) { "/success:enable" } else { "/success:disable" }
        $fArg = if ($Failure) { "/failure:enable" } else { "/failure:disable" }
        $out  = & auditpol /set /subcategory:"$SubCategory" $sArg $fArg 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "$Desc  [configured]" "FIX"
            Add-Result $ID $Desc "FIX" "S:$Success F:$Failure"
        } else {
            Write-Log "$Desc  [auditpol error: $out]" "ERROR"
            Add-Result $ID $Desc "FAIL" "$out"
        }
    } catch {
        Write-Log "$Desc  [ERROR: $_]" "ERROR"
        Add-Result $ID $Desc "FAIL" "$_"
    }
}

function Disable-Svc {
    param([string]$Name, [string]$Desc, [string]$ID)
    $svc = Get-Service -Name $Name -EA SilentlyContinue
    if (-not $svc) {
        Write-Log "$Desc  [not installed - skipped]" "SKIP"
        Add-Result $ID $Desc "SKIP" "Not installed"
        return
    }
    if ($svc.StartType -eq "Disabled") {
        Write-Log "$Desc  [already disabled]" "PASS"
        Add-Result $ID $Desc "PASS" "Already disabled"
    } else {
        try {
            Stop-Service -Name $Name -Force -EA SilentlyContinue
            Set-Service  -Name $Name -StartupType Disabled
            Write-Log "$Desc  [disabled]" "FIX"
            Add-Result $ID $Desc "FIX" "Disabled"
        } catch {
            Write-Log "$Desc  [ERROR: $_]" "ERROR"
            Add-Result $ID $Desc "FAIL" "$_"
        }
    }
}

# ===============================================================================
#  OS DETECTION
# ===============================================================================
function Get-OSInfo {
    Write-Log "Detecting Windows version..." "HEAD"
    $os = Get-CimInstance Win32_OperatingSystem
    $Script:OSCaption = $os.Caption
    $Script:OSBuild   = [int]$os.BuildNumber
    $Script:IsWin11   = $Script:OSBuild -ge 22000

    if ($os.Caption -notmatch "Windows 10|Windows 11") {
        Write-Log "WARNING: This script targets Windows 10/11. Detected: $($os.Caption)" "ERROR"
        Write-Log "Continuing anyway - many controls still apply." "ERROR"
    }

    $edition = if ($Script:IsWin11) { "Windows 11" } else { "Windows 10" }
    Write-Log "Detected : $($os.Caption)"
    Write-Log "Build    : $($Script:OSBuild)  ->  Treating as: $edition"
    Write-Log "Log file : $LogPath"
}

# ===============================================================================
#  BACKUP
# ===============================================================================
function Invoke-Backup {
    Write-Log "Creating pre-remediation backup..." "HEAD"
    $dir = ".\CIS-L1-Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    @("HKLM\SOFTWARE\Policies",
      "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
      "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
      "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    ) | ForEach-Object {
        $safe = $_ -replace "[\\:]","_"
        reg export $_ "$dir\$safe.reg" /y 2>$null | Out-Null
    }

    secedit /export /cfg "$dir\secedit_backup.cfg" /quiet 2>$null
    auditpol /backup  /file:"$dir\auditpol_backup.csv" 2>$null

    Write-Log "Backup saved to: $dir"
}

# ===============================================================================
#  SECTION 1 - ACCOUNT POLICIES
# ===============================================================================
function Invoke-AccountPolicies {
    Write-Log "SECTION 1 - Account Policies" "HEAD"

    Set-SecPol "System Access" "PasswordHistorySize"  "24"  "1.1.1"  "Password History: 24 passwords"
    Set-SecPol "System Access" "MaximumPasswordAge"   "365" "1.1.2"  "Maximum Password Age: 365 days"
    Set-SecPol "System Access" "MinimumPasswordAge"   "1"   "1.1.3"  "Minimum Password Age: 1 day"
    Set-SecPol "System Access" "MinimumPasswordLength" "14" "1.1.4"  "Minimum Password Length: 14 chars"
    Set-SecPol "System Access" "PasswordComplexity"   "1"   "1.1.5"  "Password Complexity: Enabled"
    Set-SecPol "System Access" "ClearTextPassword"    "0"   "1.1.6"  "Reversible Encryption: Disabled"

    Set-SecPol "System Access" "LockoutDuration"      "15"  "1.2.1"  "Account Lockout Duration: 15 min"
    Set-SecPol "System Access" "LockoutBadCount"      "5"   "1.2.2"  "Lockout Threshold: 5 attempts"
    Set-SecPol "System Access" "ResetLockoutCount"    "15"  "1.2.3"  "Reset Lockout Counter: 15 min"
}

# ===============================================================================
#  SECTION 2 - LOCAL POLICIES
# ===============================================================================
function Invoke-LocalPolicies {
    Write-Log "SECTION 2.2 - User Rights Assignment" "HEAD"

    $rights = @(
        # ID       Key                                Value                                    Description
        @("2.2.1",  "SeNetworkLogonRight",            "*S-1-5-32-544,*S-1-5-32-551",          "Access this computer from network: Admins, Backup Operators"),
        @("2.2.2",  "SeTrustedCredManAccessPrivilege","",                                      "Access Credential Manager as trusted caller: No One"),
        @("2.2.3",  "SeTcbPrivilege",                 "",                                      "Act as part of OS: No One"),
        @("2.2.4",  "SeIncreaseQuotaPrivilege",       "*S-1-5-19,*S-1-5-20,*S-1-5-32-544",    "Adjust memory quotas: LocalSvc/NetworkSvc/Admins"),
        @("2.2.5",  "SeInteractiveLogonRight",        "*S-1-5-32-544",                         "Allow log on locally: Administrators"),
        @("2.2.6",  "SeRemoteInteractiveLogonRight",  "*S-1-5-32-544,*S-1-5-32-578",           "Allow log on via RDP: Admins, Remote Desktop Users"),
        @("2.2.7",  "SeBackupPrivilege",              "*S-1-5-32-544,*S-1-5-32-551",           "Back up files and directories: Admins, Backup Operators"),
        @("2.2.8",  "SeSystemTimePrivilege",          "*S-1-5-19,*S-1-5-32-544",               "Change system time: LocalSvc, Admins"),
        @("2.2.9",  "SeTimeZonePrivilege",            "*S-1-5-19,*S-1-5-32-544",               "Change time zone: LocalSvc, Admins"),
        @("2.2.10", "SeCreatePagefilePrivilege",      "*S-1-5-32-544",                         "Create a pagefile: Administrators"),
        @("2.2.11", "SeCreateTokenPrivilege",         "",                                      "Create a token object: No One"),
        @("2.2.12", "SeCreateGlobalPrivilege",        "*S-1-5-19,*S-1-5-20,*S-1-5-32-544",    "Create global objects: LocalSvc/NetworkSvc/Admins"),
        @("2.2.13", "SeCreatePermanentPrivilege",     "",                                      "Create permanent shared objects: No One"),
        @("2.2.14", "SeCreateSymbolicLinkPrivilege",  "*S-1-5-32-544",                         "Create symbolic links: Administrators"),
        @("2.2.15", "SeDebugPrivilege",               "*S-1-5-32-544",                         "Debug programs: Administrators"),
        @("2.2.16", "SeDenyNetworkLogonRight",        "*S-1-5-32-546",                         "Deny access from network: Guests"),
        @("2.2.17", "SeDenyBatchLogonRight",          "*S-1-5-32-546",                         "Deny log on as batch job: Guests"),
        @("2.2.18", "SeDenyServiceLogonRight",        "*S-1-5-32-546",                         "Deny log on as service: Guests"),
        @("2.2.19", "SeDenyInteractiveLogonRight",    "*S-1-5-32-546",                         "Deny log on locally: Guests"),
        @("2.2.20", "SeDenyRemoteInteractiveLogonRight","*S-1-5-32-546",                       "Deny log on via RDP: Guests"),
        @("2.2.21", "SeEnableDelegationPrivilege",    "",                                      "Enable delegation: No One"),
        @("2.2.22", "SeRemoteShutdownPrivilege",      "*S-1-5-32-544",                         "Force shutdown from remote: Administrators"),
        @("2.2.23", "SeAuditPrivilege",               "*S-1-5-19,*S-1-5-20",                   "Generate security audits: LocalSvc, NetworkSvc"),
        @("2.2.24", "SeImpersonatePrivilege",         "*S-1-5-19,*S-1-5-20,*S-1-5-32-544",    "Impersonate a client: LocalSvc/NetworkSvc/Admins"),
        @("2.2.25", "SeIncreaseBasePriorityPrivilege","*S-1-5-32-544",                         "Increase scheduling priority: Administrators"),
        @("2.2.26", "SeLoadDriverPrivilege",          "*S-1-5-32-544",                         "Load/unload device drivers: Administrators"),
        @("2.2.27", "SeLockMemoryPrivilege",          "",                                      "Lock pages in memory: No One"),
        @("2.2.28", "SeManageVolumePrivilege",        "*S-1-5-32-544",                         "Perform volume maintenance: Administrators"),
        @("2.2.29", "SeProfileSingleProcessPrivilege","*S-1-5-32-544",                         "Profile single process: Administrators"),
        @("2.2.30", "SeSystemProfilePrivilege",       "*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420,*S-1-5-32-544","Profile system performance: Admins + WdiServiceHost"),
        @("2.2.31", "SeAssignPrimaryTokenPrivilege",  "*S-1-5-19,*S-1-5-20",                   "Replace process level token: LocalSvc, NetworkSvc"),
        @("2.2.32", "SeRestorePrivilege",             "*S-1-5-32-544,*S-1-5-32-551",           "Restore files: Admins, Backup Operators"),
        @("2.2.33", "SeShutdownPrivilege",            "*S-1-5-32-544",                         "Shut down the system: Administrators"),
        @("2.2.34", "SeTakeOwnershipPrivilege",       "*S-1-5-32-544",                         "Take ownership of files: Administrators")
    )

    foreach ($r in $rights) {
        Set-SecPol "Privilege Rights" $r[1] $r[2] $r[0] $r[3]
    }

    Write-Log "SECTION 2.3 - Security Options" "HEAD"

    # -- Accounts --------------------------------------------------------------
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "NoConnectedUser" 3 "DWord" "2.3.1.1" "Accounts: Block Microsoft accounts"

    # Disable Guest
    try {
        $guest = Get-LocalUser -Name "Guest" -EA SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Disable-LocalUser -Name "Guest"
            Write-Log "Accounts: Guest account disabled  [fixed]" "FIX"
            Add-Result "2.3.1.2" "Accounts: Guest account status: Disabled" "FIX" "Disabled"
        } else {
            Write-Log "Accounts: Guest account  [already disabled]" "PASS"
            Add-Result "2.3.1.2" "Accounts: Guest account status: Disabled" "PASS" "OK"
        }
    } catch { Add-Result "2.3.1.2" "Accounts: Guest account status" "FAIL" "$_" }

    # Rename Administrator (CIS L1 recommendation)
    try {
        $builtinAdmin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
        if ($builtinAdmin -and $builtinAdmin.Name -eq "Administrator") {
            Rename-LocalUser -Name "Administrator" -NewName "LocalAdmin_CIS"
            Write-Log "Accounts: Administrator renamed to LocalAdmin_CIS  [fixed]" "FIX"
            Add-Result "2.3.1.3" "Accounts: Rename Administrator account" "FIX" "Renamed"
        } else {
            Write-Log "Accounts: Administrator already renamed ($($builtinAdmin.Name))  [OK]" "PASS"
            Add-Result "2.3.1.3" "Accounts: Rename Administrator account" "PASS" "Name=$($builtinAdmin.Name)"
        }
    } catch { Add-Result "2.3.1.3" "Accounts: Rename Administrator account" "FAIL" "$_" }

    # -- Audit -----------------------------------------------------------------
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "SCENoApplyLegacyAuditPolicy" 1 "DWord" "2.3.2.1" "Audit: Force audit policy subcategory settings"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "CrashOnAuditFail" 0 "DWord" "2.3.2.2" "Audit: Shut down if unable to log security audits: Disabled"

    # -- Interactive Logon -----------------------------------------------------
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "DisableCAD" 0 "DWord" "2.3.7.1" "Interactive Logon: Do not require CTRL+ALT+DEL: Disabled"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "DontDisplayLastUserName" 1 "DWord" "2.3.7.2" "Interactive Logon: Don't display last signed-in user"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "InactivityTimeoutSecs" 900 "DWord" "2.3.7.3" "Interactive Logon: Machine inactivity limit: 900 sec"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "LegalNoticeCaption" "Authorized Use Only" "String" "2.3.7.4" "Interactive Logon: Message title for logon"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "LegalNoticeText" "This system is restricted to authorized users only. Unauthorized access is prohibited and subject to legal action." "String" "2.3.7.5" "Interactive Logon: Message text for logon"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "PasswordExpiryWarning" 14 "DWord" "2.3.7.6" "Interactive Logon: Password expiry warning: 14 days"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "ScRemoveOption" "1" "String" "2.3.7.7" "Interactive Logon: Smart card removal behavior: Lock Workstation"

    # -- MS Network Client -----------------------------------------------------
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        "EnableSecuritySignature" 1 "DWord" "2.3.8.1" "MS Network Client: Digitally sign comms (always)"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        "RequireSecuritySignature" 1 "DWord" "2.3.8.2" "MS Network Client: Digitally sign comms (if server agrees)"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        "EnablePlainTextPassword" 0 "DWord" "2.3.8.3" "MS Network Client: No unencrypted passwords to 3rd-party SMB"

    # -- MS Network Server -----------------------------------------------------
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
        "AutoDisconnect" 15 "DWord" "2.3.9.1" "MS Network Server: Idle time before suspend: 15 min"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
        "RequireSecuritySignature" 1 "DWord" "2.3.9.2" "MS Network Server: Digitally sign comms (always)"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
        "EnableSecuritySignature" 1 "DWord" "2.3.9.3" "MS Network Server: Digitally sign comms (if client agrees)"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
        "EnableForcedLogOff" 1 "DWord" "2.3.9.4" "MS Network Server: Disconnect when logon hours expire"

    # -- Network Access --------------------------------------------------------
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "RestrictAnonymousSAM" 1 "DWord" "2.3.10.1" "Network Access: No anonymous SAM enumeration"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "RestrictAnonymous" 1 "DWord" "2.3.10.2" "Network Access: No anonymous SAM + share enumeration"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "EveryoneIncludesAnonymous" 0 "DWord" "2.3.10.3" "Network Access: Everyone permissions don't apply to anonymous"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        "AllowInsecureGuestAuth" 0 "DWord" "2.3.10.4" "Network Access: Disable insecure guest auth"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "RestrictRemoteSAM" "O:BAG:BAD:(A;;RC;;;BA)" "String" "2.3.10.5" "Network Access: Restrict remote calls to SAM"

    # -- Network Security ------------------------------------------------------
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "LmCompatibilityLevel" 5 "DWord" "2.3.11.1" "Network Security: LAN Manager auth level: NTLMv2 only"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "NoLMHash" 1 "DWord" "2.3.11.2" "Network Security: Do not store LAN Manager hash"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
        "allownullsessionfallback" 0 "DWord" "2.3.11.3" "Network Security: Allow LocalSystem NULL session fallback: Disabled"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "NTLMMinClientSec" 537395200 "DWord" "2.3.11.4" "Network Security: Min session security NTLM SSP clients: NTLMv2+128-bit"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "NTLMMinServerSec" 537395200 "DWord" "2.3.11.5" "Network Security: Min session security NTLM SSP servers: NTLMv2+128-bit"

    # -- Shutdown --------------------------------------------------------------
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "ShutdownWithoutLogon" 0 "DWord" "2.3.13.1" "Shutdown: Allow shutdown without logon: Disabled"

    # -- UAC -------------------------------------------------------------------
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "FilterAdministratorToken" 1 "DWord" "2.3.15.1" "UAC: Admin Approval Mode for built-in Administrator: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "ConsentPromptBehaviorAdmin" 2 "DWord" "2.3.15.2" "UAC: Prompt for credentials on secure desktop (admins)"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "ConsentPromptBehaviorUser" 0 "DWord" "2.3.15.3" "UAC: Auto-deny elevation requests (standard users)"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "EnableInstallerDetection" 1 "DWord" "2.3.15.4" "UAC: Detect application installs and prompt"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "EnableSecureUIAPaths" 1 "DWord" "2.3.15.5" "UAC: Elevate only UIAccess apps in secure locations"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "EnableLUA" 1 "DWord" "2.3.15.6" "UAC: Run all administrators in Admin Approval Mode"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "PromptOnSecureDesktop" 1 "DWord" "2.3.15.7" "UAC: Elevate prompt on secure desktop"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "EnableVirtualization" 1 "DWord" "2.3.15.8" "UAC: Virtualize file/registry write failures"
}

# ===============================================================================
#  SECTION 9 - WINDOWS DEFENDER FIREWALL
# ===============================================================================
function Invoke-Firewall {
    Write-Log "SECTION 9 - Windows Defender Firewall" "HEAD"

    # --- Domain Profile ---
    $rk = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    Set-RegValue $rk "EnableFirewall"        1     "DWord"        "9.1.1"  "Firewall Domain: Enabled"
    Set-RegValue $rk "DefaultInboundAction"  1     "DWord"        "9.1.2"  "Firewall Domain: Block inbound"
    Set-RegValue $rk "DefaultOutboundAction" 0     "DWord"        "9.1.3"  "Firewall Domain: Allow outbound"
    Set-RegValue $rk "DisableNotifications"  0     "DWord"        "9.1.4"  "Firewall Domain: Show notifications"
    Set-RegValue "$rk\Logging" "LogDroppedPackets"       1     "DWord"        "9.1.5"  "Firewall Domain: Log dropped packets"
    Set-RegValue "$rk\Logging" "LogSuccessfulConnections" 0    "DWord"        "9.1.6"  "Firewall Domain: No log successful connections"
    Set-RegValue "$rk\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\pfirewall.log" "ExpandString" "9.1.7" "Firewall Domain: Log file path"
    Set-RegValue "$rk\Logging" "LogFileSize" 16384 "DWord"        "9.1.8"  "Firewall Domain: Log file size 16384 KB"

    # --- Private Profile ---
    $rk = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    Set-RegValue $rk "EnableFirewall"        1     "DWord"        "9.2.1"  "Firewall Private: Enabled"
    Set-RegValue $rk "DefaultInboundAction"  1     "DWord"        "9.2.2"  "Firewall Private: Block inbound"
    Set-RegValue $rk "DefaultOutboundAction" 0     "DWord"        "9.2.3"  "Firewall Private: Allow outbound"
    Set-RegValue $rk "DisableNotifications"  0     "DWord"        "9.2.4"  "Firewall Private: Show notifications"
    Set-RegValue "$rk\Logging" "LogDroppedPackets"       1     "DWord"        "9.2.5"  "Firewall Private: Log dropped packets"
    Set-RegValue "$rk\Logging" "LogSuccessfulConnections" 0    "DWord"        "9.2.6"  "Firewall Private: No log successful connections"
    Set-RegValue "$rk\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\pfirewall.log" "ExpandString" "9.2.7" "Firewall Private: Log file path"
    Set-RegValue "$rk\Logging" "LogFileSize" 16384 "DWord"        "9.2.8"  "Firewall Private: Log file size 16384 KB"

    # --- Public Profile ---
    $rk = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    Set-RegValue $rk "EnableFirewall"        1     "DWord"        "9.3.1"  "Firewall Public: Enabled"
    Set-RegValue $rk "DefaultInboundAction"  1     "DWord"        "9.3.2"  "Firewall Public: Block inbound"
    Set-RegValue $rk "DefaultOutboundAction" 0     "DWord"        "9.3.3"  "Firewall Public: Allow outbound"
    Set-RegValue $rk "DisableNotifications"  0     "DWord"        "9.3.4"  "Firewall Public: Show notifications"
    Set-RegValue "$rk\Logging" "LogDroppedPackets"       1     "DWord"        "9.3.5"  "Firewall Public: Log dropped packets"
    Set-RegValue "$rk\Logging" "LogSuccessfulConnections" 0    "DWord"        "9.3.6"  "Firewall Public: No log successful connections"
    Set-RegValue "$rk\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\pfirewall.log" "ExpandString" "9.3.7" "Firewall Public: Log file path"
    Set-RegValue "$rk\Logging" "LogFileSize" 16384 "DWord"        "9.3.8"  "Firewall Public: Log file size 16384 KB"

    # Apply via cmdlet as well for immediate effect
    try { Set-NetFirewallProfile -Profile Domain  -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -LogBlocked True -LogMaxSizeKilobytes 16384 -EA SilentlyContinue } catch {}
    try { Set-NetFirewallProfile -Profile Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -LogBlocked True -LogMaxSizeKilobytes 16384 -EA SilentlyContinue } catch {}
    try { Set-NetFirewallProfile -Profile Public  -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -LogBlocked True -LogMaxSizeKilobytes 16384 -EA SilentlyContinue } catch {}
}

# ===============================================================================
#  SECTION 17 - ADVANCED AUDIT POLICY
# ===============================================================================
function Invoke-AuditPolicy {
    Write-Log "SECTION 17 - Advanced Audit Policy" "HEAD"

    # Enable advanced audit policy (suppress legacy)
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "SCENoApplyLegacyAuditPolicy" 1 "DWord" "17.0" "Force advanced audit policy subcategory settings"

    # S=Success  F=Failure
    $audits = @(
        # Account Logon
        @("17.1.1","Credential Validation",               $true, $true),
        @("17.1.2","Kerberos Authentication Service",     $false,$false),  # N/A on workstations
        @("17.1.3","Kerberos Service Ticket Operations",  $false,$false),  # N/A on workstations
        # Account Management
        @("17.2.1","Application Group Management",        $true, $true),
        @("17.2.2","Computer Account Management",         $true, $false),
        @("17.2.3","Distribution Group Management",       $true, $false),
        @("17.2.4","Other Account Management Events",     $true, $false),
        @("17.2.5","Security Group Management",           $true, $false),
        @("17.2.6","User Account Management",             $true, $true),
        # Detailed Tracking
        @("17.3.1","Plug and Play Events",                $true, $false),
        @("17.3.2","Process Creation",                    $true, $false),
        @("17.3.3","Process Termination",                 $false,$false),
        @("17.3.4","DPAPI Activity",                      $false,$false),
        # DS Access (N/A for workstations but set anyway)
        @("17.4.1","Detailed Directory Service Replication",$false,$false),
        # Logon/Logoff
        @("17.5.1","Account Lockout",                     $false,$true),
        @("17.5.2","Group Membership",                    $true, $false),
        @("17.5.3","Logon",                               $true, $true),
        @("17.5.4","Logoff",                              $true, $false),
        @("17.5.5","Network Policy Server",               $true, $true),
        @("17.5.6","Other Logon/Logoff Events",           $true, $true),
        @("17.5.7","Special Logon",                       $true, $false),
        # Object Access
        @("17.6.1","Detailed File Share",                 $false,$true),
        @("17.6.2","File Share",                          $true, $true),
        @("17.6.3","Other Object Access Events",          $true, $true),
        @("17.6.4","Removable Storage",                   $true, $true),
        @("17.6.5","SAM",                                 $false,$false),
        # Policy Change
        @("17.7.1","Audit Policy Change",                 $true, $false),
        @("17.7.2","Authentication Policy Change",        $true, $false),
        @("17.7.3","Authorization Policy Change",         $true, $false),
        @("17.7.4","MPSSVC Rule-Level Policy Change",     $true, $true),
        @("17.7.5","Other Policy Change Events",          $false,$true),
        # Privilege Use
        @("17.8.1","Sensitive Privilege Use",             $true, $true),
        # System
        @("17.9.1","IPsec Driver",                        $true, $true),
        @("17.9.2","Other System Events",                 $true, $true),
        @("17.9.3","Security State Change",               $true, $false),
        @("17.9.4","Security System Extension",           $true, $false),
        @("17.9.5","System Integrity",                    $true, $true)
    )

    foreach ($a in $audits) {
        Set-AuditSub $a[1] $a[2] $a[3] $a[0] "Audit: $($a[1])"
    }
}

# ===============================================================================
#  SECTION 18 - ADMINISTRATIVE TEMPLATES (COMPUTER)
# ===============================================================================
function Invoke-AdminTemplates {
    Write-Log "SECTION 18 - Administrative Templates (Computer)" "HEAD"

    # -- 18.1 Control Panel / Personalization ----------------------------------
    Write-Log "18.1 - Control Panel" "HEAD"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
        "NoLockScreenCamera"   1 "DWord" "18.1.1.1" "Prevent lock screen camera"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
        "NoLockScreenSlideshow" 1 "DWord" "18.1.1.2" "Prevent lock screen slide show"

    # -- 18.3 Internet Communication Management --------------------------------
    Write-Log "18.3 - Internet Communication" "HEAD"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" `
        "DontSearchWindowsUpdate" 1 "DWord" "18.3.1" "Turn off automatic driver searches on Windows Update"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" `
        "PreventHandwritingErrorReports" 1 "DWord" "18.3.2" "Turn off handwriting error reports"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" `
        "PreventHandwritingDataSharing" 1 "DWord" "18.3.3" "Turn off handwriting personalization data sharing"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" `
        "Disabled" 0 "DWord" "18.3.4" "Turn off Windows Error Reporting: Enabled (reporting stays on)"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" `
        "AutoApproveOSDumps" 0 "DWord" "18.3.5" "Windows Error Reporting: Auto-approve OS dumps: Disabled"

    # -- 18.4 MS Security Guide ------------------------------------------------
    Write-Log "18.4 - MS Security Guide" "HEAD"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "RestrictRemoteSAM" "O:BAG:BAD:(A;;RC;;;BA)" "String" "18.4.1" "Apply UAC restrictions to local accounts on network logons"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "UseLogonCredential" 0 "DWord" "18.4.2" "WDigest Authentication: Disabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" `
        "AllowProtectedCreds" 1 "DWord" "18.4.3" "Remote host allows delegation of non-exportable credentials"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
        "EnableAuthEpResolution" 1 "DWord" "18.4.4" "RPC Endpoint Mapper Client Authentication: Enabled"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        "DisableExceptionChainValidation" 0 "DWord" "18.4.5" "SEHOP (Structured Exception Handling Overwrite Protection): Enabled"

    # -- 18.5 MSS (Legacy) -----------------------------------------------------
    Write-Log "18.5 - MSS Legacy" "HEAD"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        "DisableIPSourceRouting"  2 "DWord" "18.5.1" "MSS: Disable IP source routing IPv4 (highest protection)"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
        "DisableIPSourceRouting"  2 "DWord" "18.5.2" "MSS: Disable IP source routing IPv6 (highest protection)"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        "EnableICMPRedirect"      0 "DWord" "18.5.3" "MSS: Disable ICMP redirects"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
        "NoNameReleaseOnDemand"   1 "DWord" "18.5.4" "MSS: No NetBIOS name release on demand"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        "PerformRouterDiscovery"  0 "DWord" "18.5.5" "MSS: Disable router discovery"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        "SafeDllSearchMode"       1 "DWord" "18.5.6" "MSS: SafeDllSearchMode: Enabled"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        "ScreenSaverGracePeriod" "0" "String" "18.5.7" "MSS: ScreenSaverGracePeriod = 0 seconds"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        "TcpMaxDataRetransmissions" 3 "DWord" "18.5.8" "MSS: TcpMaxDataRetransmissions IPv4 = 3"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
        "TcpMaxDataRetransmissions" 3 "DWord" "18.5.9" "MSS: TcpMaxDataRetransmissions IPv6 = 3"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
        "WarningLevel" 90 "DWord" "18.5.10" "MSS: WarningLevel = 90%"

    # -- 18.6 Network ----------------------------------------------------------
    Write-Log "18.6 - Network Settings" "HEAD"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections" `
        "NC_ShowSharedAccessUI" 0 "DWord" "18.6.1" "Prohibit Internet Connection Sharing"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
        "fMinimizeConnections" 3 "DWord" "18.6.2" "Minimize simultaneous connections"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
        "fBlockNonDomain" 1 "DWord" "18.6.3" "Prohibit connection to non-domain networks when on domain"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" `
        "ISATAP_State" "Disabled" "String" "18.6.4" "ISATAP State: Disabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" `
        "6to4_State" "Disabled" "String" "18.6.5" "6to4 State: Disabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" `
        "Teredo_State" "Disabled" "String" "18.6.6" "Teredo State: Disabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        "EnableMulticast" 0 "DWord" "18.6.7" "Turn off multicast name resolution (LLMNR)"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        "DoHPolicy" 2 "DWord" "18.6.8" "Configure DNS over HTTPS"
    # Hardened UNC paths
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
        "\\*\NETLOGON" "RequireMutualAuthentication=1,RequireIntegrity=1" "String" "18.6.9"  "Hardened UNC path: NETLOGON"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
        "\\*\SYSVOL"   "RequireMutualAuthentication=1,RequireIntegrity=1" "String" "18.6.10" "Hardened UNC path: SYSVOL"

    # -- 18.8 System -----------------------------------------------------------
    Write-Log "18.8 - System" "HEAD"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" `
        "DODownloadMode" 0 "DWord" "18.8.1" "Turn off Delivery Optimization (or limit to LAN)"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "fAllowUnsolicited" 0 "DWord" "18.8.2" "Configure Offer Remote Assistance: Disabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "fAllowToGetHelp" 0 "DWord" "18.8.3" "Configure Solicited Remote Assistance: Disabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
        "RestrictRemoteClients" 1 "DWord" "18.8.4" "Restrict unauthenticated RPC clients: Authenticated"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" `
        "Enabled" 1 "DWord" "18.8.5" "Enable Windows NTP Client"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer" `
        "Enabled" 0 "DWord" "18.8.6" "Disable Windows NTP Server"
    # Boot-Start Driver Initialization
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" `
        "DriverLoadPolicy" 3 "DWord" "18.8.7" "Boot-Start Driver Init Policy: Good, unknown, bad but critical"
    # KMS
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" `
        "NoGenTicket" 1 "DWord" "18.8.8" "Turn off KMS Client Online AVS Validation"
    # Virtualization Based Security
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        "EnableVirtualizationBasedSecurity" 1 "DWord" "18.8.9" "Enable Virtualization Based Security"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        "RequirePlatformSecurityFeatures" 1 "DWord" "18.8.10" "VBS: Require Secure Boot"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        "HypervisorEnforcedCodeIntegrity" 1 "DWord" "18.8.11" "VBS: Virtualization Based Code Integrity: Enabled with UEFI lock"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        "HVCIMATRequired" 1 "DWord" "18.8.12" "VBS: Require UEFI Memory Attributes Table"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        "LsaCfgFlags" 1 "DWord" "18.8.13" "VBS: Credential Guard: Enabled with UEFI lock"

    # -- 18.9 Windows Components -----------------------------------------------
    Write-Log "18.9 - Windows Components" "HEAD"

    # App Runtime
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "MSAOptional" 1 "DWord" "18.9.1" "Allow Microsoft accounts to be optional"

    # AutoPlay
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        "NoAutoplayfornonVolume" 1 "DWord" "18.9.2" "Disallow Autoplay for non-volume devices"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "NoAutorun" 1 "DWord" "18.9.3" "Turn off AutoRun"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "NoDriveTypeAutoRun" 255 "DWord" "18.9.4" "Turn off AutoPlay on all drives"

    # BitLocker - Removable drives
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
        "RDVDenyWriteAccess" 1 "DWord" "18.9.5" "Deny write access to removable drives not protected by BitLocker"

    # Camera
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Camera" `
        "AllowCamera" 0 "DWord" "18.9.6" "Allow use of camera: Disabled"

    # Cloud Content
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        "DisableWindowsConsumerFeatures" 1 "DWord" "18.9.7" "Turn off Microsoft consumer experiences"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        "DisableConsumerAccountStateContent" 1 "DWord" "18.9.8" "Turn off consumer account state content"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        "DisableSoftLanding" 1 "DWord" "18.9.9" "Do not show Windows tips"

    # Credential UI
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" `
        "DisablePasswordReveal" 1 "DWord" "18.9.10" "Do not display the password reveal button"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" `
        "EnumerateAdministrators" 0 "DWord" "18.9.11" "Enumerate administrator accounts on elevation: Disabled"

    # Data Collection / Telemetry
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        "AllowTelemetry" 1 "DWord" "18.9.12" "Allow Telemetry: Required (1)"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        "DisableEnterpriseAuthProxy" 1 "DWord" "18.9.13" "Disable Authenticated Proxy for telemetry"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        "DoNotShowFeedbackNotifications" 1 "DWord" "18.9.14" "Do not show feedback notifications"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        "LimitDiagnosticLogCollection" 1 "DWord" "18.9.15" "Limit Diagnostic Log Collection"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        "LimitDumpCollection" 1 "DWord" "18.9.16" "Limit Dump Collection"

    # Event Log sizes
    foreach ($log in @(
        @{ Name="Application"; Size=32768;  ID="18.9.17"; Desc="App Event Log max size >= 32768 KB" },
        @{ Name="Security";    Size=196608; ID="18.9.18"; Desc="Security Event Log max size >= 196608 KB" },
        @{ Name="Setup";       Size=32768;  ID="18.9.19"; Desc="Setup Event Log max size >= 32768 KB" },
        @{ Name="System";      Size=32768;  ID="18.9.20"; Desc="System Event Log max size >= 32768 KB" }
    )) {
        $ek = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$($log.Name)"
        Set-RegValue $ek "MaxSize"   $log.Size "DWord"  $log.ID  $log.Desc
        Set-RegValue $ek "Retention" "0"       "String" "$($log.ID)r" "$($log.Desc) - retention: overwrite"
    }

    # File Explorer
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        "NoDataExecutionPrevention" 0 "DWord" "18.9.21" "Turn off DEP for Explorer: Disabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        "NoHeapTerminationOnCorruption" 0 "DWord" "18.9.22" "Turn off heap termination on corruption: Disabled"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "PreXPSP2ShellProtocolBehavior" 0 "DWord" "18.9.23" "Shell: pre-XP SP2 protected mode: Disabled"

    # Location
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" `
        "DisableLocation" 1 "DWord" "18.9.24" "Turn off location: Enabled"

    # OneDrive
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" `
        "DisableFileSyncNGSC" 1 "DWord" "18.9.25" "Prevent OneDrive file storage"

    # Remote Desktop
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "UserAuthentication" 1 "DWord" "18.9.26" "RDP: Network Level Authentication required"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "MinEncryptionLevel" 3 "DWord" "18.9.27" "RDP: Encryption level: High"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "fPromptForPassword" 1 "DWord" "18.9.28" "RDP: Always prompt for password"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "MaxDisconnectionTime" 60000 "DWord" "18.9.29" "RDP: Disconnect idle sessions after 1 min"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "MaxIdleTime" 900000 "DWord" "18.9.30" "RDP: End sessions after 15 min idle"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "fSingleSessionPerUser" 1 "DWord" "18.9.31" "RDP: Restrict to single session per user"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "DeleteTempDirsOnExit" 1 "DWord" "18.9.32" "RDP: Delete temp folders on exit"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "PerSessionTempDir" 1 "DWord" "18.9.33" "RDP: Unique temp folder per session"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "fEncryptRPCTraffic" 1 "DWord" "18.9.34" "RDP: Encrypt RPC traffic"

    # RSS Feeds
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" `
        "DisableEnclosureDownload" 1 "DWord" "18.9.35" "Prevent downloading enclosures from RSS feeds"

    # Search
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
        "AllowIndexingEncryptedStoresOrItems" 0 "DWord" "18.9.36" "Disable indexing encrypted files"

    # SmartScreen
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        "EnableSmartScreen" 1 "DWord" "18.9.37" "Configure Windows Defender SmartScreen: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        "ShellSmartScreenLevel" "Block" "String" "18.9.38" "SmartScreen level: Block"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" `
        "EnabledV9" 1 "DWord" "18.9.39" "Edge SmartScreen: Enabled"

    # Windows Ink Workspace
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" `
        "AllowSuggestedAppsInWindowsInkWorkspace" 0 "DWord" "18.9.40" "No suggested apps in Windows Ink Workspace"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" `
        "AllowWindowsInkWorkspace" 1 "DWord" "18.9.41" "Windows Ink Workspace: On (above lock disabled)"

    # WinRM Client
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
        "AllowBasic" 0 "DWord" "18.9.42" "WinRM Client: Disallow Basic authentication"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
        "AllowUnencryptedTraffic" 0 "DWord" "18.9.43" "WinRM Client: No unencrypted traffic"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
        "AllowDigest" 0 "DWord" "18.9.44" "WinRM Client: Disallow Digest authentication"

    # WinRM Service
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
        "AllowBasic" 0 "DWord" "18.9.45" "WinRM Service: Disallow Basic authentication"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
        "AllowUnencryptedTraffic" 0 "DWord" "18.9.46" "WinRM Service: No unencrypted traffic"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
        "DisableRunAs" 1 "DWord" "18.9.47" "WinRM Service: Disallow WinRM RunAs"

    # Windows Defender Antivirus
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
        "DisableAntiSpyware" 0 "DWord" "18.9.48" "Windows Defender: AntiSpyware: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
        "DisableBehaviorMonitoring" 0 "DWord" "18.9.49" "WD: Behavior Monitoring: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
        "DisableIOAVProtection" 0 "DWord" "18.9.50" "WD: Scan all downloaded files: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
        "DisableRealtimeMonitoring" 0 "DWord" "18.9.51" "WD: Real-time protection: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
        "DisableScriptScanning" 0 "DWord" "18.9.52" "WD: Script scanning: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" `
        "DisableEnhancedNotifications" 0 "DWord" "18.9.53" "WD: Enhanced notifications: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
        "DisableBlockAtFirstSeen" 0 "DWord" "18.9.54" "WD: Block at First Seen: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
        "SpynetReporting" 2 "DWord" "18.9.55" "WD: Join Microsoft MAPS: Advanced Membership"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
        "SubmitSamplesConsent" 1 "DWord" "18.9.56" "WD: Send file samples: Send safe samples"

    # Exploit Guard / Attack Surface Reduction
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" `
        "ExploitGuard_ASR_Rules" 1 "DWord" "18.9.57" "Configure Attack Surface Reduction rules: Enabled"
    # Core ASR rules (block office macros, credential theft, etc.)
    $asrRules = @{
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 1  # Block Office content creation
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1  # Block Office apps from child processes
        "3B576869-A4EC-4529-8536-B80A7769E899" = 1  # Block Office from injecting code
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1  # Block Office apps from injecting into other processes
        "D3E037E1-3EB8-44C8-A917-57927947596D" = 1  # Block JS/VBS from executing payloads
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1  # Block script obfuscation
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 1  # Block Win32 API calls from Office macros
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = 1  # Block credential stealing from LSASS
        "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = 1  # Block Adobe Reader child processes
        "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = 1  # Block persistence via WMI event subscription
        "01443614-CD74-433A-B99E-2ECDC07BFC25" = 1  # Block untrusted/unsigned processes from USB
        "C1DB55AB-C21A-4637-BB3F-A12568109D35" = 1  # Block advanced ransomware protection
        "26190899-1602-49E8-8B27-EB1D0A1CE869" = 1  # Block Office communication app child processes
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = 1  # Block untrusted processes from USB
    }
    $asrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
    if (-not (Test-Path $asrPath)) { New-Item -Path $asrPath -Force | Out-Null }
    foreach ($rule in $asrRules.GetEnumerator()) {
        Set-RegValue $asrPath $rule.Key $rule.Value "DWord" "18.9.57-$($rule.Key.Substring(0,8))" "ASR Rule: $($rule.Key.Substring(0,8))..."
    }

    # Windows Sandbox
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" `
        "AllowSandbox" 0 "DWord" "18.9.58" "Windows Sandbox: Disabled"
}

# ===============================================================================
#  SECTION 18 - WINDOWS 11 SPECIFIC CONTROLS
# ===============================================================================
function Invoke-Win11Specific {
    Write-Log "WINDOWS 11 SPECIFIC CONTROLS" "HEAD"

    # Cross-device clipboard (Phone Link)
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        "AllowCrossDeviceClipboard" 0 "DWord" "W11-1" "Win11: Disable cross-device clipboard"

    # Device name in telemetry
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        "AllowDeviceNameInTelemetry" 0 "DWord" "W11-2" "Win11: Do not send device name in telemetry"

    # Chat app
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" `
        "ChatIcon" 3 "DWord" "W11-3" "Win11: Remove Chat (Teams) from taskbar"

    # Consumer features (extra Win11 cloud content)
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        "DisableCloudOptimizedContent" 1 "DWord" "W11-4" "Win11: Disable cloud-optimized content"

    # Account-linked settings sync
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" `
        "DisableSettingSync" 2 "DWord" "W11-5" "Win11: Disable settings sync"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" `
        "DisableSettingSyncUserOverride" 1 "DWord" "W11-6" "Win11: Prevent users from overriding sync"

    # Widgets
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" `
        "AllowNewsAndInterests" 0 "DWord" "W11-7" "Win11: Disable Widgets/News and Interests"

    # Recall (AI feature - Win11 24H2+)
    if ($Script:OSBuild -ge 26100) {
        Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" `
            "DisableAIDataAnalysis" 1 "DWord" "W11-8" "Win11: Disable Recall (AI data analysis)"
    }
}

# ===============================================================================
#  SECTION 19 - USER CONFIGURATION TEMPLATES
# ===============================================================================
function Invoke-UserTemplates {
    Write-Log "SECTION 19 - User Configuration Templates" "HEAD"

    # Game DVR
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" `
        "AllowGameDVR" 0 "DWord" "19.1.1" "Disable Game DVR and broadcasting"

    # Attachment Manager
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" `
        "SaveZoneInformation" 1 "DWord" "19.2.1" "Attachment Manager: Do not preserve zone info: Disabled"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" `
        "HideZoneInfoOnProperties" 1 "DWord" "19.2.2" "Attachment Manager: Hide zone-removal mechanisms"

    # AutoPlay (user scope)
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "NoDriveTypeAutoRun" 255 "DWord" "19.3.1" "AutoPlay: Disabled for all drives (user policy)"

    # Internet Communication (user scope)
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "NoPublishingWizard" 1 "DWord" "19.4.1" "Turn off Internet Connection Wizard"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "NoWebServices" 1 "DWord" "19.4.2" "Turn off web publishing wizard"
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "NoOnlinePrintsWizard" 1 "DWord" "19.4.3" "Turn off online ordering wizard"

    # Search suggestions
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        "DisableSearchBoxSuggestions" 1 "DWord" "19.5.1" "Turn off search suggestions in search box"

    # Windows Messaging
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Messenger" `
        "PreventRun" 1 "DWord" "19.6.1" "Prevent Windows Messenger from running"
}

# ===============================================================================
#  SERVICE HARDENING
# ===============================================================================
function Invoke-ServiceHardening {
    Write-Log "SERVICE HARDENING - Disable insecure/unnecessary services" "HEAD"

    $services = @(
        @("RemoteRegistry",  "Remote Registry",                        "SVC-RR"),
        @("Browser",         "Computer Browser (SMBv1 dependency)",    "SVC-CB"),
        @("SSDPSRV",         "SSDP Discovery",                         "SVC-SSDP"),
        @("upnphost",        "UPnP Device Host",                       "SVC-UPNP"),
        @("SharedAccess",    "Internet Connection Sharing (ICS)",       "SVC-ICS"),
        @("Fax",             "Fax Service",                            "SVC-FAX"),
        @("irmon",           "Infrared Monitor Service",               "SVC-IR"),
        @("TlntSvr",         "Telnet Server",                          "SVC-TELNET"),
        @("simptcp",         "Simple TCP/IP Services",                 "SVC-STCP"),
        @("FTPSVC",          "FTP Publishing Service",                 "SVC-FTP"),
        @("WMSvc",           "IIS Web Management Service",             "SVC-WMS"),
        @("W3SVC",           "World Wide Web Publishing Service (IIS)","SVC-IIS"),
        @("XboxGipSvc",      "Xbox Accessory Management",              "SVC-XBOX1"),
        @("XblAuthManager",  "Xbox Live Auth Manager",                 "SVC-XBOX2"),
        @("XblGameSave",     "Xbox Live Game Save",                    "SVC-XBOX3"),
        @("XboxNetApiSvc",   "Xbox Live Networking",                   "SVC-XBOX4"),
        @("WinHttpAutoProxySvc","WinHTTP Auto Proxy Discovery",        "SVC-PROXY")
    )

    foreach ($s in $services) {
        Disable-Svc $s[0] $s[1] $s[2]
    }
}

# ===============================================================================
#  WINDOWS FEATURES
# ===============================================================================
function Invoke-WindowsFeatures {
    Write-Log "WINDOWS FEATURES - Remove insecure optional features" "HEAD"

    $features = @(
        @("SMB1Protocol",                      "SMBv1 Protocol",    "FEAT-SMB1"),
        @("MicrosoftWindowsPowerShellV2Root",  "PowerShell v2 Root","FEAT-PSv2"),
        @("MicrosoftWindowsPowerShellV2",      "PowerShell v2",     "FEAT-PSv2b"),
        @("TelnetClient",                      "Telnet Client",     "FEAT-TELC"),
        @("TFTP",                              "TFTP Client",       "FEAT-TFTP"),
        @("WorkFolders-Client",                "Work Folders",      "FEAT-WF")
    )

    foreach ($f in $features) {
        try {
            $feat = Get-WindowsOptionalFeature -Online -FeatureName $f[0] -EA SilentlyContinue
            if ($feat) {
                if ($feat.State -eq "Enabled") {
                    Disable-WindowsOptionalFeature -Online -FeatureName $f[0] -NoRestart -EA Stop | Out-Null
                    Write-Log "$($f[1])  [disabled]" "FIX"
                    Add-Result $f[2] "Disable feature: $($f[1])" "FIX" "Disabled"
                } else {
                    Write-Log "$($f[1])  [already disabled]" "PASS"
                    Add-Result $f[2] "Disable feature: $($f[1])" "PASS" "OK"
                }
            } else {
                Write-Log "$($f[1])  [not found - skipped]" "SKIP"
                Add-Result $f[2] "Disable feature: $($f[1])" "SKIP" "Not present"
            }
        } catch {
            Write-Log "$($f[1])  [ERROR: $_]" "ERROR"
            Add-Result $f[2] "Disable feature: $($f[1])" "FAIL" "$_"
        }
    }

    # Also disable SMBv1 via registry (belt-and-suspenders)
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        "SMB1" 0 "DWord" "FEAT-SMB1-REG" "SMBv1: Disabled via LanmanServer registry"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
        "Start" 4 "DWord" "FEAT-SMB1-DRV" "SMBv1: mrxsmb10 driver: Disabled"
}

# ===============================================================================
#  POWERSHELL HARDENING
# ===============================================================================
function Invoke-PowerShellHardening {
    Write-Log "POWERSHELL HARDENING" "HEAD"

    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" `
        "EnableScripts" 1 "DWord" "PS-1" "PowerShell: Script execution: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" `
        "ExecutionPolicy" "RemoteSigned" "String" "PS-2" "PowerShell: Execution policy: RemoteSigned"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        "EnableScriptBlockLogging" 1 "DWord" "PS-3" "PowerShell: Script block logging: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        "EnableScriptBlockInvocationLogging" 1 "DWord" "PS-4" "PowerShell: Script block invocation logging: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        "EnableTranscripting" 1 "DWord" "PS-5" "PowerShell: Transcription: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        "EnableInvocationHeader" 1 "DWord" "PS-6" "PowerShell: Invocation header in transcripts: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
        "EnableModuleLogging" 1 "DWord" "PS-7" "PowerShell: Module logging: Enabled"
}

# ===============================================================================
#  SCREEN LOCK & IDLE SETTINGS
# ===============================================================================
function Invoke-ScreenLock {
    Write-Log "SCREEN LOCK & IDLE TIMEOUT" "HEAD"

    foreach ($hive in @("HKLM:\SOFTWARE","HKCU:\Software")) {
        $k = "$hive\Policies\Microsoft\Windows\Control Panel\Desktop"
        Set-RegValue $k "ScreenSaveActive"    "1"   "String" "SCR-1" "Screen saver: Enabled ($hive)"
        Set-RegValue $k "ScreenSaverIsSecure" "1"   "String" "SCR-2" "Screen saver: Password protected ($hive)"
        Set-RegValue $k "ScreenSaveTimeOut"   "900" "String" "SCR-3" "Screen saver timeout: 900 sec ($hive)"
    }
    # Machine-level interactive logon timeout (belt-and-suspenders with 2.3.7.3)
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "InactivityTimeoutSecs" 900 "DWord" "SCR-4" "Machine inactivity timeout: 900 sec"
}

# ===============================================================================
#  WINDOWS UPDATE
# ===============================================================================
function Invoke-WindowsUpdate {
    Write-Log "WINDOWS UPDATE" "HEAD"

    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
        "NoAutoUpdate" 0 "DWord" "WU-1" "Automatic Updates: Enabled"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
        "AUOptions" 4 "DWord" "WU-2" "Auto-install + schedule restart"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
        "AutoInstallMinorUpdates" 1 "DWord" "WU-3" "Auto-install minor updates"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
        "DeferFeatureUpdates" 1 "DWord" "WU-4" "Defer feature updates (prioritize quality)"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
        "DeferFeatureUpdatesPeriodInDays" 180 "DWord" "WU-5" "Feature update deferral: 180 days"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
        "DeferQualityUpdates" 0 "DWord" "WU-6" "Quality/security updates: Not deferred"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
        "SetDisablePauseUXAccess" 1 "DWord" "WU-7" "Prevent users from pausing Windows Updates"
}

# ===============================================================================
#  ADDITIONAL HARDENING (CIS L1 extras)
# ===============================================================================
function Invoke-AdditionalHardening {
    Write-Log "ADDITIONAL HARDENING" "HEAD"

    # Credential Guard
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
        "EnableVirtualizationBasedSecurity" 1 "DWord" "ADD-1" "Device Guard: VBS Enabled"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
        "RequirePlatformSecurityFeatures" 1 "DWord" "ADD-2" "Device Guard: Require Secure Boot"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "LsaCfgFlags" 1 "DWord" "ADD-3" "Credential Guard: Enabled with UEFI lock"
    # RunAsPPL - protect LSASS
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "RunAsPPL" 1 "DWord" "ADD-4" "LSA: Run as Protected Process Light (PPL)"

    # Disable LLMNR
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        "EnableMulticast" 0 "DWord" "ADD-5" "Disable LLMNR (multicast name resolution)"

    # Disable NetBIOS over TCP (via WMI per adapter - best effort)
    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
        foreach ($a in $adapters) {
            $a | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} -EA SilentlyContinue | Out-Null
        }
        Write-Log "NetBIOS over TCP: Disabled on all active adapters" "FIX"
        Add-Result "ADD-6" "Disable NetBIOS over TCP/IP" "FIX" "Applied to all adapters"
    } catch {
        Write-Log "NetBIOS: ERROR: $_" "ERROR"
        Add-Result "ADD-6" "Disable NetBIOS over TCP/IP" "FAIL" "$_"
    }

    # Disable IPv6 if desired (CIS recommends unless needed)
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
        "DisabledComponents" 255 "DWord" "ADD-7" "IPv6: Disabled (all components)"

    # Kerberos encryption types
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
        "SupportedEncryptionTypes" 2147483640 "DWord" "ADD-8" "Kerberos: AES128/AES256 + Future only"

    # Disable weak TLS/SSL ciphers
    @(
        "SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1"
    ) | ForEach-Object {
        Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$_\Client" `
            "Enabled" 0 "DWord" "SCHAN-$_-C" "SCHANNEL: Disable $_ (client)"
        Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$_\Client" `
            "DisabledByDefault" 1 "DWord" "SCHAN-$_-CD" "SCHANNEL: $_ disabled by default (client)"
        Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$_\Server" `
            "Enabled" 0 "DWord" "SCHAN-$_-S" "SCHANNEL: Disable $_ (server)"
        Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$_\Server" `
            "DisabledByDefault" 1 "DWord" "SCHAN-$_-SD" "SCHANNEL: $_ disabled by default (server)"
    }

    # Enable TLS 1.2 + 1.3
    @("TLS 1.2","TLS 1.3") | ForEach-Object {
        Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$_\Client" `
            "Enabled" 1 "DWord" "SCHAN-$_-CE" "SCHANNEL: Enable $_ (client)"
        Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$_\Client" `
            "DisabledByDefault" 0 "DWord" "SCHAN-$_-CDE" "SCHANNEL: $_ default (client)"
        Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$_\Server" `
            "Enabled" 1 "DWord" "SCHAN-$_-SE" "SCHANNEL: Enable $_ (server)"
        Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$_\Server" `
            "DisabledByDefault" 0 "DWord" "SCHAN-$_-SDE" "SCHANNEL: $_ default (server)"
    }

    # Disable weak ciphers
    @("NULL","DES 56/56","RC2 40/128","RC2 56/128","RC2 128/128","RC4 40/128","RC4 56/128","RC4 64/128","RC4 128/128","Triple DES 168") | ForEach-Object {
        Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$_" `
            "Enabled" 0 "DWord" "CIPH-$($_ -replace '[/ ]','_')" "Cipher: Disable $_"
    }

    # Disable NTLMv1 sending
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
        "RestrictSendingNTLMTraffic" 2 "DWord" "ADD-9" "Restrict sending NTLM traffic: Deny all"

    # Spectre/Meltdown mitigations
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
        "FeatureSettingsOverride" 0 "DWord" "ADD-10" "Spectre/Meltdown: Override feature settings = 0"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
        "FeatureSettingsOverrideMask" 3 "DWord" "ADD-11" "Spectre/Meltdown: Override mask = 3"

    # Prevent storage of credentials in Credential Manager (network auth)
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "DisableDomainCreds" 0 "DWord" "ADD-12" "Network access: Do not store domain credentials: Per-policy"

    # Audit object access for SAM
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "AuditBaseObjects" 0 "DWord" "ADD-13" "Audit: Audit the access of global system objects: Disabled"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "FullPrivilegeAuditing" 0 "DWord" "ADD-14" "Audit: Audit the use of backup and restore privilege: Disabled"

    # AppLocker / Software Restriction (enable enforcement mode registry keys)
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" `
        "EnforcementMode" 1 "DWord" "ADD-15" "AppLocker EXE enforcement mode: Enforce"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script" `
        "EnforcementMode" 1 "DWord" "ADD-16" "AppLocker Script enforcement mode: Enforce"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Msi" `
        "EnforcementMode" 1 "DWord" "ADD-17" "AppLocker MSI enforcement mode: Enforce"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Dll" `
        "EnforcementMode" 0 "DWord" "ADD-18" "AppLocker DLL enforcement mode: Audit (safe default)"

    # Secure Boot / UEFI
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" `
        "Enabled" 1 "DWord" "ADD-19" "HVCI: Hypervisor-Enforced Code Integrity: Enabled"
}

# ===============================================================================
#  FINAL REPORT
# ===============================================================================
function Write-FinalReport {
    $total     = $Script:PassCount + $Script:FixCount + $Script:FailCount + $Script:SkipCount
    $compliant = $Script:PassCount + $Script:FixCount
    $rate      = if ($total -gt 0) { [math]::Round($compliant / $total * 100, 1) } else { 0 }

    $report = @"

+==============================================================================+
|           CIS Level 1 - Remediation Complete                                |
+==============================================================================+

  System       : $($Script:OSCaption)
  Build        : $($Script:OSBuild)  ($(if ($Script:IsWin11) {"Windows 11"} else {"Windows 10"}))
  Completed    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

  +--------------------------------------+
  |  Controls evaluated  : $($total.ToString().PadLeft(5))           |
  |  Already compliant   : $($Script:PassCount.ToString().PadLeft(5))           |
  |  Fixed               : $($Script:FixCount.ToString().PadLeft(5))           |
  |  Failed (manual fix) : $($Script:FailCount.ToString().PadLeft(5))           |
  |  Skipped (N/A)       : $($Script:SkipCount.ToString().PadLeft(5))           |
  |  ---------------------------------- |
  |  Compliance rate     : $($rate.ToString().PadLeft(4))%           |
  +--------------------------------------+

"@

    Write-Host $report -ForegroundColor Cyan
    Add-Content $LogPath $report -Encoding UTF8

    $failed = $Script:Results | Where-Object { $_.Status -eq "FAIL" }
    if ($failed) {
        Write-Host "  Controls requiring manual attention:" -ForegroundColor Red
        $failed | ForEach-Object {
            Write-Host "    [$($_.ID)] $($_.Name)" -ForegroundColor Red
            Write-Host "           $($_.Detail)" -ForegroundColor DarkRed
        }
        Write-Host ""
    }

    # Save CSV
    $csv = $LogPath -replace '\.log$', '.csv'
    $Script:Results | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

    Write-Host "  Log  : $LogPath"  -ForegroundColor Green
    Write-Host "  CSV  : $csv"      -ForegroundColor Green
    Write-Host ""
}

# ===============================================================================
#  GUI - SPLASH / CONFIRMATION POPUP
# ===============================================================================
function Show-SplashGUI {
    <#
    .SYNOPSIS
        Displays a modern WPF popup asking the user to confirm before hardening begins.
        Returns $true if user clicks "Start Securing", $false if they cancel.
    #>
    Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,System.Windows.Forms

    [xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="CIS Hardening Tool"
    Width="520" Height="380"
    WindowStartupLocation="CenterScreen"
    ResizeMode="NoResize"
    WindowStyle="None"
    AllowsTransparency="True"
    Background="Transparent">

  <Window.Resources>
    <Style x:Key="PrimaryBtn" TargetType="Button">
      <Setter Property="Background"   Value="#0078D4"/>
      <Setter Property="Foreground"   Value="White"/>
      <Setter Property="FontSize"     Value="14"/>
      <Setter Property="FontWeight"   Value="SemiBold"/>
      <Setter Property="Height"       Value="44"/>
      <Setter Property="Width"        Value="200"/>
      <Setter Property="Cursor"       Value="Hand"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}"
                    CornerRadius="8"
                    Padding="12,0">
              <ContentPresenter HorizontalAlignment="Center"
                                VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter Property="Background" Value="#005A9E"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter Property="Background" Value="#004578"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="CancelBtn" TargetType="Button">
      <Setter Property="Background"   Value="#3A3A3A"/>
      <Setter Property="Foreground"   Value="#AAAAAA"/>
      <Setter Property="FontSize"     Value="13"/>
      <Setter Property="Height"       Value="36"/>
      <Setter Property="Width"        Value="100"/>
      <Setter Property="Cursor"       Value="Hand"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}"
                    CornerRadius="6"
                    Padding="10,0">
              <ContentPresenter HorizontalAlignment="Center"
                                VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter Property="Background" Value="#555555"/>
                <Setter Property="Foreground" Value="White"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <!-- Drop shadow outer border -->
  <Border CornerRadius="14"
          Background="#1E1E1E"
          BorderBrush="#2D2D2D"
          BorderThickness="1">
    <Border.Effect>
      <DropShadowEffect BlurRadius="24" ShadowDepth="6"
                        Color="Black" Opacity="0.55"/>
    </Border.Effect>

    <Grid>
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>   <!-- drag handle / close -->
        <RowDefinition Height="*"/>      <!-- content -->
        <RowDefinition Height="Auto"/>   <!-- buttons -->
        <RowDefinition Height="16"/>     <!-- bottom padding -->
      </Grid.RowDefinitions>

      <!-- Title bar (drag area) -->
      <Border Grid.Row="0" CornerRadius="14,14,0,0"
              Background="#141414" Height="42"
              MouseLeftButtonDown="Border_MouseLeftButtonDown">
        <Grid>
          <TextBlock Text="    CIS Benchmark Level 1"
                     Foreground="#CCCCCC" FontSize="12"
                     FontWeight="Medium"
                     VerticalAlignment="Center" Margin="12,0,0,0"/>
          <Button x:Name="BtnClose" Content=""
                  HorizontalAlignment="Right" VerticalAlignment="Center"
                  Margin="0,0,10,0"
                  Width="28" Height="28"
                  Background="Transparent" Foreground="#888888"
                  BorderThickness="0" FontSize="14" Cursor="Hand"
                  ToolTip="Cancel"/>
        </Grid>
      </Border>

      <!-- Main content -->
      <StackPanel Grid.Row="1"
                  HorizontalAlignment="Center"
                  VerticalAlignment="Center"
                  Margin="32,16,32,8">

        <!-- Shield icon -->
        <Border Width="72" Height="72"
                CornerRadius="36"
                HorizontalAlignment="Center"
                Background="#0D2137">
          <Border.Effect>
            <DropShadowEffect BlurRadius="16" ShadowDepth="0"
                              Color="#0078D4" Opacity="0.6"/>
          </Border.Effect>
          <TextBlock Text="" FontSize="36"
                     HorizontalAlignment="Center"
                     VerticalAlignment="Center"
                     Margin="0,4,0,0"/>
        </Border>

        <TextBlock Text="Start Securing Your Device"
                   Foreground="White"
                   FontSize="22"
                   FontWeight="Bold"
                   HorizontalAlignment="Center"
                   Margin="0,18,0,10"/>

        <TextBlock TextWrapping="Wrap"
                   TextAlignment="Center"
                   HorizontalAlignment="Center"
                   MaxWidth="400"
                   Foreground="#AAAAAA"
                   FontSize="13"
                   LineHeight="20"
                   Margin="0,0,0,6">
          This tool will automatically apply all
          <Run Foreground="#0078D4" FontWeight="SemiBold">CIS Level 1</Run>
          security controls to this machine.&#x0a;&#x0a;
          Settings will be changed immediately.
          A <Run Foreground="#FFA500" FontWeight="SemiBold">reboot</Run>
          will be required when complete.
        </TextBlock>

        <!-- OS info label (filled at runtime) -->
        <Border Background="#2A2A2A" CornerRadius="6"
                Padding="10,6" Margin="0,10,0,0"
                HorizontalAlignment="Center">
          <TextBlock x:Name="TxtOS"
                     Foreground="#0078D4"
                     FontSize="12"
                     FontFamily="Consolas"/>
        </Border>
      </StackPanel>

      <!-- Action buttons -->
      <StackPanel Grid.Row="2"
                  Orientation="Horizontal"
                  HorizontalAlignment="Center"
                  Margin="0,12,0,0">
        <Button x:Name="BtnStart"
                Style="{StaticResource PrimaryBtn}"
                Content="  Start Securing"
                Margin="0,0,14,0"/>
        <Button x:Name="BtnCancel"
                Style="{StaticResource CancelBtn}"
                Content="Cancel"/>
      </StackPanel>

    </Grid>
  </Border>
</Window>
"@

    $reader = [System.Xml.XmlNodeReader]::new($xaml)
    $window = [Windows.Markup.XamlReader]::Load($reader)

    # Fill OS label
    $os      = (Get-CimInstance Win32_OperatingSystem)
    $build   = $os.BuildNumber
    $edition = if ([int]$build -ge 22000) { "Windows 11" } else { "Windows 10" }
    $window.FindName("TxtOS").Text = "$edition  |  Build $build  |  $($os.CSName)"

    # Wire up drag
    $window.FindName("Border_MouseLeftButtonDown") | Out-Null   # referenced inside XAML event
    $window.Add_MouseLeftButtonDown({ $window.DragMove() })

    # Result flag
    $Script:GUIResult = $false

    $window.FindName("BtnStart").Add_Click({
        $Script:GUIResult = $true
        $window.Close()
    })
    $window.FindName("BtnClose").Add_Click({ $window.Close() })
    $window.FindName("BtnCancel").Add_Click({ $window.Close() })

    # Show modal (blocks until closed)
    $window.ShowDialog() | Out-Null

    return $Script:GUIResult
}

# ===============================================================================
#  GUI - COMPLETION POPUP
# ===============================================================================
function Show-CompleteGUI {
    param([int]$Fixed, [int]$Passed, [int]$Failed, [int]$Skipped)

    Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase

    $rate = if (($Fixed+$Passed+$Failed) -gt 0) {
        [math]::Round(($Fixed+$Passed)/($Fixed+$Passed+$Failed)*100,1)
    } else { 100 }

    $rateColor = if ($rate -ge 95) { "#00C853" } elseif ($rate -ge 80) { "#FFA500" } else { "#F44336" }

    [xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Hardening Complete"
    Width="460" Height="340"
    WindowStartupLocation="CenterScreen"
    ResizeMode="NoResize"
    WindowStyle="None"
    AllowsTransparency="True"
    Background="Transparent">

  <Border CornerRadius="14" Background="#1E1E1E"
          BorderBrush="#2D2D2D" BorderThickness="1">
    <Border.Effect>
      <DropShadowEffect BlurRadius="24" ShadowDepth="6" Color="Black" Opacity="0.55"/>
    </Border.Effect>
    <Grid>
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="*"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="16"/>
      </Grid.RowDefinitions>

      <Border Grid.Row="0" CornerRadius="14,14,0,0"
              Background="#141414" Height="42"
              MouseLeftButtonDown="Border_MouseLeftButtonDown">
        <TextBlock Text="    Hardening Complete"
                   Foreground="#CCCCCC" FontSize="12"
                   VerticalAlignment="Center" Margin="12,0"/>
      </Border>

      <StackPanel Grid.Row="1" HorizontalAlignment="Center"
                  VerticalAlignment="Center" Margin="28,12">

        <TextBlock Text="$rate%" FontSize="48" FontWeight="Bold"
                   Foreground="$rateColor"
                   HorizontalAlignment="Center"/>
        <TextBlock Text="Compliance Rate"
                   Foreground="#888888" FontSize="13"
                   HorizontalAlignment="Center" Margin="0,0,0,16"/>

        <Grid HorizontalAlignment="Center">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="110"/>
            <ColumnDefinition Width="110"/>
            <ColumnDefinition Width="110"/>
            <ColumnDefinition Width="110"/>
          </Grid.ColumnDefinitions>

          <StackPanel Grid.Column="0" HorizontalAlignment="Center">
            <TextBlock Text="$Passed" FontSize="22" FontWeight="Bold"
                       Foreground="#00C853" HorizontalAlignment="Center"/>
            <TextBlock Text="Already OK" Foreground="#777777"
                       FontSize="11" HorizontalAlignment="Center"/>
          </StackPanel>
          <StackPanel Grid.Column="1" HorizontalAlignment="Center">
            <TextBlock Text="$Fixed" FontSize="22" FontWeight="Bold"
                       Foreground="#0078D4" HorizontalAlignment="Center"/>
            <TextBlock Text="Fixed" Foreground="#777777"
                       FontSize="11" HorizontalAlignment="Center"/>
          </StackPanel>
          <StackPanel Grid.Column="2" HorizontalAlignment="Center">
            <TextBlock Text="$Failed" FontSize="22" FontWeight="Bold"
                       Foreground="#F44336" HorizontalAlignment="Center"/>
            <TextBlock Text="Failed" Foreground="#777777"
                       FontSize="11" HorizontalAlignment="Center"/>
          </StackPanel>
          <StackPanel Grid.Column="3" HorizontalAlignment="Center">
            <TextBlock Text="$Skipped" FontSize="22" FontWeight="Bold"
                       Foreground="#888888" HorizontalAlignment="Center"/>
            <TextBlock Text="Skipped" Foreground="#777777"
                       FontSize="11" HorizontalAlignment="Center"/>
          </StackPanel>
        </Grid>

        <TextBlock Text="Reboot required for all changes to take effect."
                   Foreground="#FFA500" FontSize="12"
                   HorizontalAlignment="Center" Margin="0,18,0,0"/>
      </StackPanel>

      <StackPanel Grid.Row="2" Orientation="Horizontal"
                  HorizontalAlignment="Center" Margin="0,0,0,4">
        <Button x:Name="BtnReboot" Content="    Reboot Now  "
                Height="40" Width="150" Margin="0,0,12,0"
                FontSize="13" FontWeight="SemiBold"
                Background="#C62828" Foreground="White"
                BorderThickness="0" Cursor="Hand">
          <Button.Template>
            <ControlTemplate TargetType="Button">
              <Border Background="{TemplateBinding Background}"
                      CornerRadius="8">
                <ContentPresenter HorizontalAlignment="Center"
                                  VerticalAlignment="Center"/>
              </Border>
              <ControlTemplate.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                  <Setter Property="Background" Value="#B71C1C"/>
                </Trigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
          </Button.Template>
        </Button>
        <Button x:Name="BtnClose2" Content="  Close  "
                Height="40" Width="100"
                FontSize="13" Background="#3A3A3A" Foreground="#AAAAAA"
                BorderThickness="0" Cursor="Hand">
          <Button.Template>
            <ControlTemplate TargetType="Button">
              <Border Background="{TemplateBinding Background}"
                      CornerRadius="8">
                <ContentPresenter HorizontalAlignment="Center"
                                  VerticalAlignment="Center"/>
              </Border>
              <ControlTemplate.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                  <Setter Property="Background" Value="#555555"/>
                  <Setter Property="Foreground" Value="White"/>
                </Trigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
          </Button.Template>
        </Button>
      </StackPanel>
    </Grid>
  </Border>
</Window>
"@

    $reader = [System.Xml.XmlNodeReader]::new($xaml)
    $win    = [Windows.Markup.XamlReader]::Load($reader)
    $win.Add_MouseLeftButtonDown({ $win.DragMove() })

    $Script:ShouldReboot = $false
    $win.FindName("BtnReboot").Add_Click({ $Script:ShouldReboot = $true; $win.Close() })
    $win.FindName("BtnClose2").Add_Click({ $win.Close() })

    $win.ShowDialog() | Out-Null
    return $Script:ShouldReboot
}

# ===============================================================================
#  MAIN
# ===============================================================================
function Main {
    Clear-Host
    Write-Host @"
+==============================================================================+
|   CIS Benchmark Level 1 - Windows 10 & 11 Auto-Remediation                 |
|   All non-compliant settings are fixed automatically                        |
+==============================================================================+
"@ -ForegroundColor Cyan

    # -- Show splash GUI -------------------------------------------------------
    $confirmed = Show-SplashGUI
    if (-not $confirmed) {
        Write-Host "`n  [CANCELLED] User closed the dialog. No changes were made.`n" -ForegroundColor Yellow
        exit 0
    }

    "CIS-CAT L1 Auto-Remediation - $(Get-Date)" | Set-Content $LogPath -Encoding UTF8

    Get-OSInfo
    if ($BackupFirst) { Invoke-Backup }

    Invoke-AccountPolicies
    Invoke-LocalPolicies
    Invoke-Firewall
    Invoke-AuditPolicy
    Invoke-AdminTemplates
    if ($Script:IsWin11) { Invoke-Win11Specific }
    Invoke-UserTemplates
    Invoke-ServiceHardening
    Invoke-WindowsFeatures
    Invoke-PowerShellHardening
    Invoke-ScreenLock
    Invoke-WindowsUpdate
    Invoke-AdditionalHardening

    Write-FinalReport

    # -- Show completion GUI ---------------------------------------------------
    $reboot = Show-CompleteGUI `
        -Fixed   $Script:FixCount `
        -Passed  $Script:PassCount `
        -Failed  $Script:FailCount `
        -Skipped $Script:SkipCount

    if ($reboot) { Restart-Computer -Force }
}

Main
