# CIS L1 Auto-Remediation Context

## Project Overview
This project focuses on the autonomous remediation of Windows 10/11 systems to meet the **CIS (Center for Internet Security) Microsoft Windows 10 Enterprise Benchmark v4.0.0, Level 1 (L1)**.

### Key Files
- **`CIS-L1.ps1`**: The primary PowerShell automation script. It applies security hardening across multiple sections (Account Policies, User Rights, Security Options, Firewall, Audit Policies, etc.). It addresses approximately 160 controls.
- **`DESKTOP-41TD331-CIS_Microsoft_Windows_10_Enterprise_Benchmark-20260312T212312Z.pdf`**: The baseline assessment report for the target machine, showing a compliance score of 57% (210/370) prior to remediation.
- **`CIS-L1-20260312_214844.pdf`**: Execution logs of the script, showing PASS/FIX/FAIL status for each control.
- **`CIS-L1-Project-Docs.pdf`**: Project documentation outlining the scope, background, and roadmap.

## Engineering Standards & Patterns
- **Scripting**: PowerShell 3.0+ required. Must run as Administrator.
- **Remediation Logic**: The script uses a `PASS / FIX / FAIL / SKIP` logging pattern.
- **Target OS**: Windows 10/11 Enterprise or Pro.

## Roadmap & Goals
- **Phase 1**: Fix remaining FAIL items (e.g., `Get-LocalUser` errors, Administrator/Guest renames).
- **Phase 2**: Operational hardening (PS2EXE packaging, GPO integration, rollback flags).
- **Phase 3**: CIS Level 2 controls (AppLocker, Credential Guard, etc.).
- **Phase 4**: Reporting and compliance dashboards.
- **GUI Addition**: Plans to add a graphical interface using WPF/XAML (preferred for corporate IT) or Electron/React.

## Known Issues
- `Get-LocalUser` cmdlet failures in some environments (as seen in logs).
- Manual renames of Administrator/Guest accounts may fail if already renamed via GPO.
