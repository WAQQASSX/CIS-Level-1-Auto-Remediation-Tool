# CIS Level 1 Auto-Remediation Tool (Windows 10 & 11)

![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-lightgrey.svg)
![Compliance](https://img.shields.io/badge/CIS%20Benchmark-v4.0.0%20Level%201-green.svg)

A professional, GUI-driven PowerShell automation tool designed to autonomously remediate Windows 10 and 11 systems to meet the **CIS (Center for Internet Security) Microsoft Windows 10/11 Enterprise Benchmark v4.0.0, Level 1**.

---

## 🚀 Features

- **Modern WPF GUI**: A clean, dark-themed interface with real-time logging.
- **Live Compliance Stats**: Visual counters for `PASS`, `FIXED`, `FAIL`, and `SKIPPED` items.
- **Safety First**:
  - **OS Edition Check**: Automatically blocks execution on Windows Home editions (Pro/Enterprise required).
  - **MSA Detection**: Scans for Microsoft Accounts and warns the user to ensure a local admin account is available.
  - **Full Consent**: Displays a comprehensive summary of changes before starting.
- **160+ Controls**: Addresses Account Policies, User Rights, Registry Hardening, Firewall, and Service disabling.

## 🛠️ Installation & Usage

### Option 1: Run as Script (PowerShell)
1. Open PowerShell as **Administrator**.
2. Navigate to the project folder.
3. Run the following command:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\CIS-L1-GUI.ps1
   ```

### Option 2: Run as Standalone EXE
If you have compiled the script using `PS2EXE`, simply double-click `CIS-Remediator.exe`.

---

## 🔨 How to Build (Create EXE)

To bundle this script into a professional executable, use the `ps2exe` module:

1. **Install the compiler**:
   ```powershell
   Install-Module ps2exe -Scope CurrentUser -Force
   ```
2. **Compile the script**:
   ```powershell
   ps2exe .\CIS-L1-GUI.ps1 .\CIS-Remediator.exe -title "CIS L1 Remediator" -noConsole -runtime40
   ```

---

## 🛡️ Security Hardening Overview

| Section | Impact |
| :--- | :--- |
| **Account Policies** | Enforces 14-char passwords, lockout thresholds, and complexity. |
| **User Rights** | Renames 'Administrator' and 'Guest', restricts local logons. |
| **Firewall** | Enables Defender Firewall on all profiles with strict inbound rules. |
| **Network** | Disables SMBv1, LLMNR, NetBIOS, and insecure TLS versions. |
| **Services** | Disables Remote Registry, Xbox services, and insecure web servers. |

---

## ⚠️ Disclaimer
*This tool makes significant changes to Windows security settings. It is intended for use in enterprise or lab environments. **Always ensure you have a local administrator account and a full system backup before proceeding.***
