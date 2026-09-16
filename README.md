# Joi Windows Security Audit Collector

This is a **one-time, read-only security audit collector** intended for analysis by a remote agent such as Hermes/Joi. It does not give the agent a shell on the Windows machine.

## What it collects

- Windows/system/security platform status
- Microsoft Defender status, preferences, exclusions, detections and scan timestamps
- Windows Security Center AV/firewall registrations and relevant service state
- Installed classic software and AppX/MSIX packages
- Windows update/hotfix history
- Services, drivers, processes and command lines
- Scheduled tasks including actions/triggers/principals/settings
- Startup folders, Run/RunOnce and many additional persistence registry locations
- WMI permanent event subscriptions and BITS jobs
- Optional Sysinternals Autoruns inventory
- Firewall profiles/rules/filters, listeners, TCP/UDP endpoints, routes, DNS and proxy configuration
- SMB shares/configuration and RDP/WinRM/OpenSSH configuration
- Local users, groups and group memberships
- UAC, LSA, PowerShell, SMB, WDigest, Schannel and related hardening configuration
- Audit policy, local security policy, effective Group Policy summary, AppLocker if present
- Certificate-store metadata (no private-key export)
- Selected security-relevant event logs from the configured time window

## Privacy boundary

The collector intentionally does **not** recursively inspect `Documents`, `Downloads`, `Desktop`, `Pictures`, `Videos`, `Music`, `OneDrive`, arbitrary user data folders, or files on non-system drives.

A configured service/task/startup entry can still contain a *path string* pointing to one of those locations. The path is part of Windows configuration and is recorded, but the referenced file is not opened, hashed, signature-checked or copied.

It also does **not** dump browser history/cookies/passwords, Windows Credential Manager, Wi-Fi passwords, SAM/SECURITY registry hives, DPAPI secrets, LSASS memory or certificate private keys.

Specific system-owned configuration files such as the Windows `hosts` file and `C:\ProgramData\ssh\sshd_config` may be copied because their contents are directly security-relevant.

## Run it

Open **Windows PowerShell as Administrator** in the folder containing the script:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Joi-Windows-Security-Audit.ps1
```

Default output:

```text
C:\JoiAudit\JoiAudit-COMPUTERNAME-YYYYMMDD-HHMMSS\
C:\JoiAudit\JoiAudit-COMPUTERNAME-YYYYMMDD-HHMMSS.zip
```

To collect 60 days of selected events:

```powershell
.\Joi-Windows-Security-Audit.ps1 -EventDays 60
```

## Give the gathered data to your agent

Send only the generated ZIP to Joi/Hermes. No remote Windows access is required. 
Give her the prompt provided in ```analyse_prompt_for_agent.txt```.
After analysis, delete the ZIP/audit folder if you no longer want the snapshot retained.

## Recommended: include Sysinternals Autoruns

Autoruns has broader knowledge of Windows auto-start/persistence locations than the normal Task Manager startup page.

Either place `autorunsc64.exe` next to the collector or run:

```powershell
.\Joi-Windows-Security-Audit.ps1 -DownloadAutoruns
```

The download option retrieves the official Microsoft Sysinternals Autoruns ZIP into a temporary directory inside the audit folder, runs `autorunsc`, and removes the temporary binaries afterward.

The collector deliberately does **not** use Autoruns VirusTotal options and does not ask Autoruns to broadly hash/signature-check every target. Its own targeted hash/signature checks obey the privacy boundary above.

## Why the Defender/Security Center section is detailed

Windows Security's UI gets protection status through `SecurityHealthService` and the Windows Security Center service (`wscsvc`), while Microsoft Defender Antivirus has its own operational state. A problem or stale registration at the Security Center layer can therefore produce a warning that does not exactly match Defender's actual engine/scan state.

The collector records both sides so the agent can compare:

- Defender engine/service status
- real-time protection and other Defender component flags
- signature age/update time
- quick/full scan timestamps and ages
- Defender preferences and exclusions
- Defender detections and events
- `SecurityHealthService` / `wscsvc` service state
- Security Center registered AV/firewall products and raw `productState`
- Security Center / Security Health event channels if present

## Troubleshooting

Bei Fehlermeldung, dass das Script nicht digital signiert wurde:
```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

Falls immer noch dieselbe Fehlermeldung:
```
Get-ExecutionPolicy -List
Unblock-File .\Joi-Windows-Security-Audit.v1.4.ps1
```

Falls bei der Policy-Liste Einträge wie sowas aussehen,.
```
MachinePolicy    AllSigned
UserPolicy       Undefined
Process          Bypass
...
```

dann sind vermutlich Gruppenrichtlinien aktiv. 
MachinePolicy/UserPolicy haben Vorrang vor dem Process Bypass.
