# x-ray-chrome

PowerShell scripts to secure Chrome browsers on dedicated medical X-ray workstations by restricting network access to localhost and preventing unauthorized updates.

## Purpose

Medical imaging systems often require web browsers for local applications while maintaining strict security. This tool:
- Locks Chrome to localhost-only access (blocks internet browsing)
- Prevents automatic updates that could break medical software compatibility
- Uses enterprise policies for reliable, tamper-resistant restrictions
- Provides complete reversal capability for maintenance

## Files

* **Lockdown script:** [`lockdown-xray-chrome.ps1`](https://github.com/stephenvsawyer/x-ray-chrome/blob/main/lockdown-xray-chrome.ps1) - Applies security restrictions
* **Undo script:** [`undo-lockdown-xray-chrome.ps1`](https://github.com/stephenvsawyer/x-ray-chrome/blob/main/undo-lockdown-xray-chrome.ps1) - Completely reverses lockdown
* **Chrome installer:** [Releases](https://github.com/stephenvsawyer/x-ray-chrome/releases) - Specific tested Chrome version

## Quick Start

**Requirements:** Windows 10/11, Administrator privileges, PowerShell 5.1+

```powershell
# Apply security lockdown
.\lockdown-xray-chrome.ps1

# Verify restrictions (in Chrome)
# chrome://policy - Check URL policies and update settings
# chrome://settings/help - Should show "Updates disabled by administrator"

# Remove all restrictions and restore normal Chrome
.\undo-lockdown-xray-chrome.ps1 -RemoveAdmx  # Optional: also remove policy templates
```

## What It Does

**Lockdown process:**
- Uninstalls existing Chrome installations
- Installs specific Chrome version (138.0.7204.184)
- Applies enterprise URL allowlist (localhost only)
- Disables Google Update services and scheduled tasks
- Installs ADMX policy templates for management

**Undo process:**
- Removes all applied policies and restrictions
- Installs latest Chrome via winget
- Re-enables update mechanisms
- Optionally removes policy templates

## Screenshots

**Lockdown process**
![Lockdown process](https://github.com/stephenvsawyer/xray-chrome/blob/main/xray-chrome.png?raw=1)

**Reversal process**
![Reversal process](https://github.com/stephenvsawyer/xray-chrome/blob/main/xray-reversal-chrome.png?raw=1)

> Tested on **Windows 10 Enterprise LTSC** and **Windows 11**. Requires elevated PowerShell prompt.
