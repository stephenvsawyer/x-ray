# X-Ray Chrome Lockdown

PowerShell scripts to lock down Google Chrome on dedicated X-ray machines (disable auto-updates and restrict browsing to `localhost`) plus a full undo.

## Files

* **Lockdown script:** [`lockdown-xray-chrome.ps1`](https://github.com/stephenvsawyer/x-ray/blob/main/lockdown-xray-chrome.ps1)
* **Undo script:** [`undo-lockdown-xray-chrome.ps1`](https://github.com/stephenvsawyer/x-ray/blob/main/undo-lockdown-xray-chrome.ps1)
* **Chrome bundle (release asset):** [Releases](https://github.com/stephenvsawyer/x-ray/releases)

## Quick start (Windows, run as Admin)

```powershell
# Lock down Chrome to localhost and disable updates
.\lockdown-xray-chrome.ps1

# Revert all changes
.\undo-lockdown-xray-chrome.ps1
```
