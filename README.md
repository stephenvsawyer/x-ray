# x-ray-chrome

PowerShell scripts to lock down Google Chrome on dedicated X-ray machines (disable auto-updates and restrict browsing to `localhost`) plus a full undo.

## Files

* **Lockdown script:** [`lockdown-xray-chrome.ps1`](https://github.com/stephenvsawyer/x-ray-chrome/blob/main/lockdown-xray-chrome.ps1)
* **Undo script:** [`undo-lockdown-xray-chrome.ps1`](https://github.com/stephenvsawyer/x-ray-chrome/blob/main/undo-lockdown-xray-chrome.ps1)
* **Chrome bundle (release asset):** [Releases](https://github.com/stephenvsawyer/x-ray-chrome/releases)

## Screenshots

**Lockdown process**
![Lockdown process](https://github.com/stephenvsawyer/xray-chrome/blob/main/xray-chrome.png?raw=1)

**Reversal process**
![Reversal process](https://github.com/stephenvsawyer/xray-chrome/blob/main/xray-reversal-chrome.png?raw=1)

## Quick start (Windows, run as Admin)

```powershell
# Lock down Chrome to localhost and disable updates
.\lockdown-xray-chrome.ps1

# Revert all changes
.\undo-lockdown-xray-chrome.ps1
```

> Tested on **Windows 10 Enterprise LTSC**. Run from an elevated PowerShell prompt.
