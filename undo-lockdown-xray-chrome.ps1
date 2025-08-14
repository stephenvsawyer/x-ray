# undo-lockdown-xray-chrome.ps1
# Purpose: Safely revert changes applied by lockdown-xray-chrome.ps1
# - Re-enable Chrome updates
# - Re-enable Google Update services & tasks
# - Remove URL allow/block list policies (localhost-only)
# - (Optional) Remove Chrome/Google ADMX/ADML files
# Run as Administrator.

[CmdletBinding()]
param(
    [switch]$RemoveAdmx  # If specified, remove chrome/google ADMX & ADML from PolicyDefinitions
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Admin check ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "This script must be run as Administrator."
}

# --- Paths & constants ---
$PolicyRoot         = 'HKLM:\SOFTWARE\Policies\Google'
$ChromeRoot         = Join-Path $PolicyRoot 'Chrome'
$UpdateRoot         = Join-Path $PolicyRoot 'Update'
$ChromeAppId        = '{8A69D345-D564-463C-AFF1-A69D9E530F96}'   # Chrome Stable
$ChromeAppKey       = Join-Path $UpdateRoot ("Applications\" + $ChromeAppId)
$PolicyDefinitions  = Join-Path $env:WINDIR 'PolicyDefinitions'

function Remove-SubKeyIfEmpty {
    param([Parameter(Mandatory)][string]$KeyPath)
    if (Test-Path $KeyPath) {
        $subkeys   = (Get-ChildItem -Path $KeyPath -ErrorAction SilentlyContinue)
        $props     = (Get-ItemProperty -Path $KeyPath -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)
        if (($subkeys | Measure-Object).Count -eq 0 -and ($props | Measure-Object).Count -eq 0) {
            Remove-Item -Path $KeyPath -Force
        }
    }
}

function Safe-RemoveValue {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    if (Test-Path $Path) {
        $item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        if ($null -ne $item.$Name) {
            Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
        }
    }
}

function Remove-ListPolicyKey {
    param([Parameter(Mandatory)][string]$BaseKey, [Parameter(Mandatory)][string]$ListKeyName)
    $fullKey = Join-Path $BaseKey $ListKeyName
    if (Test-Path $fullKey) {
        Remove-Item $fullKey -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Reverting Chrome update policies..."
# Remove machine-wide Update policy values (falls back to default: updates enabled)
if (Test-Path $UpdateRoot) {
    Safe-RemoveValue -Path $UpdateRoot -Name 'UpdateDefault'
    Safe-RemoveValue -Path $UpdateRoot -Name 'AutoUpdateCheckPeriodMinutes'
}
# Remove per-app override for Chrome
if (Test-Path $ChromeAppKey) {
    Safe-RemoveValue -Path $ChromeAppKey -Name 'UpdateDefault'
    # If Applications\{GUID} is now empty, remove it
    Remove-SubKeyIfEmpty -KeyPath $ChromeAppKey
}
# If Update key is empty, remove it
Remove-SubKeyIfEmpty -KeyPath $UpdateRoot

Write-Host "Removing URL allow/block list policies (including legacy names)..."
if (Test-Path $ChromeRoot) {
    # New names
    Remove-ListPolicyKey -BaseKey $ChromeRoot -ListKeyName 'URLBlocklist'
    Remove-ListPolicyKey -BaseKey $ChromeRoot -ListKeyName 'URLAllowlist'
    # Legacy names (for compatibility)
    Remove-ListPolicyKey -BaseKey $ChromeRoot -ListKeyName 'URLBlacklist'
    Remove-ListPolicyKey -BaseKey $ChromeRoot -ListKeyName 'URLWhitelist'

    # Also clean optional homepage settings if they were enabled by the lockdown script
    foreach ($name in 'HomepageLocation','RestoreOnStartup','HomepageIsNewTabPage') {
        Safe-RemoveValue -Path $ChromeRoot -Name $name
    }

    # Remove Chrome root key if it is empty after cleanup
    Remove-SubKeyIfEmpty -KeyPath $ChromeRoot
}

Write-Host "Restoring Google Update services to defaults..."
# Defaults: gupdate = Automatic (Delayed Start), gupdatem = Manual
$services = @(
    @{ Name='gupdate';   StartupType='Automatic'; Delayed=1; StartNow=$true  },
    @{ Name='gupdatem';  StartupType='Manual';    Delayed=0; StartNow=$false }
)
foreach ($svc in $services) {
    $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($s) {
        try {
            Set-Service -Name $svc.Name -StartupType $svc.StartupType
            # Configure delayed auto-start via registry when Automatic is selected
            $svcReg = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
            if (Test-Path $svcReg) {
                New-ItemProperty -Path $svcReg -Name 'DelayedAutostart' -PropertyType DWord -Value $svc.Delayed -Force | Out-Null
            }
            if ($svc.StartNow) {
                if ($s.Status -ne 'Running') { Start-Service -Name $svc.Name -ErrorAction SilentlyContinue }
            }
        } catch {
            Write-Warning "Could not adjust service $($svc.Name): $($_.Exception.Message)"
        }
    } else {
        Write-Host "Service $($svc.Name) not present; skipping."
    }
}

Write-Host "Re-enabling Google Update scheduled tasks..."
# Core task names plus wildcard catch-all
$taskNames = @('GoogleUpdateTaskMachineCore','GoogleUpdateTaskMachineUA')
foreach ($tn in $taskNames) {
    try { Enable-ScheduledTask -TaskName $tn -ErrorAction Stop | Out-Null } catch { }
}
# Enable any other GoogleUpdate* tasks if present
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -like 'GoogleUpdate*'
} | ForEach-Object {
    try { Enable-ScheduledTask -InputObject $_ -ErrorAction SilentlyContinue | Out-Null } catch { }
}

Write-Host "Forcing Group Policy refresh so Chrome picks up policy removals..."
Start-Process -FilePath "$env:SystemRoot\System32\gpupdate.exe" -ArgumentList '/force' -Wait

if ($RemoveAdmx) {
    Write-Host "Removing Chrome/Google ADMX & ADML templates from PolicyDefinitions..."
    $removed = $false
    # Remove ADMX files
    foreach ($admx in 'chrome.admx','google.admx') {
        $path = Join-Path $PolicyDefinitions $admx
        if (Test-Path $path) {
            Remove-Item $path -Force -ErrorAction SilentlyContinue
            $removed = $true
        }
    }
    # Remove ADML from locale subfolders (one level deep)
    Get-ChildItem -Path $PolicyDefinitions -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($adml in 'chrome.adml','google.adml') {
            $admlPath = Join-Path $_.FullName $adml
            if (Test-Path $admlPath) {
                Remove-Item $admlPath -Force -ErrorAction SilentlyContinue
                $removed = $true
            }
        }
    }
    if (-not $removed) {
        Write-Host "No Chrome/Google ADMX/ADML files found to remove."
    }
}

Write-Host "`nUndo complete."
Write-Host "Verify in Chrome:"
Write-Host " - chrome://policy  (URLBlocklist/Allowlist & Update policies should be absent)"
Write-Host " - chrome://settings/help  (updates should proceed normally)"
