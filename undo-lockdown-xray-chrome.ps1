# undo-lockdown-xray-chrome.ps1
# Purpose: Revert lockdown, reinstall latest Chrome via winget
# Steps:
#  1) Uninstall any installed Chrome (system + per-user)
#  2) Install latest Chrome via winget
#  3) Remove lockdown policies
#  4) Re-enable Google Update services & tasks
#  5) (Optional) remove ADMX/ADML templates
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
$TempDir            = $env:TEMP
$BackupFile         = Join-Path $TempDir 'xray-chrome-registry-backup.json'

# --- Helpers ------------------------------------------------------------------
function Test-NetworkConnectivity {
    param([string[]]$TestUrls = @('github.com', 'google.com'))
    
    Write-Host "Checking network connectivity..."
    foreach ($url in $TestUrls) {
        try {
            $result = Test-NetConnection -ComputerName $url -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
            if ($result) {
                Write-Host "✓ Network connectivity verified ($url)"
                return $true
            }
        } catch { }
    }
    
    # Fallback test using System.Net.NetworkInformation
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $result = $ping.Send('8.8.8.8', 3000)
        if ($result.Status -eq 'Success') {
            Write-Host "✓ Network connectivity verified (DNS)"
            return $true
        }
    } catch { }
    
    Write-Warning "Network connectivity test failed. Downloads may not work."
    return $false
}

function Restore-RegistryKeys {
    param([string]$BackupPath)
    
    if (-not (Test-Path $BackupPath)) {
        Write-Warning "Registry backup not found: $BackupPath"
        return
    }
    
    try {
        Write-Host "Restoring registry from backup..."
        $backupData = Get-Content $BackupPath -Raw | ConvertFrom-Json
        
        foreach ($keyPath in $backupData.PSObject.Properties.Name) {
            $regContent = $backupData.$keyPath
            if ($regContent) {
                $tempFile = Join-Path $env:TEMP "reg_restore_$(Get-Random).reg"
                Set-Content $tempFile $regContent -Encoding UTF8
                Start-Process -FilePath 'reg.exe' -ArgumentList @('import', $tempFile) -Wait -NoNewWindow
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Host "Registry restored successfully."
        # Clean up backup file after successful restore
        Remove-Item $BackupPath -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Error "Failed to restore registry: $($_.Exception.Message)"
    }
}
function Remove-SubKeyIfEmpty {
    param([Parameter(Mandatory)][string]$KeyPath)
    if (-not (Test-Path $KeyPath)) { return }
    $key = Get-Item -Path $KeyPath -ErrorAction SilentlyContinue
    $subkeysCount = @(Get-ChildItem -Path $KeyPath -ErrorAction SilentlyContinue).Count
    $valuesCount = 0
    if ($key) {
        try { $valuesCount = @($key.GetValueNames()).Count } catch { $valuesCount = 0 }
    }
    if ($subkeysCount -eq 0 -and $valuesCount -eq 0) {
        Remove-Item -Path $KeyPath -Force -ErrorAction SilentlyContinue
    }
}

function Safe-RemoveValue {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    if (-not (Test-Path $Path)) { return }
    try {
        $key = Get-Item -Path $Path -ErrorAction Stop
        if (($key.GetValueNames()) -contains $Name) {
            Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

function Remove-ListPolicyKey {
    param([Parameter(Mandatory)][string]$BaseKey, [Parameter(Mandatory)][string]$ListKeyName)
    $fullKey = Join-Path $BaseKey $ListKeyName
    if (Test-Path $fullKey) {
        Remove-Item $fullKey -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Stop-IfRunning {
    param([string[]]$Names)
    foreach ($n in $Names) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object {
            try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
}

function Uninstall-ChromeFromSetup {
    param([Parameter(Mandatory)][string]$SetupPath, [switch]$SystemLevel)
    if (-not (Test-Path $SetupPath)) { return }
    $args = @('--uninstall','--force-uninstall','--verbose-logging')
    if ($SystemLevel) { $args += '--system-level' }
    Write-Host "Uninstalling via: $SetupPath $($args -join ' ')"
    Start-Process -FilePath $SetupPath -ArgumentList $args -Wait -NoNewWindow
}

function Uninstall-AllChrome {
    Write-Host "Stopping Chrome/Google processes..."
    Stop-IfRunning -Names @('chrome','GoogleCrashHandler','GoogleCrashHandler64','GoogleUpdate','GoogleUpdater')

    Write-Host "Attempting system-level uninstalls..."
    $systemPaths = @(
        'C:\Program Files\Google\Chrome\Application',
        'C:\Program Files (x86)\Google\Chrome\Application'
    )
    foreach ($root in $systemPaths) {
        if (Test-Path $root) {
            Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $setup = Join-Path $_.FullName 'Installer\setup.exe'
                Uninstall-ChromeFromSetup -SetupPath $setup -SystemLevel
            }
        }
    }

    Write-Host "Attempting per-user uninstalls (if any)..."
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') } |
      ForEach-Object {
          $userApp = Join-Path $_.FullName 'AppData\Local\Google\Chrome\Application'
          if (Test-Path $userApp) {
              Get-ChildItem -Path $userApp -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                  $setup = Join-Path $_.FullName 'Installer\setup.exe'
                  Uninstall-ChromeFromSetup -SetupPath $setup
              }
          }
      }
}

# Test network connectivity
if (-not (Test-NetworkConnectivity)) {
    $response = Read-Host "Network connectivity issues detected. Continue anyway? (y/N)"
    if ($response -notmatch '^[Yy]') {
        Write-Error "Aborted due to network connectivity issues."
    }
}

# --- 1) Uninstall any installed Chrome ---------------------------------------
Write-Host "=== STEP 1: Uninstalling existing Chrome installations ==="
Uninstall-AllChrome

# --- 2) Install the latest Chrome via winget ----------------------------------
Write-Host "=== STEP 2: Installing latest Chrome via winget ==="
$winget = Get-Command winget -ErrorAction SilentlyContinue
if (-not $winget) {
    throw "winget not found. Install 'App Installer' from Microsoft Store or https://learn.microsoft.com/windows/package-manager/winget/."
}

# Install (idempotent; will install or repair to latest)
Write-Progress -Activity "Installing Chrome via winget" -Status "Downloading and installing..." -PercentComplete 25
$installArgs = @('install','-e','--id','Google.Chrome','--accept-package-agreements','--accept-source-agreements','--silent')
$proc = Start-Process -FilePath $winget.Source -ArgumentList $installArgs -PassThru -Wait -NoNewWindow
if ($proc.ExitCode -ne 0) {
    Write-Progress -Activity "Installing Chrome via winget" -Completed
    throw "winget install failed with exit code $($proc.ExitCode)."
}
Write-Progress -Activity "Installing Chrome via winget" -Status "Installation complete" -PercentComplete 100
Start-Sleep -Seconds 1
Write-Progress -Activity "Installing Chrome via winget" -Completed

# Optional: ensure fully up to date
try {
    Write-Progress -Activity "Updating Chrome" -Status "Checking for updates..." -PercentComplete 50
    $upgradeArgs = @('upgrade','-e','--id','Google.Chrome','--silent')
    Start-Process -FilePath $winget.Source -ArgumentList $upgradeArgs -PassThru -Wait -NoNewWindow | Out-Null
    Write-Progress -Activity "Updating Chrome" -Completed
} catch { 
    Write-Progress -Activity "Updating Chrome" -Completed
}

# --- 3) Remove lockdown policies ---------------------------------------------
Write-Host "=== STEP 3: Removing lockdown policies ==="
Write-Host "Reverting Chrome update policies..."
if (Test-Path $UpdateRoot) {
    Safe-RemoveValue -Path $UpdateRoot -Name 'UpdateDefault'
    Safe-RemoveValue -Path $UpdateRoot -Name 'AutoUpdateCheckPeriodMinutes'
}
if (Test-Path $ChromeAppKey) {
    Safe-RemoveValue -Path $ChromeAppKey -Name 'UpdateDefault'
    Remove-SubKeyIfEmpty -KeyPath $ChromeAppKey
}
Remove-SubKeyIfEmpty -KeyPath $UpdateRoot

Write-Host "Removing URL allow/block list policies (including legacy names)..."
if (Test-Path $ChromeRoot) {
    # New names
    Remove-ListPolicyKey -BaseKey $ChromeRoot -ListKeyName 'URLBlocklist'
    Remove-ListPolicyKey -BaseKey $ChromeRoot -ListKeyName 'URLAllowlist'
    # Legacy names
    Remove-ListPolicyKey -BaseKey $ChromeRoot -ListKeyName 'URLBlacklist'
    Remove-ListPolicyKey -BaseKey $ChromeRoot -ListKeyName 'URLWhitelist'

    foreach ($name in 'HomepageLocation','RestoreOnStartup','HomepageIsNewTabPage') {
        Safe-RemoveValue -Path $ChromeRoot -Name $name
    }
    Remove-SubKeyIfEmpty -KeyPath $ChromeRoot
}
Remove-SubKeyIfEmpty -KeyPath $PolicyRoot

# --- 4) Re-enable Google Update services & tasks ------------------------------
Write-Host "=== STEP 4: Re-enabling Google Update services & tasks ==="
# Defaults (best effort):
# - Omaha: gupdate = Automatic (Delayed), gupdatem = Manual
# - New updater: GoogleUpdaterService = Automatic (Delayed), GoogleUpdaterInternalService = Manual
$services = @(
    @{ Name='gupdate';                   StartupType='Automatic'; Delayed=1; StartNow=$true  },
    @{ Name='gupdatem';                  StartupType='Manual';    Delayed=0; StartNow=$false },
    @{ Name='GoogleUpdaterService';      StartupType='Automatic'; Delayed=1; StartNow=$true  },
    @{ Name='GoogleUpdaterInternalService'; StartupType='Manual'; Delayed=0; StartNow=$false }
)
foreach ($svc in $services) {
    $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($s) {
        try {
            Set-Service -Name $svc.Name -StartupType $svc.StartupType
            $svcReg = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
            if (Test-Path $svcReg) {
                New-ItemProperty -Path $svcReg -Name 'DelayedAutostart' -PropertyType DWord -Value $svc.Delayed -Force | Out-Null
            }
            if ($svc.StartNow -and $s.Status -ne 'Running') {
                Start-Service -Name $svc.Name -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Warning "Could not adjust service $($svc.Name): $($_.Exception.Message)"
        }
    }
}

Write-Host "Re-enabling Google Update/Updater scheduled tasks..."
$enableByName = @('GoogleUpdateTaskMachineCore','GoogleUpdateTaskMachineUA')
foreach ($tn in $enableByName) {
    try { Enable-ScheduledTask -TaskName $tn -ErrorAction Stop | Out-Null } catch { }
}
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -like 'GoogleUpdate*' -or $_.TaskName -like 'GoogleUpdater*'
} | ForEach-Object {
    try { Enable-ScheduledTask -InputObject $_ -ErrorAction SilentlyContinue | Out-Null } catch { }
}

# --- 5) Force policy refresh --------------------------------------------------
Write-Host "=== STEP 5: Forcing Group Policy refresh ==="
Start-Process -FilePath "$env:SystemRoot\System32\gpupdate.exe" -ArgumentList '/force' -Wait

# --- Optional: remove ADMX/ADML ----------------------------------------------
if ($RemoveAdmx) {
    Write-Host "Removing Chrome/Google ADMX & ADML templates from PolicyDefinitions..."
    $removed = $false
    foreach ($admx in 'chrome.admx','google.admx') {
        $path = Join-Path $PolicyDefinitions $admx
        if (Test-Path $path) { Remove-Item $path -Force -ErrorAction SilentlyContinue; $removed = $true }
    }
    Get-ChildItem -Path $PolicyDefinitions -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($adml in 'chrome.adml','google.adml') {
            $admlPath = Join-Path $_.FullName $adml
            if (Test-Path $admlPath) { Remove-Item $admlPath -Force -ErrorAction SilentlyContinue; $removed = $true }
        }
    }
    if (-not $removed) { Write-Host "No Chrome/Google ADMX/ADML files found to remove." }
}

# Offer to restore original registry state if backup exists
if (Test-Path $BackupFile) {
    $response = Read-Host "Registry backup found. Restore original settings? (Y/n)"
    if ($response -notmatch '^[Nn]') {
        Restore-RegistryKeys -BackupPath $BackupFile
    }
}

Write-Host "`nUndo complete."
Write-Host "Verify in Chrome:"
Write-Host " - chrome://policy  (no URL allow/block list, no UpdateDefault)"
Write-Host " - chrome://settings/help  (updates should proceed normally)"
