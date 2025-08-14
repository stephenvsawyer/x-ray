# lockdown-xray-chrome.ps1
# Purpose: Downgrade Chrome to a specific version, then lock Chrome to localhost and disable updates on dedicated X-ray PCs
# Run: As Administrator

# --- safety & config ----------------------------------------------------------
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Versions/URLs you control
$ChromeInstallerUrl = 'https://github.com/stephenvsawyer/xray-chrome/releases/download/2.0/Google_Chrome_.64bit._v138.0.7204.184.exe'
$BundleUrl          = 'https://github.com/stephenvsawyer/xray-chrome/releases/download/1.0/GoogleChromeEnterpriseBundle64.zip'

# Paths
$TempDir     = $env:TEMP
$ChromeExe   = Join-Path $TempDir 'Chrome_138_x64.exe'
$TempZip     = Join-Path $TempDir 'GoogleChromeEnterpriseBundle64.zip'
$ExtractDir  = Join-Path $TempDir 'GoogleChromeEnterpriseBundle64'
$PolicyRoot  = 'HKLM:\SOFTWARE\Policies\Google'
$ChromeRoot  = Join-Path $PolicyRoot 'Chrome'
$UpdateRoot  = Join-Path $PolicyRoot 'Update'
$PolicyDefinitions = Join-Path $env:WINDIR 'PolicyDefinitions'
$AllowList   = @('127.0.0.1','localhost')  # Only allow these

# Global variables
$BackupFile = Join-Path $TempDir 'xray-chrome-registry-backup.json'

# --- admin check --------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
}

# --- helpers ------------------------------------------------------------------
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# Test network connectivity before proceeding
if (-not (Test-NetworkConnectivity)) {
    $response = Read-Host "Network connectivity issues detected. Continue anyway? (y/N)"
    if ($response -notmatch '^[Yy]') {
        Write-Error "Aborted due to network connectivity issues."
    }
}

function Invoke-Download {
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$OutFile)
    if (Test-Path $OutFile) { Remove-Item $OutFile -Force -ErrorAction SilentlyContinue }
    Write-Host "Downloading: $Url"
    
    $ProgressPreference = 'Continue'
    $webClient = New-Object System.Net.WebClient
    $startTime = Get-Date
    
    # Register progress event
    Register-ObjectEvent -InputObject $webClient -EventName DownloadProgressChanged -Action {
        $elapsed = (Get-Date) - $Event.MessageData
        $percent = $Event.SourceEventArgs.ProgressPercentage
        $received = $Event.SourceEventArgs.BytesReceived
        $total = $Event.SourceEventArgs.TotalBytesToReceive
        
        if ($total -gt 0) {
            $speed = if ($elapsed.TotalSeconds -gt 0) { ($received / $elapsed.TotalSeconds) / 1MB } else { 0 }
            Write-Progress -Activity "Downloading file" -Status "$percent% complete - $([math]::Round($speed, 2)) MB/s" -PercentComplete $percent
        }
    } -MessageData $startTime | Out-Null
    
    try {
        $webClient.DownloadFile($Url, $OutFile)
        Write-Progress -Activity "Downloading file" -Completed
    }
    finally {
        $webClient.Dispose()
        Get-EventSubscriber | Where-Object { $_.SourceObject -is [System.Net.WebClient] } | Unregister-Event
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

function Backup-RegistryKeys {
    param([string[]]$KeyPaths, [string]$BackupPath)
    
    Write-Host "Creating registry backup..."
    $backupData = @{}
    
    foreach ($keyPath in $KeyPaths) {
        if (Test-Path $keyPath) {
            try {
                # Export registry key to temporary file
                $tempFile = Join-Path $env:TEMP "reg_backup_$(Get-Random).reg"
                $regPath = $keyPath -replace '^HKLM:', 'HKEY_LOCAL_MACHINE'
                Start-Process -FilePath 'reg.exe' -ArgumentList @('export', $regPath, $tempFile, '/y') -Wait -NoNewWindow
                
                if (Test-Path $tempFile) {
                    $backupData[$keyPath] = Get-Content $tempFile -Raw
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
            } catch {
                Write-Warning "Could not backup registry key: $keyPath"
            }
        }
    }
    
    # Save backup data
    $backupData | ConvertTo-Json | Set-Content $BackupPath -Encoding UTF8
    Write-Host "Registry backup saved to: $BackupPath"
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
    } catch {
        Write-Error "Failed to restore registry: $($_.Exception.Message)"
    }
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

function Disable-GoogleUpdates {
    Write-Host "Disabling Google Update services (legacy + new)..."
    $svcNames = @('gupdate','gupdatem','GoogleUpdaterService','GoogleUpdaterInternalService')
    foreach ($svc in $svcNames) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            try { if ($s.Status -ne 'Stopped') { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } } catch {}
            try { Set-Service -Name $svc -StartupType Disabled } catch {}
        }
    }

    Write-Host "Disabling Google Update scheduled tasks..."
    # Common task names
    $coreTasks = @('GoogleUpdateTaskMachineCore','GoogleUpdateTaskMachineUA')
    foreach ($tn in $coreTasks) {
        try { Disable-ScheduledTask -TaskName $tn -ErrorAction Stop | Out-Null } catch { }
    }
    # Catch-all for any other Google update/updater tasks in any folder
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -like 'GoogleUpdate*' -or $_.TaskName -like 'GoogleUpdater*'
    } | ForEach-Object {
        try { Disable-ScheduledTask -InputObject $_ -ErrorAction SilentlyContinue | Out-Null } catch { }
    }
}

function Set-ListPolicy {
    param(
        [Parameter(Mandatory)] [string] $BaseKey,
        [Parameter(Mandatory)] [string] $ListKeyName,
        [Parameter(Mandatory)] [string[]] $Values
    )
    $fullKey = Join-Path $BaseKey $ListKeyName
    if (Test-Path $fullKey) { Remove-Item $fullKey -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item $fullKey -Force | Out-Null
    $i = 1
    foreach ($v in $Values) {
        New-ItemProperty -Path $fullKey -Name "$i" -PropertyType String -Value $v -Force | Out-Null
        $i++
    }
}

# Create registry backup before making changes
$registryKeys = @($PolicyRoot, $UpdateRoot, $ChromeRoot)
Backup-RegistryKeys -KeyPaths $registryKeys -BackupPath $BackupFile

# --- A) DOWNGRADE / INSTALL SPECIFIC CHROME -----------------------------------
Write-Host "=== STEP A: Downgrade/Install specified Chrome build ==="

# 1) Uninstall any existing Chrome (system & per-user)
Uninstall-AllChrome

# 2) Download your specific Chrome build and install
Invoke-Download -Url $ChromeInstallerUrl -OutFile $ChromeExe
Write-Host "Installing Chrome from $ChromeExe ..."
Write-Progress -Activity "Installing Chrome" -Status "Running installer..." -PercentComplete 50
# Keep same behavior as your batch: /passive
Start-Process -FilePath $ChromeExe -ArgumentList '/passive' -Wait -NoNewWindow
Write-Progress -Activity "Installing Chrome" -Completed

# 3) Immediately disable updater services/tasks to prevent re-upgrade races
Disable-GoogleUpdates

# --- B) LOCKDOWN (Policies, ADMX, URL allowlist) ------------------------------
Write-Host "=== STEP B: Lockdown policies & ADMX templates ==="

# Download & extract the Enterprise bundle (for ADMX/ADML)
if (Test-Path $TempZip)     { Remove-Item $TempZip -Force -ErrorAction SilentlyContinue }
if (Test-Path $ExtractDir)  { Remove-Item $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host "Downloading Chrome Enterprise bundle..."
Invoke-Download -Url $BundleUrl -OutFile $TempZip

Write-Host "Extracting bundle..."
Write-Progress -Activity "Extracting Enterprise Bundle" -Status "Decompressing files..." -PercentComplete 25
Expand-Archive -LiteralPath $TempZip -DestinationPath $ExtractDir -Force
Write-Progress -Activity "Extracting Enterprise Bundle" -Completed

# Find ADMX directory dynamically (contains chrome.admx / google.admx)
$admxDir = Get-ChildItem -Path $ExtractDir -Recurse -Filter 'chrome.admx' -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty DirectoryName
if (-not $admxDir) { throw "Could not locate ADMX folder in extracted bundle." }

# Ensure PolicyDefinitions exists
if (-not (Test-Path $PolicyDefinitions)) {
    New-Item -Path $PolicyDefinitions -ItemType Directory -Force | Out-Null
}

# Copy ADMX files (chrome.admx, google.admx)
Write-Host "Installing ADMX templates..."
Get-ChildItem $admxDir -Filter '*.admx' -ErrorAction SilentlyContinue | ForEach-Object {
    Copy-Item $_.FullName -Destination $PolicyDefinitions -Force
}

# Copy ADML language files for chrome & google (all locales found)
Write-Host "Installing ADML language files..."
Get-ChildItem -Path $admxDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $locale = $_.Name
    $destLocaleDir = Join-Path $PolicyDefinitions $locale
    if (-not (Test-Path $destLocaleDir)) {
        New-Item -Path $destLocaleDir -ItemType Directory -Force | Out-Null
    }
    Get-ChildItem -Path $_.FullName -Filter '*.adml' -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -in @('chrome.adml','google.adml')
    } | ForEach-Object {
        Copy-Item $_.FullName -Destination $destLocaleDir -Force
    }
}

# Apply registry policies to disable updates (covers legacy & per-app override)
Write-Host "Applying registry policies to disable updates..."
New-Item -Path $UpdateRoot -Force | Out-Null
New-ItemProperty -Path $UpdateRoot -Name 'UpdateDefault' -PropertyType DWord -Value 0 -Force | Out-Null
New-ItemProperty -Path $UpdateRoot -Name 'AutoUpdateCheckPeriodMinutes' -PropertyType DWord -Value 0 -Force | Out-Null

# Per-app override for Chrome (AppID for Chrome Stable)
$chromeAppId = '{8A69D345-D564-463C-AFF1-A69D9E530F96}'
$appKey = Join-Path $UpdateRoot ("Applications\" + $chromeAppId)
New-Item -Path $appKey -Force | Out-Null
New-ItemProperty -Path $appKey -Name 'UpdateDefault' -PropertyType DWord -Value 0 -Force | Out-Null

# Redo service/task hardening now that policies are in place (belts & suspenders)
Disable-GoogleUpdates

# Restrict Chrome to localhost only
Write-Host "Applying URL allow/block list (localhost only)..."
New-Item -Path $ChromeRoot -Force | Out-Null
# New policy names (preferred)
Set-ListPolicy -BaseKey $ChromeRoot -ListKeyName 'URLBlocklist'  -Values @('*')
Set-ListPolicy -BaseKey $ChromeRoot -ListKeyName 'URLAllowlist'  -Values $AllowList
# Legacy names (for compatibility with older templates)
Set-ListPolicy -BaseKey $ChromeRoot -ListKeyName 'URLBlacklist'  -Values @('*')
Set-ListPolicy -BaseKey $ChromeRoot -ListKeyName 'URLWhitelist'  -Values $AllowList

# Optional: set homepage to localhost (uncomment if desired)
# New-ItemProperty -Path $ChromeRoot -Name 'HomepageLocation' -PropertyType String -Value 'http://127.0.0.1/' -Force | Out-Null
# New-ItemProperty -Path $ChromeRoot -Name 'RestoreOnStartup' -PropertyType DWord -Value 1 -Force | Out-Null
# New-ItemProperty -Path $ChromeRoot -Name 'HomepageIsNewTabPage' -PropertyType DWord -Value 0 -Force | Out-Null

# Apply policies
Write-Host "Forcing Group Policy refresh..."
Start-Process -FilePath "$env:SystemRoot\System32\gpupdate.exe" -ArgumentList '/force' -Wait

Write-Host "`nDone."
Write-Host "Verify in Chrome:"
Write-Host " - chrome://policy  (URLBlocklist/Allowlist present, UpdateDefault=0)"
Write-Host " - chrome://settings/help  ('Updates disabled by your administrator')"
