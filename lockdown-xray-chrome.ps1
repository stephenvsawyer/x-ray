# lockdown-xray-chrome.ps1
# Purpose: Lock Chrome to localhost and disable updates on dedicated X-ray PCs
# Run: As Administrator

# --- safety & config ----------------------------------------------------------
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Customize if needed:
$BundleUrl   = 'https://github.com/dunamismax/x-ray/releases/download/v1.0/GoogleChromeEnterpriseBundle64.zip'
$TempZip     = Join-Path $env:TEMP 'GoogleChromeEnterpriseBundle64.zip'
$ExtractDir  = Join-Path $env:TEMP 'GoogleChromeEnterpriseBundle64'
$PolicyRoot  = 'HKLM:\SOFTWARE\Policies\Google'
$ChromeRoot  = Join-Path $PolicyRoot 'Chrome'
$UpdateRoot  = Join-Path $PolicyRoot 'Update'
$PolicyDefinitions = Join-Path $env:WINDIR 'PolicyDefinitions'
$AllowList   = @('127.0.0.1','localhost')  # Only allow these

# --- admin check --------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
}

# --- helper: create or reset a Chrome list policy key and set numbered values --
function Set-ListPolicy {
    param(
        [Parameter(Mandatory)] [string] $BaseKey,
        [Parameter(Mandatory)] [string] $ListKeyName,
        [Parameter(Mandatory)] [string[]] $Values
    )
    $fullKey = Join-Path $BaseKey $ListKeyName
    if (Test-Path $fullKey) { Remove-Item $fullKey -Recurse -Force }
    New-Item $fullKey -Force | Out-Null
    $i = 1
    foreach ($v in $Values) {
        New-ItemProperty -Path $fullKey -Name "$i" -PropertyType String -Value $v -Force | Out-Null
        $i++
    }
}

# --- 1) Download & extract the Enterprise bundle (for ADMX/ADML) --------------
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch { }

if (Test-Path $TempZip)     { Remove-Item $TempZip -Force }
if (Test-Path $ExtractDir)  { Remove-Item $ExtractDir -Recurse -Force }

Write-Host "Downloading Chrome Enterprise bundle..."
Invoke-WebRequest -Uri $BundleUrl -OutFile $TempZip

Write-Host "Extracting bundle..."
Expand-Archive -LiteralPath $TempZip -DestinationPath $ExtractDir -Force

# Find ADMX directory dynamically (contains chrome.admx / google.admx)
$admxDir = Get-ChildItem -Path $ExtractDir -Recurse -Filter 'chrome.admx' |
    Select-Object -First 1 -ExpandProperty DirectoryName
if (-not $admxDir) { throw "Could not locate ADMX folder in extracted bundle." }

# Ensure PolicyDefinitions exists
if (-not (Test-Path $PolicyDefinitions)) {
    New-Item -Path $PolicyDefinitions -ItemType Directory -Force | Out-Null
}

# Copy ADMX files (chrome.admx, google.admx)
Write-Host "Installing ADMX templates..."
Get-ChildItem $admxDir -Filter '*.admx' | ForEach-Object {
    Copy-Item $_.FullName -Destination $PolicyDefinitions -Force
}

# Copy ADML language files for chrome & google (all locales found)
Write-Host "Installing ADML language files..."
Get-ChildItem -Path $admxDir -Directory | ForEach-Object {
    $locale = $_.Name
    $destLocaleDir = Join-Path $PolicyDefinitions $locale
    if (-not (Test-Path $destLocaleDir)) {
        New-Item -Path $destLocaleDir -ItemType Directory -Force | Out-Null
    }
    Get-ChildItem -Path $_.FullName -Filter '*.adml' -File | Where-Object {
        $_.Name -in @('chrome.adml','google.adml')
    } | ForEach-Object {
        Copy-Item $_.FullName -Destination $destLocaleDir -Force
    }
}

# --- 2) Disable Chrome/Google auto-updates (policy + services + tasks) --------
Write-Host "Applying registry policies to disable updates..."
# Machine-wide Google Update policies
New-Item -Path $UpdateRoot -Force | Out-Null
New-ItemProperty -Path $UpdateRoot -Name 'UpdateDefault' -PropertyType DWord -Value 0 -Force | Out-Null
New-ItemProperty -Path $UpdateRoot -Name 'AutoUpdateCheckPeriodMinutes' -PropertyType DWord -Value 0 -Force | Out-Null

# Per-app override for Chrome (AppID for Chrome Stable)
$chromeAppId = '{8A69D345-D564-463C-AFF1-A69D9E530F96}'
$appKey = Join-Path $UpdateRoot ("Applications\" + $chromeAppId)
New-Item -Path $appKey -Force | Out-Null
New-ItemProperty -Path $appKey -Name 'UpdateDefault' -PropertyType DWord -Value 0 -Force | Out-Null

# Stop & disable Google Update services
Write-Host "Disabling Google Update services..."
foreach ($svc in 'gupdate','gupdatem') {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        try { if ($s.Status -ne 'Stopped') { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } } catch {}
        try { Set-Service -Name $svc -StartupType Disabled } catch {}
    }
}

# Disable Google Update scheduled tasks
Write-Host "Disabling Google Update scheduled tasks..."
$taskNames = @('GoogleUpdateTaskMachineCore','GoogleUpdateTaskMachineUA')
foreach ($tn in $taskNames) {
    try { Disable-ScheduledTask -TaskName $tn -ErrorAction Stop | Out-Null } catch {}
}
# Also catch any similarly named tasks just in case
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -like 'GoogleUpdate*'
} | ForEach-Object {
    try { Disable-ScheduledTask -InputObject $_ -ErrorAction SilentlyContinue | Out-Null } catch {}
}

# --- 3) Restrict Chrome to localhost only ------------------------------------
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

# --- 4) Apply policies --------------------------------------------------------
Write-Host "Forcing Group Policy refresh..."
Start-Process -FilePath "$env:SystemRoot\System32\gpupdate.exe" -ArgumentList '/force' -Wait

Write-Host "`nDone."
Write-Host "Verify in Chrome: go to  chrome://policy  (URLBlocklist/Allowlist) and  chrome://settings/help  ('Updates disabled by your administrator')."
