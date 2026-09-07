#requires -Version 5.1
<#  Category: Updates + Microsoft Defender

    Freezes patch level (so red-team CVEs stay reachable) and neuters Defender.

    2025 notes vs the 2019 baseline:
      * DisableAntiSpyware GP value has been IGNORED since the Aug-2020 platform
        update. It is set here only for completeness; it does nothing on 2025.
      * Set-MpPreference toggles are silently blocked if Tamper Protection is ON.
        On a fresh, non-onboarded Server 2025 lab box TP is usually OFF, so they
        work. If they fail, either disable TP in the Defender UI first or set
        RemoveDefenderFeature = $true to uninstall the feature outright.
      * WaaSMedicSvc / wuauserv are protected; sc.exe config is often denied, so
        we set the service Start value via the registry instead.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'updates-defender'

# ── Windows Update + its self-repair service ─────────────────────────────
try { Stop-Service wuauserv -Force -ErrorAction SilentlyContinue } catch {}
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv'      'Start' DWord 4 $cat   # disabled
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'  'Start' DWord 4 $cat   # Update Medic (repairs wuauserv)
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc'        'Start' DWord 4 $cat   # Update Orchestrator
Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' DWord 1 $cat

# ── Defender: runtime toggles (best-effort; TP may block) ────────────────
$mp = @{
    DisableRealtimeMonitoring   = $true
    DisableIOAVProtection       = $true
    DisableScriptScanning       = $true
    DisableBehaviorMonitoring   = $true
    DisableBlockAtFirstSeen     = $true
    MAPSReporting               = 0
    SubmitSamplesConsent        = 2
}
if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
    foreach ($k in $mp.Keys) {
        # MUST splat from a VARIABLE. `Set-MpPreference @{ ... }` passes the
        # hashtable POSITIONALLY and always throws "A positional parameter cannot
        # be found..." -- which the old catch mislabelled as Tamper Protection,
        # so every toggle silently failed and Defender stayed on. (Finding F4.)
        $arg = @{ $k = $mp[$k] }
        try { Set-MpPreference @arg -ErrorAction Stop
              Write-RangeLog "Set-MpPreference $k=$($mp[$k])" }
        catch { Write-RangeLog "Set-MpPreference $k failed (Tamper Protection or policy?): $($_.Exception.Message)" 'WARN' }
    }
    try { Add-MpPreference -ExclusionPath 'C:\','C:\ProgramData\SysTasks' -ErrorAction Stop
          Write-RangeManifest $cat 'defender-exclusion' 'C:\;C:\ProgramData\SysTasks' } catch {}
} else { Write-RangeLog 'Defender cmdlets not present.' 'WARN' }

# ── Defender: policy registry (belt-and-suspenders) ──────────────────────
$dp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
Set-RegValue $dp 'DisableAntiSpyware' DWord 1 $cat            # NOTE: ignored on 2025, kept for parity
Set-RegValue "$dp\Real-Time Protection" 'DisableRealtimeMonitoring'  DWord 1 $cat
Set-RegValue "$dp\Real-Time Protection" 'DisableBehaviorMonitoring'  DWord 1 $cat
Set-RegValue "$dp\Real-Time Protection" 'DisableOnAccessProtection'  DWord 1 $cat
Set-RegValue "$dp\Real-Time Protection" 'DisableScanOnRealtimeEnable' DWord 1 $cat
Set-RegValue "$dp\Spynet" 'SpyNetReporting'     DWord 0 $cat
Set-RegValue "$dp\Spynet" 'SubmitSamplesConsent' DWord 2 $cat
Set-RegValue "$dp\Windows Defender Exploit Guard\ASR" 'ExploitGuard_ASR_Rules' DWord 0 $cat
# Tamper Protection reg toggle (unreliable when cloud/Intune-managed; harmless otherwise)
Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' 'TamperProtection' DWord 0 $cat

# ── Optional: remove the Defender feature entirely ───────────────────────
if ($Config.RemoveDefenderFeature) {
    Write-RangeLog 'Uninstalling Windows-Defender feature (reboot required).' 'WARN'
    try { Uninstall-WindowsFeature -Name Windows-Defender -ErrorAction Stop | Out-Null
          Write-RangeManifest $cat 'uninstall-feature' 'Windows-Defender' }
    catch { Write-RangeLog "Feature removal failed: $($_.Exception.Message)" 'WARN' }
}

Write-RangeLog 'Updates + Defender category complete.' 'OK'
