#requires -Version 5.1
<#  Category: UAC, LSA Protection (PPL), Credential Guard / VBS

    2025 caveat — READ THIS:
      Server 2025 can ship with VBS + Credential Guard and LSASS PPL ENABLED
      BY DEFAULT, and when they were enabled "with UEFI lock" a registry value
      of 0 is NOT enough — the setting is re-asserted from a UEFI variable at
      boot. The registry writes below are correct and sufficient when the
      features were enabled WITHOUT a UEFI lock (the usual case for a freshly
      built lab image). If LSASS still runs protected / Credential Guard still
      shows running after a reboot, clear the UEFI lock as well:

         - Credential Guard: run Microsoft's DG_Readiness_Tool  -Disable
           (removes EFI variables), then reboot twice and accept the firmware
           prompt.
         - LSA PPL UEFI lock: see KB "How to configure added LSA protection"
           to remove the UEFI variable, then reboot.

      Verify after reboot:
         Get-CimInstance -Class Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
         (Get-Process lsass).Path ; look for PPL via  Get-CimInstance ... or Process Hacker.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'uac-lsa-vbs'
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

# ── UAC fully disabled + never-notify ────────────────────────────────────
Set-RegValue $sys 'EnableLUA'                 DWord 0 $cat
Set-RegValue $sys 'ConsentPromptBehaviorAdmin' DWord 0 $cat
Set-RegValue $sys 'ConsentPromptBehaviorUser'  DWord 0 $cat
Set-RegValue $sys 'PromptOnSecureDesktop'      DWord 0 $cat
Set-RegValue $sys 'ValidateAdminCodeSignatures' DWord 0 $cat
Set-RegValue $sys 'EnableUIADesktopToggle'     DWord 1 $cat
# Remote UAC token filtering off -> local admins get full token over the network
Set-RegValue $sys 'LocalAccountTokenFilterPolicy' DWord 1 $cat

# ── LSA Protection (PPL) OFF -> allows LSASS dumping ─────────────────────
Set-RegValue $lsa 'RunAsPPL'     DWord 0 $cat
Set-RegValue $lsa 'RunAsPPLBoot' DWord 0 $cat

# ── Credential Guard / VBS OFF ───────────────────────────────────────────
Set-RegValue $lsa 'LsaCfgFlags' DWord 0 $cat
$dg = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
Set-RegValue $dg 'EnableVirtualizationBasedSecurity' DWord 0 $cat
Set-RegValue $dg 'RequirePlatformSecurityFeatures'   DWord 0 $cat
Set-RegValue $dg 'LsaCfgFlags'                        DWord 0 $cat
Set-RegValue "$dg\Scenarios\CredentialGuard"          'Enabled' DWord 0 $cat
Set-RegValue "$dg\Scenarios\HypervisorEnforcedCodeIntegrity" 'Enabled' DWord 0 $cat

Write-RangeLog 'UAC / LSA-PPL / VBS category complete. Reboot required; verify PPL+CG actually off (see header if UEFI-locked).' 'WARN'
