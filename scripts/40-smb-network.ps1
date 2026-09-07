#requires -Version 5.1
<#  Category: SMB + network exposure

    2025 notes vs 2019 baseline:
      * SMB SIGNING IS NOW REQUIRED BY DEFAULT (client AND server) on Server
        2025 / Win11 24H2. Disabling it here is therefore a genuine, meaningful
        downgrade that re-enables NTLM relay practice.
      * SMB1 is not installed by default and is deprecated. We install the
        optional feature (FS-SMB1) first; on builds where it has been removed
        the install simply fails and we log it.
      * The SMB CLIENT now blocks guest/insecure logons by default, so we also
        flip EnableInsecureGuestLogons for accessing weak shares.
      * NTLM min security is loosened for legacy interop.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'smb-network'

# ── SMB1 (install optional feature, then enable protocol) ────────────────
try {
    $f = Get-WindowsFeature -Name FS-SMB1 -ErrorAction Stop
    if ($f -and -not $f.Installed) { Install-WindowsFeature FS-SMB1 -ErrorAction Stop | Out-Null }
    Write-RangeManifest $cat 'install-feature' 'FS-SMB1'
} catch { Write-RangeLog "FS-SMB1 feature unavailable on this build: $($_.Exception.Message)" 'WARN' }

Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' DWord 1 $cat
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction Stop
    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -ErrorAction Stop
} catch { Write-RangeLog "Set-SmbServerConfiguration protocol: $($_.Exception.Message)" 'WARN' }

# ── SMB signing OFF (relay), encryption OFF, insecure guest ON ───────────
try {
    Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -EncryptData $false -Force -ErrorAction Stop
    Set-SmbClientConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -EnableInsecureGuestLogons $true -Force -ErrorAction Stop
} catch { Write-RangeLog "SMB signing/guest cmdlets: $($_.Exception.Message)" 'WARN' }

$srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$wks = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
Set-RegValue $srv 'RequireSecuritySignature' DWord 0 $cat
Set-RegValue $srv 'EnableSecuritySignature'  DWord 0 $cat
Set-RegValue $wks 'RequireSecuritySignature' DWord 0 $cat
Set-RegValue $wks 'EnableSecuritySignature'  DWord 0 $cat
Set-RegValue $wks 'AllowInsecureGuestAuth'   DWord 1 $cat

# ── Null sessions / anonymous pipe + share access ────────────────────────
Set-RegValue $srv 'RestrictNullSessAccess' DWord 0 $cat
Set-RegValue $srv 'NullSessionShares' MultiString @('IPC$') $cat
Set-RegValue $srv 'NullSessionPipes'  MultiString @('samr','lsarpc','netlogon','browser') $cat

# ── NTLM min security loosened ───────────────────────────────────────────
$msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
Set-RegValue $msv 'NtlmMinClientSec' DWord 0 $cat
Set-RegValue $msv 'NtlmMinServerSec' DWord 0 $cat

# ── Windows Firewall fully off (policy + live state) ─────────────────────
foreach ($p in 'DomainProfile','PrivateProfile','PublicProfile','StandardProfile') {
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$p" 'EnableFirewall' DWord 0 $cat
}
try { Set-NetFirewallProfile -All -Enabled False -ErrorAction Stop } catch { Invoke-Native 'netsh.exe' @('advfirewall','set','allprofiles','state','off') $cat }

Write-RangeLog 'SMB + network category complete.' 'OK'
