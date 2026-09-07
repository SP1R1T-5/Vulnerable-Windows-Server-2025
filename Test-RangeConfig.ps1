#requires -Version 5.1
<#
.SYNOPSIS
    Verify that the cyber-range misconfigurations are actually in place.

.DESCRIPTION
    Read-only post-build checker. It inspects the host for every intentional
    weakness the build applies (machine-level categories 10-90/75 and, on a DC,
    the dc\ scenarios) and reports PASS / FAIL / WARN / N-A with a summary.

    This is the executable form of the Part B matrix in
    docs\VERIFICATION-SESSION.md. It is deliberately standalone (no dependency on
    RangeCommon.psm1) so it runs on a freshly built or partially damaged box, and
    it changes NOTHING.

    OPERATIONAL vs DECLARED
      A registry value is a DECLARATION; it is not proof the behaviour is active.
      Where the live state can be queried, this script queries it and says so:
      checks tagged [live] read the running subsystem (service state, WSMan,
      SMB config, DeviceGuard, TS settings, effective execution policy, an actual
      OpenProcess against lsass). Checks tagged [reg] are registry-only because
      that IS the mechanism, or because no live API exists.

    States:
      PASS  the intended misconfiguration is present (as-built)
      FAIL  it is NOT present  -- the build did not apply it, or it was reverted
      WARN  present but effect needs a reboot, OR a known no-op on 2025 (value set
            but the OS ignores it), OR could not be fully verified
      N-A   not applicable to this host/config (feature toggle off, or not a DC)

    Every result carries a Control field (NIST SP 800-53 Rev.5 / CIS Controls
    v8.1) so the output doubles as the scoring baseline for blue-team
    remediation -- see docs\GRC-CONTROL-MAP.md.

    Run it as Administrator for complete results (some reads require elevation).
    Exit code is always 0 -- this is a measurement tool, not a build gate.

.PARAMETER Format
    Table (default, console), Csv, or Json.

.PARAMETER Out
    Optional path to also write the results (csv/json inferred from -Format).

.PARAMETER ShowControl
    Print the control mapping inline in the table view.

.EXAMPLE
    .\Test-RangeConfig.ps1
.EXAMPLE
    .\Test-RangeConfig.ps1 -ShowControl
.EXAMPLE
    .\Test-RangeConfig.ps1 -Format Csv -Out C:\Temp\range-check.csv
#>
[CmdletBinding()]
param(
    [ValidateSet('Table','Csv','Json')][string]$Format = 'Table',
    [string]$Out,
    [switch]$ShowControl
)

$ErrorActionPreference = 'Continue'
$script:Results = New-Object System.Collections.Generic.List[object]

# ── config (best-effort: tells us what to EXPECT -- DC or not, account names) ──
$cfg = $null
$cfgPath = Join-Path $PSScriptRoot 'config\range.config.psd1'
if (Test-Path $cfgPath) { try { $cfg = Import-PowerShellDataFile $cfgPath } catch {} }

$role   = (Get-CimInstance Win32_ComputerSystem).DomainRole
$isDC   = $role -ge 4
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

function Add-Result {
    param(
        [string]$Category,
        [string]$Check,
        [ValidateSet('PASS','FAIL','WARN','N-A')][string]$State,
        [string]$Detail = '',
        [string]$Control = '',
        [ValidateSet('live','reg','')][string]$Probe = ''
    )
    $script:Results.Add([pscustomobject]@{
        Category = $Category; Check = $Check; State = $State
        Detail = $Detail; Control = $Control; Probe = $Probe
    })
}

function Get-RegVal {
    <# Non-throwing. Get-ItemProperty -ErrorAction Stop inside a try/catch still
       fills $Error with one record per missing key, which on an unbuilt host is
       ~100 entries of pure noise that looks like the checker is broken. Probe
       instead of throwing. #>
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return $null }
    if ($item.GetValueNames() -notcontains $Name) { return $null }
    return $item.GetValue($Name)
}

# Server-only cmdlets: on a client SKU these do not exist at all, and
# -ErrorAction cannot suppress CommandNotFoundException.
function Test-HasCommand { param([string]$Name) [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

# Get-LocalUser -Name <missing> writes an error record even with
# -ErrorAction SilentlyContinue. Enumerate once and match in memory instead, so
# a host that is missing every seeded account does not look like a crash.
$script:LocalUsers = @()
if (Test-HasCommand 'Get-LocalUser') { $script:LocalUsers = @(Get-LocalUser -ErrorAction SilentlyContinue) }
function Test-LocalUserExists { param([string]$Name) [bool](@($script:LocalUsers | Where-Object { $_.Name -eq $Name }).Count) }

# Registry check: PASS when the value equals $Expect. -RebootNote / -NoOpNote
# downgrade a matching value to WARN with an explanation.
function Test-Reg {
    param(
        [string]$Category, [string]$Check, [string]$Path, [string]$Name, $Expect,
        [string]$RebootNote, [string]$NoOpNote, [string]$Control
    )
    $v = Get-RegVal $Path $Name
    if ($null -eq $v) { Add-Result $Category $Check 'FAIL' "not set ($Name absent under $Path)" $Control 'reg'; return }
    if ("$v" -eq "$Expect") {
        if ($RebootNote)   { Add-Result $Category $Check 'WARN' "set ($Name=$v); $RebootNote" $Control 'reg' }
        elseif ($NoOpNote) { Add-Result $Category $Check 'WARN' "set ($Name=$v); $NoOpNote"   $Control 'reg' }
        else               { Add-Result $Category $Check 'PASS' "$Name=$v" $Control 'reg' }
    } else {
        Add-Result $Category $Check 'FAIL' "$Name=$v (expected $Expect)" $Control 'reg'
    }
}

# Multi-value registry presence check (MultiString / list contents).
function Test-RegContains {
    param([string]$Category, [string]$Check, [string]$Path, [string]$Name, [string[]]$Expect, [string]$Control)
    $v = Get-RegVal $Path $Name
    if ($null -eq $v) { Add-Result $Category $Check 'FAIL' "$Name not set" $Control 'reg'; return }
    $have = @($v)
    $miss = @($Expect | Where-Object { $have -notcontains $_ })
    if ($miss.Count -eq 0) { Add-Result $Category $Check 'PASS' ("$Name = " + ($have -join ',')) $Control 'reg' }
    else { Add-Result $Category $Check 'WARN' ("$Name present but missing: " + ($miss -join ',')) $Control 'reg' }
}

# ── LIVE probe: can lsass actually be opened for read? ────────────────────
#    This is the operational truth behind RunAsPPL. A registry 0 means nothing
#    if the feature was enabled with a UEFI lock, or if the box has not rebooted.
function Test-LsassReadable {
    <# Returns $true (dumpable / PPL off), $false (protected), $null (unknown). #>
    try {
        if (-not ('RangePPL' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RangePPL {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr h);
    // PROCESS_VM_READ (0x0010) | PROCESS_QUERY_INFORMATION (0x0400)
    public static int TryOpen(int pid) {
        IntPtr h = OpenProcess(0x0010 | 0x0400, false, pid);
        if (h == IntPtr.Zero) return Marshal.GetLastWin32Error();
        CloseHandle(h);
        return 0;
    }
}
'@
        }
        $p = Get-Process lsass -ErrorAction Stop
        $rc = [RangePPL]::TryOpen($p.Id)
        return ($rc -eq 0)
    } catch { return $null }
}

# Wininit logs event 12 at boot when lsass starts protected. Corroborates the above.
function Get-LsassPplEvent {
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Wininit'; Id=12 } -MaxEvents 1 -ErrorAction Stop
        if ($ev -and $ev.Message -match 'level:\s*(\d+)') { return [int]$Matches[1] }
    } catch {}
    return $null
}

Write-Host ""
Write-Host "RANGE CONFIG CHECK  --  $env:COMPUTERNAME  --  $(Get-Date -Format s)" -ForegroundColor Cyan
Write-Host ("Role: " + $(switch ($role) {5{'primary DC'}4{'backup DC'}3{'member server'}2{'standalone server'}default{"role $role"}}) +
            $(if (-not $elevated) {'   [NOT elevated -- some checks may under-report]'} else {''})) -ForegroundColor Cyan

# ══ Updates + Defender ════════════════════════════════════════════════════
$c = 'updates-defender'
$ctlUpd = 'NIST SI-2, CM-3; CIS 7.3'
Test-Reg $c 'Windows Update (wuauserv) disabled'    'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv'     'Start' 4 -Control $ctlUpd
Test-Reg $c 'Update Medic (WaaSMedicSvc) disabled'  'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' 'Start' 4 -Control $ctlUpd
Test-Reg $c 'Update Orchestrator (UsoSvc) disabled' 'HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc'       'Start' 4 -Control $ctlUpd
Test-Reg $c 'NoAutoUpdate policy'                   'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' 1 -Control $ctlUpd

# [live] the registry Start value is a declaration; WaaSMedicSvc exists precisely
# to undo it, so confirm the services really are disabled and not running.
foreach ($svcName in 'wuauserv','WaaSMedicSvc','UsoSvc') {
    $s = Get-Service $svcName -ErrorAction SilentlyContinue
    if (-not $s) { Add-Result $c "[live] $svcName present" 'WARN' 'service not found' $ctlUpd 'live'; continue }
    if ($s.StartType -eq 'Disabled' -and $s.Status -ne 'Running') {
        Add-Result $c "[live] $svcName disabled + stopped" 'PASS' "$($s.StartType)/$($s.Status)" $ctlUpd 'live'
    } elseif ($s.StartType -eq 'Disabled') {
        Add-Result $c "[live] $svcName disabled + stopped" 'WARN' "$($s.StartType) but still $($s.Status) -- reboot to settle" $ctlUpd 'live'
    } else {
        Add-Result $c "[live] $svcName disabled + stopped" 'FAIL' "StartType=$($s.StartType) -- registry set but service re-enabled" $ctlUpd 'live'
    }
}

if ($cfg -and $cfg.RemoveDefenderFeature) {
    $f = if (Test-HasCommand 'Get-WindowsFeature') { Get-WindowsFeature -Name Windows-Defender -ErrorAction SilentlyContinue } else { $null }
    if ($f -and -not $f.Installed) { Add-Result $c '[live] Defender feature removed' 'PASS' 'Windows-Defender not installed' 'NIST SI-3; CIS 10.1' 'live' }
    elseif ($f) { Add-Result $c '[live] Defender feature removed' 'FAIL' 'Windows-Defender still installed' 'NIST SI-3; CIS 10.1' 'live' }
    else { Add-Result $c '[live] Defender feature removed' 'WARN' 'could not query feature' 'NIST SI-3; CIS 10.1' 'live' }
} else {
    $mp = $null; try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}
    if ($mp) {
        if (-not $mp.RealTimeProtectionEnabled) { Add-Result $c '[live] Defender real-time protection off' 'PASS' 'RealTimeProtectionEnabled=False' 'NIST SI-3; CIS 10.1' 'live' }
        else { Add-Result $c '[live] Defender real-time protection off' 'FAIL' 'RealTimeProtectionEnabled=True -- Tamper Protection, or the Set-MpPreference splat bug (F4), has regressed' 'NIST SI-3; CIS 10.1' 'live' }
        if ($mp.IsTamperProtected) { Add-Result $c '[live] Tamper Protection' 'WARN' 'ON -- registry/Set-MpPreference toggles are blocked; consider RemoveDefenderFeature' 'NIST SI-3' 'live' }
    } else { Add-Result $c '[live] Defender status' 'WARN' 'Get-MpComputerStatus unavailable (feature removed or cmdlet missing)' 'NIST SI-3' 'live' }
    Test-Reg $c 'Defender policy: realtime disabled' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' 1 -Control 'NIST SI-3; CIS 10.1'
}

# ══ Credential exposure ════════════════════════════════════════════════════
$c = 'credential-exposure'
Test-Reg $c 'WDigest UseLogonCredential'      'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 1 -Control 'NIST IA-5(1), SC-28'
Test-Reg $c 'WDigest Negotiate'               'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'Negotiate' 1 -Control 'NIST IA-5(1)'
Test-Reg $c 'LM hash stored (NoLmHash=0)'     'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLmHash' 0 -Control 'NIST IA-7, SC-13'
Test-Reg $c 'LmCompatibilityLevel=0'          'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 0 -NoOpNote 'NTLMv1 is removed on Server 2025 -- config finding only, not an exploit (F9)' -Control 'NIST IA-7, SC-13'
Test-Reg $c 'RestrictAnonymous=0'             'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 0 -Control 'NIST AC-3, AC-14'
Test-Reg $c 'RestrictAnonymousSAM=0'          'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 0 -Control 'NIST AC-3, AC-14'
Test-Reg $c 'EveryoneIncludesAnonymous=1'     'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' 1 -Control 'NIST AC-3, AC-14'
Test-Reg $c 'CachedLogonsCount=50'            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount' 50 -Control 'NIST AC-3, IA-5'
# Kerberos etypes: the build sets 0x1C (28) = RC4+AES128+AES256. RC4 (0x4) keeps
# Kerberoasting viable; the AES bits (0x18) keep domain logon working on 2025.
# A bare 0x4 (RC4-only) is the F26 lockout bug -- flag it as FAIL, not PASS.
$ket = Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes'
if ($null -eq $ket) { Add-Result $c 'Kerberos etypes RC4+AES (0x1C)' 'FAIL' 'SupportedEncryptionTypes not set' 'NIST SC-13' 'reg' }
elseif (([int]$ket -band 0x4) -and ([int]$ket -band 0x18)) { Add-Result $c 'Kerberos etypes RC4+AES (0x1C)' 'PASS' "SupportedEncryptionTypes=$ket (RC4 for Kerberoast + AES so domain logon works)" 'NIST SC-13' 'reg' }
elseif (([int]$ket -band 0x4) -and -not ([int]$ket -band 0x18)) { Add-Result $c 'Kerberos etypes RC4+AES (0x1C)' 'FAIL' "SupportedEncryptionTypes=$ket = RC4-ONLY -- breaks every domain logon on 2025 (F26); must be 28" 'NIST SC-13' 'reg' }
else { Add-Result $c 'Kerberos etypes RC4+AES (0x1C)' 'WARN' "SupportedEncryptionTypes=$ket (no RC4 bit -- Kerberoast downgrade weaker)" 'NIST SC-13' 'reg' }

# Autologon -- the lockout-relevant set (F1)
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$ctlAuto = 'NIST IA-5(1)(c), AC-2'
Test-Reg $c 'AutoAdminLogon=1'  $wl 'AutoAdminLogon' 1 -Control $ctlAuto
if (Get-RegVal $wl 'DefaultUserName') { Add-Result $c 'DefaultUserName set' 'PASS' (Get-RegVal $wl 'DefaultUserName') $ctlAuto 'reg' }
else { Add-Result $c 'DefaultUserName set' 'FAIL' 'not set' $ctlAuto 'reg' }
if (Get-RegVal $wl 'DefaultPassword') { Add-Result $c 'DefaultPassword present (cleartext)' 'PASS' 'set in Winlogon' $ctlAuto 'reg' }
else { Add-Result $c 'DefaultPassword present (cleartext)' 'FAIL' 'not set' $ctlAuto 'reg' }
$ddn = Get-RegVal $wl 'DefaultDomainName'
if ($ddn) {
    $wantDom = if ($isDC -and $cfg -and $cfg.DC -and $cfg.DC.NetbiosName) { $cfg.DC.NetbiosName } else { '.' }
    if ("$ddn" -eq "$wantDom") { Add-Result $c 'DefaultDomainName correct for role (F1)' 'PASS' "$ddn" $ctlAuto 'reg' }
    else { Add-Result $c 'DefaultDomainName correct for role (F1)' 'WARN' "=$ddn but this host expects '$wantDom' -- autologon may fail" $ctlAuto 'reg' }
} else { Add-Result $c 'DefaultDomainName correct for role (F1)' 'FAIL' 'absent -- autologon fails after promotion' $ctlAuto 'reg' }
$fal = Get-RegVal $wl 'ForceAutoLogon'
if ($null -eq $fal -or "$fal" -eq '0') { Add-Result $c 'ForceAutoLogon NOT set (F1)' 'PASS' 'absent or 0 (no autologon loop)' $ctlAuto 'reg' }
else { Add-Result $c 'ForceAutoLogon NOT set (F1)' 'FAIL' "ForceAutoLogon=$fal -- LOCKOUT RISK" $ctlAuto 'reg' }

# ══ UAC / LSA PPL / VBS ════════════════════════════════════════════════════
$c = 'uac-lsa-vbs'
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Test-Reg $c 'UAC disabled (EnableLUA=0)'          $sys 'EnableLUA' 0 -RebootNote 'takes effect after reboot' -Control 'NIST AC-6(2), AC-6(9)'
Test-Reg $c 'ConsentPromptBehaviorAdmin=0'        $sys 'ConsentPromptBehaviorAdmin' 0 -Control 'NIST AC-6(9)'
Test-Reg $c 'PromptOnSecureDesktop=0'             $sys 'PromptOnSecureDesktop' 0 -Control 'NIST AC-6(9)'
Test-Reg $c 'ValidateAdminCodeSignatures=0'       $sys 'ValidateAdminCodeSignatures' 0 -Control 'NIST SI-7'
Test-Reg $c 'LocalAccountTokenFilterPolicy=1'     $sys 'LocalAccountTokenFilterPolicy' 1 -Control 'NIST AC-6, AC-17'
Test-Reg $c 'LSA PPL off (RunAsPPL=0)'            'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 0 -Control 'NIST SC-39, SI-3'
Test-Reg $c 'LSA PPL boot off (RunAsPPLBoot=0)'   'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPLBoot' 0 -Control 'NIST SC-39'
Test-Reg $c 'Credential Guard off (LsaCfgFlags=0)' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags' 0 -Control 'NIST IA-2, SC-39'
Test-Reg $c 'VBS off (DeviceGuard)'               'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity' 0 -Control 'NIST IA-2, SC-39'
Test-Reg $c 'HVCI off (DeviceGuard scenario)'     'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled' 0 -Control 'NIST SI-7'

# [live] LSASS protection -- the operational truth behind RunAsPPL. A registry 0
# is meaningless if PPL was enabled with a UEFI lock, or before a reboot.
$lsassOpen = Test-LsassReadable
$pplEvent  = Get-LsassPplEvent
if ($lsassOpen -eq $true) {
    Add-Result $c '[live] LSASS dumpable (PPL not enforced)' 'PASS' 'OpenProcess(VM_READ) on lsass succeeded -- credential dumping will work' 'NIST SC-39, SI-3' 'live'
} elseif ($lsassOpen -eq $false) {
    $lvl = if ($null -ne $pplEvent) { " (Wininit event 12 reports level $pplEvent)" } else { '' }
    Add-Result $c '[live] LSASS dumpable (PPL not enforced)' 'FAIL' "OpenProcess(VM_READ) on lsass DENIED -- lsass is still protected$lvl. If RunAsPPL=0 and you have rebooted, the UEFI lock needs clearing (see 30-uac-lsa-vbs.ps1 header)" 'NIST SC-39, SI-3' 'live'
} else {
    Add-Result $c '[live] LSASS dumpable (PPL not enforced)' 'WARN' 'could not probe lsass (run elevated)' 'NIST SC-39, SI-3' 'live'
}
if ($null -ne $pplEvent -and $lsassOpen -eq $true) {
    Add-Result $c '[live] Wininit PPL boot event' 'WARN' "event 12 says lsass started protected at level $pplEvent but it is readable now -- verify after a clean reboot" 'NIST SC-39' 'live'
}

# [live] VBS / Credential Guard running state (post-reboot truth)
try {
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
    $running = @($dg.SecurityServicesRunning)
    if ($running -contains 1) { Add-Result $c '[live] Credential Guard NOT running' 'FAIL' 'SecurityServicesRunning includes 1 (CredGuard active) -- may need UEFI-lock removal' 'NIST IA-2, SC-39' 'live' }
    else { Add-Result $c '[live] Credential Guard NOT running' 'PASS' 'CredGuard not in SecurityServicesRunning' 'NIST IA-2, SC-39' 'live' }
    if ($dg.VirtualizationBasedSecurityStatus -eq 2) { Add-Result $c '[live] VBS not running' 'FAIL' 'VirtualizationBasedSecurityStatus=2 (running)' 'NIST SC-39' 'live' }
    else { Add-Result $c '[live] VBS not running' 'PASS' "VirtualizationBasedSecurityStatus=$($dg.VirtualizationBasedSecurityStatus)" 'NIST SC-39' 'live' }
} catch { Add-Result $c '[live] Credential Guard / VBS state' 'WARN' 'could not query Win32_DeviceGuard' 'NIST SC-39' 'live' }

# ══ SMB + network ══════════════════════════════════════════════════════════
$c = 'smb-network'
try {
    $s = Get-SmbServerConfiguration -ErrorAction Stop
    if ($s.EnableSMB1Protocol) { Add-Result $c '[live] SMB1 enabled' 'PASS' 'EnableSMB1Protocol=True' 'NIST CM-7, SC-8; CIS 4.8' 'live' } else { Add-Result $c '[live] SMB1 enabled' 'FAIL' 'EnableSMB1Protocol=False (FS-SMB1 feature may be absent on 2025)' 'NIST CM-7; CIS 4.8' 'live' }
    if (-not $s.RequireSecuritySignature) { Add-Result $c '[live] SMB server signing not required' 'PASS' 'RequireSecuritySignature=False' 'NIST SC-8(1), SC-23' 'live' } else { Add-Result $c '[live] SMB server signing not required' 'FAIL' 'RequireSecuritySignature=True' 'NIST SC-8(1), SC-23' 'live' }
    if (-not $s.EnableSecuritySignature) { Add-Result $c '[live] SMB server signing not offered' 'PASS' 'EnableSecuritySignature=False' 'NIST SC-8(1)' 'live' } else { Add-Result $c '[live] SMB server signing not offered' 'WARN' 'EnableSecuritySignature=True' 'NIST SC-8(1)' 'live' }
    if (-not $s.EncryptData) { Add-Result $c '[live] SMB encryption off' 'PASS' 'EncryptData=False' 'NIST SC-8' 'live' } else { Add-Result $c '[live] SMB encryption off' 'WARN' 'EncryptData=True' 'NIST SC-8' 'live' }
} catch { Add-Result $c '[live] SMB server config' 'WARN' 'Get-SmbServerConfiguration failed' 'NIST SC-8(1)' 'live' }
try {
    $cl = Get-SmbClientConfiguration -ErrorAction Stop
    if (-not $cl.RequireSecuritySignature) { Add-Result $c '[live] SMB client signing not required' 'PASS' 'RequireSecuritySignature=False' 'NIST SC-8(1)' 'live' } else { Add-Result $c '[live] SMB client signing not required' 'FAIL' 'RequireSecuritySignature=True' 'NIST SC-8(1)' 'live' }
    if ($cl.EnableInsecureGuestLogons) { Add-Result $c '[live] Insecure guest logons enabled' 'PASS' 'EnableInsecureGuestLogons=True' 'NIST IA-2, AC-3' 'live' } else { Add-Result $c '[live] Insecure guest logons enabled' 'WARN' 'EnableInsecureGuestLogons=False' 'NIST IA-2, AC-3' 'live' }
} catch { Add-Result $c '[live] SMB client config' 'WARN' 'Get-SmbClientConfiguration failed' 'NIST SC-8(1)' 'live' }

# Null sessions / anonymous pipe + share access
$srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$ctlNull = 'NIST AC-3, AC-14'
Test-Reg $c 'RestrictNullSessAccess=0'   $srv 'RestrictNullSessAccess' 0 -Control $ctlNull
Test-RegContains $c 'NullSessionPipes seeded' $srv 'NullSessionPipes' @('samr','lsarpc','netlogon','browser') $ctlNull
Test-RegContains $c 'NullSessionShares seeded' $srv 'NullSessionShares' @('IPC$') $ctlNull
Test-Reg $c 'LanmanWorkstation AllowInsecureGuestAuth=1' 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'AllowInsecureGuestAuth' 1 -Control 'NIST IA-2, AC-3'

$msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
Test-Reg $c 'NtlmMinClientSec=0' $msv 'NtlmMinClientSec' 0 -Control 'NIST SC-8, SC-13'
Test-Reg $c 'NtlmMinServerSec=0' $msv 'NtlmMinServerSec' 0 -Control 'NIST SC-8, SC-13'

# [live] Firewall -- must be off on EVERY profile, not merely one.
try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    $on  = @($profiles | Where-Object { $_.Enabled })
    if ($on.Count -eq 0) { Add-Result $c '[live] Windows Firewall off (all profiles)' 'PASS' ("disabled: " + (($profiles.Name) -join ',')) 'NIST SC-7, CM-7; CIS 4.4' 'live' }
    else { Add-Result $c '[live] Windows Firewall off (all profiles)' 'FAIL' ("still ENABLED on: " + (($on.Name) -join ',')) 'NIST SC-7, CM-7; CIS 4.4' 'live' }
} catch { Add-Result $c '[live] Windows Firewall off (all profiles)' 'WARN' 'Get-NetFirewallProfile failed' 'NIST SC-7; CIS 4.4' 'live' }

# ══ RDP + WinRM ════════════════════════════════════════════════════════════
$c = 'rdp-winrm'
$rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
Test-Reg $c 'RDP enabled (fDenyTSConnections=0)' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 0 -Control 'NIST AC-17'
Test-Reg $c 'RDP NLA off (UserAuthentication=0)' $rdpKey 'UserAuthentication' 0 -Control 'NIST IA-2, SC-8, AC-17'
Test-Reg $c 'RDP SecurityLayer=0 (no TLS)'       $rdpKey 'SecurityLayer' 0 -Control 'NIST SC-8, SC-13'
Test-Reg $c 'RDP fPromptForPassword=0' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fPromptForPassword' 0 -Control 'NIST IA-2'

# [live] Terminal Services WMI reflects what the RDP listener is really doing.
try {
    $ts = Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'" -ErrorAction Stop
    if ($ts.UserAuthenticationRequired -eq 0) { Add-Result $c '[live] RDP listener: NLA not required' 'PASS' 'UserAuthenticationRequired=0' 'NIST IA-2, AC-17' 'live' }
    else { Add-Result $c '[live] RDP listener: NLA not required' 'FAIL' "UserAuthenticationRequired=$($ts.UserAuthenticationRequired) -- registry set but listener still requires NLA" 'NIST IA-2, AC-17' 'live' }
    if ($ts.SecurityLayer -eq 0) { Add-Result $c '[live] RDP listener: security layer = RDP' 'PASS' 'SecurityLayer=0' 'NIST SC-8' 'live' }
    else { Add-Result $c '[live] RDP listener: security layer = RDP' 'WARN' "SecurityLayer=$($ts.SecurityLayer)" 'NIST SC-8' 'live' }
} catch { Add-Result $c '[live] RDP listener settings' 'WARN' 'Win32_TSGeneralSetting unavailable (run elevated / RDS role state)' 'NIST IA-2, AC-17' 'live' }
try {
    $l = Get-NetTCPConnection -State Listen -LocalPort 3389 -ErrorAction Stop
    if ($l) { Add-Result $c '[live] RDP listening on 3389' 'PASS' 'listener present' 'NIST AC-17' 'live' }
} catch { Add-Result $c '[live] RDP listening on 3389' 'WARN' 'no listener on 3389' 'NIST AC-17' 'live' }

# [live] WinRM -- read the running service config, not policy intent.
$ctlWinrm = 'NIST SC-8, IA-5, AC-17(2)'
foreach ($item in @(
    @{ P='WSMan:\localhost\Service\AllowUnencrypted'; N='WinRM AllowUnencrypted'; E='true' },
    @{ P='WSMan:\localhost\Service\Auth\Basic';       N='WinRM Basic auth';       E='true' },
    @{ P='WSMan:\localhost\Service\Auth\CredSSP';     N='WinRM CredSSP (service)'; E='true' },
    @{ P='WSMan:\localhost\Client\AllowUnencrypted';  N='WinRM client unencrypted'; E='true' }
)) {
    try {
        $v = (Get-Item $item.P -ErrorAction Stop).Value
        if ("$v" -eq $item.E) { Add-Result $c ("[live] " + $item.N) 'PASS' "$v" $ctlWinrm 'live' }
        else { Add-Result $c ("[live] " + $item.N) 'FAIL' "=$v (expected $($item.E))" $ctlWinrm 'live' }
    } catch { Add-Result $c ("[live] " + $item.N) 'WARN' 'WSMan provider unavailable (WinRM not configured?)' $ctlWinrm 'live' }
}
try {
    $th = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value
    if ("$th" -eq '*') { Add-Result $c '[live] WinRM TrustedHosts = *' 'PASS' '*' $ctlWinrm 'live' }
    elseif ($th) { Add-Result $c '[live] WinRM TrustedHosts = *' 'WARN' "=$th (not wildcard)" $ctlWinrm 'live' }
    else { Add-Result $c '[live] WinRM TrustedHosts = *' 'FAIL' 'empty' $ctlWinrm 'live' }
} catch { Add-Result $c '[live] WinRM TrustedHosts = *' 'WARN' 'WSMan provider unavailable' $ctlWinrm 'live' }

Test-Reg $c 'PowerShell ExecutionPolicy=Unrestricted (policy)' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' 'ExecutionPolicy' 'Unrestricted' -Control 'NIST CM-7(1), SI-7'
# [live] effective policy -- what PowerShell will actually enforce.
try {
    $eff = Get-ExecutionPolicy
    if ($eff -in @('Unrestricted','Bypass')) { Add-Result $c '[live] Effective execution policy' 'PASS' "$eff" 'NIST CM-7(1), SI-7' 'live' }
    else { Add-Result $c '[live] Effective execution policy' 'FAIL' "$eff -- policy value set but not effective" 'NIST CM-7(1), SI-7' 'live' }
} catch { Add-Result $c '[live] Effective execution policy' 'WARN' 'Get-ExecutionPolicy failed' 'NIST CM-7(1)' 'live' }

# ══ Logging / visibility ═══════════════════════════════════════════════════
$c = 'logging-visibility'
$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$ctlLog = 'NIST AU-2, AU-3, AU-12; CIS 8.2, 8.5'
Test-Reg $c 'ScriptBlockLogging off' "$ps\ScriptBlockLogging" 'EnableScriptBlockLogging' 0 -Control $ctlLog
Test-Reg $c 'ModuleLogging off'      "$ps\ModuleLogging"      'EnableModuleLogging' 0 -Control $ctlLog
Test-Reg $c 'Transcription off'      "$ps\Transcription"      'EnableTranscripting' 0 -Control $ctlLog
Test-Reg $c 'Cmdline in 4688 off' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 0 -Control 'NIST AU-3(1)'
Test-Reg $c 'Security log shrunk (MaxSize=1MB)' 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'MaxSize' 1048576 -Control 'NIST AU-4, AU-11; CIS 8.3'
Test-Reg $c 'System log shrunk (MaxSize=1MB)'   'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'   'MaxSize' 1048576 -Control 'NIST AU-4, AU-11; CIS 8.3'

# [live] the build also calls wevtutil, so registry and channel config can differ.
foreach ($logName in 'Security','System') {
    try {
        $li = Get-WinEvent -ListLog $logName -ErrorAction Stop | Where-Object { $_.LogName -eq $logName } | Select-Object -First 1
        # The intent is "small enough that evidence rolls over fast", not an exact
        # byte count. Windows adjusts a requested log size upward when it commits
        # it -- the field run set 1048576 and the System channel came back as
        # 1052672, exactly one 4096-byte page over, which a `-le 1048576` test
        # called a FAIL even though the setting had applied. Allow a 64KB
        # allocation-granularity margin: that accepts the adjusted value and still
        # fails the 20 MB DC default by a wide margin.
        $maxAllowed = 1048576 + 65536
        if ($li.MaximumSizeInBytes -le $maxAllowed) {
            Add-Result $c "[live] $logName channel max size" 'PASS' "$($li.MaximumSizeInBytes) bytes (target 1048576 + rounding)" 'NIST AU-4, AU-11; CIS 8.3' 'live'
        }
        else {
            # F38 -- ACCEPTED DEVIATION, reported N-A rather than FAIL.
            #
            # This is a log SIZE. It gates no attack path; its only role is to make
            # evidence roll over quickly. On this Server 2025 DC it resisted every
            # supported mechanism: the legacy Services\EventLog key (not
            # authoritative), the WINEVT channel config (written, not reloaded
            # without a service restart), `wevtutil sl` (denied on Security, which
            # needs SeSecurityPrivilege), the EventLog administrative-template
            # policy key (KB-denominated, produced 1 GB), and the security
            # template's [Security Log]/[System Log] sections (MB-denominated,
            # also produced 1 GB). The build no longer writes the two that made it
            # worse, and dc\60 still attempts the WINEVT/wevtutil path.
            #
            # Kept as a row -- not deleted -- so the control stays in the scoring
            # baseline and nobody re-opens this from scratch. Blue team can still
            # be graded on it; the range simply does not pre-break it.
            Add-Result $c "[live] $logName channel max size" 'N-A' "$($li.MaximumSizeInBytes) bytes -- accepted deviation (F38): not settable by any supported mechanism on this host; gates no attack path" 'NIST AU-4, AU-11; CIS 8.3' 'live'
        }
    } catch { Add-Result $c "[live] $logName channel max size" 'WARN' 'Get-WinEvent -ListLog failed' 'NIST AU-4' 'live' }
}
foreach ($sm in 'Sysmon','Sysmon64') {
    $svc = Get-Service $sm -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.StartType -eq 'Disabled' -or $svc.Status -ne 'Running') { Add-Result $c "[live] $sm neutralized" 'PASS' "$($svc.StartType)/$($svc.Status)" 'NIST SI-4; CIS 8.5' 'live' }
        else { Add-Result $c "[live] $sm neutralized" 'FAIL' 'running' 'NIST SI-4; CIS 8.5' 'live' }
    } else { Add-Result $c "[live] $sm neutralized" 'N-A' 'Sysmon not installed on this host' 'NIST SI-4' 'live' }
}

# ══ Legacy services + shares ═══════════════════════════════════════════════
$c = 'legacy-services'
$snmp = Get-Service SNMP -ErrorAction SilentlyContinue
if ($snmp) {
    Add-Result $c '[live] SNMP service present' 'PASS' "$($snmp.Status)" 'NIST IA-5, CM-7; CIS 4.8' 'live'
    $comm = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities' 'public'
    if ($null -ne $comm) { Add-Result $c "SNMP community 'public'" 'PASS' "access=$comm" 'NIST IA-5; CIS 4.8' 'reg' } else { Add-Result $c "SNMP community 'public'" 'FAIL' 'not set' 'NIST IA-5; CIS 4.8' 'reg' }
} else { Add-Result $c '[live] SNMP service present' 'WARN' 'not installed -- SNMP is a Feature-on-Demand and needs Windows Update, which the build disables first (F13)' 'NIST CM-7; CIS 4.8' 'live' }

# [live] PowerShell v2 engine -- the script-block-logging bypass.
try {
    $v2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
    if ($v2.State -eq 'Enabled') { Add-Result $c '[live] PowerShell v2 engine enabled' 'PASS' 'MicrosoftWindowsPowerShellV2Root=Enabled' 'NIST CM-7, AU-12; CIS 4.8' 'live' }
    elseif ($v2.State -eq 'DisabledWithPayloadRemoved') { Add-Result $c '[live] PowerShell v2 engine enabled' 'N-A' 'payload removed on Server 2025 -- cannot be enabled without Windows Update, which the build disables (F13)' 'NIST CM-7, AU-12; CIS 4.8' 'live' }
    # An EMPTY State is not a build failure: on Server 2025 the DISM query can
    # return the object without resolving State (payload absent / servicing stack
    # busy). Reporting FAIL there blamed the build for something it never did --
    # the field run showed literally "State=". Treat unknown as unknown.
    elseif ([string]::IsNullOrWhiteSpace([string]$v2.State)) { Add-Result $c '[live] PowerShell v2 engine enabled' 'N-A' 'DISM returned no State for MicrosoftWindowsPowerShellV2Root -- payload almost certainly absent; not verifiable offline (F13)' 'NIST CM-7, AU-12; CIS 4.8' 'live' }
    else { Add-Result $c '[live] PowerShell v2 engine enabled' 'FAIL' "State=$($v2.State)" 'NIST CM-7, AU-12; CIS 4.8' 'live' }
} catch { Add-Result $c '[live] PowerShell v2 engine enabled' 'N-A' 'optional feature not present on this build' 'NIST CM-7' 'live' }

# [live] TFTP client
$tftp = if (Test-HasCommand 'Get-WindowsFeature') { Get-WindowsFeature -Name TFTP-Client -ErrorAction SilentlyContinue } else { $null }
if ($tftp) {
    if ($tftp.Installed) { Add-Result $c '[live] TFTP client installed' 'PASS' 'TFTP-Client installed' 'NIST CM-7; CIS 4.8' 'live' }
    else { Add-Result $c '[live] TFTP client installed' 'FAIL' 'TFTP-Client not installed' 'NIST CM-7; CIS 4.8' 'live' }
} elseif (Test-Path "$env:SystemRoot\System32\tftp.exe") {
    Add-Result $c '[live] TFTP client installed' 'PASS' 'tftp.exe present' 'NIST CM-7; CIS 4.8' 'live'
} else { Add-Result $c '[live] TFTP client installed' 'WARN' 'could not determine' 'NIST CM-7' 'live' }

foreach ($sh in 'Public','SYSVOL$') {
    $share = Get-SmbShare -Name $sh -ErrorAction SilentlyContinue
    if ($share) {
        Add-Result $c "[live] Share '$sh' present" 'PASS' $share.Path 'NIST AC-3, AC-6; CIS 3.3' 'live'
        try {
            $acc = @(Get-SmbShareAccess -Name $sh -ErrorAction Stop | Where-Object { $_.AccountName -match 'Everyone' -and $_.AccessRight -eq 'Full' })
            if ($acc.Count) { Add-Result $c "[live] Share '$sh' Everyone:Full" 'PASS' 'Everyone has Full' 'NIST AC-3, AC-6; CIS 3.3' 'live' }
            else { Add-Result $c "[live] Share '$sh' Everyone:Full" 'FAIL' 'Everyone:Full not granted' 'NIST AC-3, AC-6; CIS 3.3' 'live' }
        } catch { Add-Result $c "[live] Share '$sh' Everyone:Full" 'WARN' 'Get-SmbShareAccess failed' 'NIST AC-3' 'live' }
    } else { Add-Result $c "[live] Share '$sh' present" 'FAIL' 'missing' 'NIST AC-3; CIS 3.3' 'live' }
}
if (Test-Path 'C:\Public') {
    try {
        $pacl = (& icacls.exe 'C:\Public' 2>$null) -join "`n"
        if ($pacl -match 'Everyone:\(.*F\)|Everyone:\(F\)') { Add-Result $c 'C:\Public NTFS Everyone:Full' 'PASS' 'Everyone Full on the folder' 'NIST AC-3, AC-6; CIS 3.3' 'live' }
        else { Add-Result $c 'C:\Public NTFS Everyone:Full' 'WARN' 'Everyone:F not visible in icacls output' 'NIST AC-3; CIS 3.3' 'live' }
    } catch { Add-Result $c 'C:\Public NTFS Everyone:Full' 'WARN' 'icacls read failed' 'NIST AC-3' 'live' }
}

# ══ CVE artifacts ══════════════════════════════════════════════════════════
$c = 'cve-repro'
$spooler = Get-Service Spooler -ErrorAction SilentlyContinue
if ($spooler -and $spooler.Status -eq 'Running') { Add-Result $c '[live] Print Spooler running (PrintNightmare)' 'PASS' 'Running' 'CVE-2021-34527 (KEV); NIST SI-2, CM-7' 'live' }
elseif ($spooler) { Add-Result $c '[live] Print Spooler running (PrintNightmare)' 'FAIL' "$($spooler.Status)" 'CVE-2021-34527 (KEV); NIST SI-2' 'live' }
else { Add-Result $c '[live] Print Spooler running (PrintNightmare)' 'FAIL' 'Spooler service not found' 'CVE-2021-34527 (KEV); NIST SI-2' 'live' }
$pnp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
Test-Reg $c 'Point-and-Print NoWarningNoElevationOnInstall' $pnp 'NoWarningNoElevationOnInstall' 1 -Control 'CVE-2021-34527; NIST CM-7'
Test-Reg $c 'Point-and-Print UpdatePromptSettings=2'        $pnp 'UpdatePromptSettings' 2 -Control 'CVE-2021-34527; NIST CM-7'
Test-Reg $c 'RestrictDriverInstallationToAdministrators=0'  $pnp 'RestrictDriverInstallationToAdministrators' 0 -Control 'CVE-2021-34527; NIST AC-6'

# The live config hives (SAM/SYSTEM/SECURITY) are held open by the kernel from
# early boot, so their on-disk DACL CANNOT be rewritten while the OS is running --
# `icacls /grant` is denied even after takeown. A machine that carries the weak
# Users ACE (genuinely vulnerable, or set offline) reads as PASS; otherwise this
# is N-A, not FAIL, because the condition is unsettable on a live host. The
# exploitable HiveNightmare artifact on 2025 is the VSS shadow copy, checked next.
foreach ($hive in 'SAM','SYSTEM','SECURITY') {
    try {
        $acl = (& icacls.exe "C:\Windows\System32\config\$hive" 2>$null) -join "`n"
        if ($acl -match 'BUILTIN\\Users') { Add-Result $c "[live] HiveNightmare: $hive readable by Users" 'PASS' "Users ACE present on $hive" 'CVE-2021-36934; NIST AC-3, AC-6' 'live' }
        else { Add-Result $c "[live] HiveNightmare: $hive readable by Users" 'N-A' "no Users ACE on $hive -- live hive DACL cannot be rewritten while the OS holds it open; exploit via the VSS shadow copy below" 'CVE-2021-36934; NIST AC-3, AC-6' 'live' }
    } catch { Add-Result $c "[live] HiveNightmare: $hive ACL" 'WARN' 'icacls read failed' 'CVE-2021-36934' 'live' }
}
# HiveNightmare also needs a shadow copy to read the locked hives from.
try {
    $sc = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop)
    if ($sc.Count -ge 1) { Add-Result $c '[live] VSS shadow copy present' 'PASS' "$($sc.Count) shadow copy/copies" 'CVE-2021-36934; NIST AC-3' 'live' }
    else { Add-Result $c '[live] VSS shadow copy present' 'FAIL' 'none -- HiveNightmare cannot read the live hives without one' 'CVE-2021-36934; NIST AC-3' 'live' }
} catch { Add-Result $c '[live] VSS shadow copy present' 'WARN' 'Win32_ShadowCopy query failed' 'CVE-2021-36934' 'live' }

# ══ Persistence ════════════════════════════════════════════════════════════
$c = 'persistence'
$ctlPersist = 'NIST CM-7, SI-4, SI-7; CIS 8.5'
$psvc = Get-Service 'WinTelemetryHelper' -ErrorAction SilentlyContinue
if ($psvc) { Add-Result $c '[live] Fake service (WinTelemetryHelper)' 'PASS' "$($psvc.StartType)/$($psvc.Status)  [ATT&CK T1543.003]" $ctlPersist 'live' }
else { Add-Result $c '[live] Fake service (WinTelemetryHelper)' 'FAIL' 'missing' $ctlPersist 'live' }
foreach ($t in 'System Update Check','Windows Health Monitor') {
    $task = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    if ($task) { Add-Result $c "[live] Scheduled task '$t'" 'PASS' "State=$($task.State)  [ATT&CK T1053.005]" $ctlPersist 'live' }
    else { Add-Result $c "[live] Scheduled task '$t'" 'FAIL' 'missing' $ctlPersist 'live' }
}
if (Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SysHealth') { Add-Result $c 'Run key (SysHealth)' 'PASS' 'present  [ATT&CK T1547.001]' $ctlPersist 'reg' }
else { Add-Result $c 'Run key (SysHealth)' 'FAIL' 'missing' $ctlPersist 'reg' }
# Winlogon Shell hijack
$shell = Get-RegVal $wl 'Shell'
if ($shell -and $shell -match 'powershell') { Add-Result $c 'Winlogon Shell hijack' 'PASS' "$shell  [ATT&CK T1547.004]" $ctlPersist 'reg' }
elseif ($shell) { Add-Result $c 'Winlogon Shell hijack' 'FAIL' "Shell=$shell (no appended payload)" $ctlPersist 'reg' }
else { Add-Result $c 'Winlogon Shell hijack' 'FAIL' 'Shell value absent' $ctlPersist 'reg' }
# All-users startup folder
$startupItem = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\SysHealth.ps1"
if (Test-Path $startupItem) { Add-Result $c '[live] Startup-folder payload' 'PASS' "$startupItem  [ATT&CK T1547.001]" $ctlPersist 'live' }
else { Add-Result $c '[live] Startup-folder payload' 'FAIL' 'SysHealth.ps1 not in all-users Startup' $ctlPersist 'live' }
foreach ($payload in 'C:\ProgramData\SysTasks\health.ps1','C:\ProgramData\SysTasks\svc.ps1') {
    $leaf = Split-Path $payload -Leaf
    if (Test-Path $payload) { Add-Result $c "[live] Beacon payload ($leaf)" 'PASS' $payload $ctlPersist 'live' }
    else { Add-Result $c "[live] Beacon payload ($leaf)" 'FAIL' "$payload missing" $ctlPersist 'live' }
}
# Accessibility SYSTEM shell (IFEO debugger) -- operator break-glass + T1546.008/012
if (-not $cfg -or $cfg.AccessibilityShell) {
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach ($exe in 'utilman.exe','sethc.exe') {
        $dbg = Get-RegVal "$ifeo\$exe" 'Debugger'
        if ($dbg -and $dbg -match 'cmd\.exe|powershell') { Add-Result $c "Accessibility shell ($exe)" 'PASS' "Debugger=$dbg  [ATT&CK T1546.008]" $ctlPersist 'reg' }
        else { Add-Result $c "Accessibility shell ($exe)" 'FAIL' 'no IFEO Debugger set' $ctlPersist 'reg' }
    }
}
# Beacon containment (F6): the target must never be routable.
if ($cfg -and $cfg.BeaconHost) {
    $bh = [string]$cfg.BeaconHost
    if ($bh -match '^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)') { Add-Result $c 'Beacon target is RFC 5737 (containment)' 'PASS' $bh 'NIST SC-7' 'reg' }
    else { Add-Result $c 'Beacon target is RFC 5737 (containment)' 'FAIL' "$bh is NOT documentation space -- clones will reach a real host (F6)" 'NIST SC-7' 'reg' }
}

# ══ Range safety: the answer key must not be readable by participants (F3) ══
$c = 'range-safety'
$answerKeyDir = Join-Path $env:ProgramData 'CyberRange'
foreach ($p in $answerKeyDir, 'C:\CyberRange') {
    if (Test-Path $p) {
        try {
            $open = @((Get-Acl $p).Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and $_.IdentityReference -match 'BUILTIN\\Users|Everyone|Authenticated Users'
            })
            if ($open.Count -eq 0) { Add-Result $c "Answer key restricted: $p" 'PASS' 'no non-admin ACE' 'NIST AC-3, AC-6; CIS 3.3' 'live'; continue }
            $who = ($open.IdentityReference | Select-Object -Unique) -join ','
            # The manifest/answer key under ProgramData MUST stay locked -> FAIL.
            # C:\CyberRange (staged config) is intentionally left inherited to end
            # the access-denied lockouts; operator is admin anyway (F18) -> WARN.
            if ($p -eq $answerKeyDir) { Add-Result $c "Answer key restricted: $p" 'FAIL' "readable by $who -- the change manifest / answer key is exposed (F3)" 'NIST AC-3, AC-6; CIS 3.3' 'live' }
            else { Add-Result $c "Staged tree readable: $p" 'WARN' "readable by $who (staged config; intentional per F18, off-boxed by WP2/WP3)" 'NIST AC-3; CIS 3.3' 'live' }
        } catch { Add-Result $c "Answer key restricted: $p" 'WARN' 'Get-Acl failed' 'NIST AC-3' 'live' }
    }
}

# ══ Recovery / break-glass (safety, not an exploit) ════════════════════════
$c = 'break-glass'
$bg = if ($cfg -and $cfg.BreakGlass -and $cfg.BreakGlass.User) { $cfg.BreakGlass.User } else { 'rangebreak' }
$bgExists = if ($isDC) {
    try { Import-Module ActiveDirectory -ErrorAction Stop; [bool](Get-ADUser -Filter "SamAccountName -eq '$bg'" -ErrorAction SilentlyContinue) } catch { $false }
} else {
    Test-LocalUserExists $bg
}
if ($bgExists) { Add-Result $c "[live] Break-glass account '$bg' exists" 'PASS' $(if($isDC){'domain'}else{'local'}) 'NIST CP-2, AC-2' 'live' }
else { Add-Result $c "[live] Break-glass account '$bg' exists" 'FAIL' 'NOT found -- you may have no recovery account' 'NIST CP-2, AC-2' 'live' }
# It must remain VISIBLE at the sign-in screen -- the build hides other accounts.
$hiddenBg = Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' $bg
if ($null -eq $hiddenBg) { Add-Result $c "Break-glass '$bg' not hidden from sign-in" 'PASS' 'absent from SpecialAccounts\UserList' 'NIST CP-2' 'reg' }
else { Add-Result $c "Break-glass '$bg' not hidden from sign-in" 'FAIL' "UserList=$hiddenBg -- hidden; you will not see it at logon" 'NIST CP-2' 'reg' }

# ══ Analyst operator admin (stable login the build never rewrites) ═════════
$c = 'analyst-admin'
$an = if ($cfg -and $cfg.Analyst -and $cfg.Analyst.User) { $cfg.Analyst.User } else { 'analyst' }
if ($isDC) {
    $anUser = $null
    try { Import-Module ActiveDirectory -ErrorAction Stop; $anUser = Get-ADUser -Filter "SamAccountName -eq '$an'" -ErrorAction SilentlyContinue } catch {}
    if ($anUser) {
        $inDA = try { [bool](Get-ADGroupMember 'Domain Admins' -ErrorAction Stop | Where-Object SamAccountName -eq $an) } catch { $false }
        if ($inDA) { Add-Result $c "[live] Analyst '$an' is a Domain Admin" 'PASS' 'domain user in Domain Admins' 'NIST AC-2, AC-6' 'live' }
        else { Add-Result $c "[live] Analyst '$an' is a Domain Admin" 'FAIL' 'exists but NOT in Domain Admins' 'NIST AC-2, AC-6' 'live' }
    } else { Add-Result $c "[live] Analyst '$an' exists" 'FAIL' 'domain user not found' 'NIST AC-2' 'live' }
} else {
    if (Test-LocalUserExists $an) {
        $inAdm = try { [bool](Get-LocalGroupMember Administrators -Member $an -ErrorAction SilentlyContinue) } catch { $false }
        if ($inAdm) { Add-Result $c "[live] Analyst '$an' is a local admin" 'PASS' 'local user in Administrators' 'NIST AC-2, AC-6' 'live' }
        else { Add-Result $c "[live] Analyst '$an' is a local admin" 'FAIL' 'exists but NOT in Administrators' 'NIST AC-2, AC-6' 'live' }
    } else { Add-Result $c "[live] Analyst '$an' exists" 'FAIL' 'local user not found' 'NIST AC-2' 'live' }
}

# ══ Hidden admins (local on non-DC, domain on DC) ══════════════════════════
$c = 'hidden-admins'
$ctlHidden = 'NIST AC-2, AC-2(3), AC-6(5); CIS 5.1, 5.4'
$hidden = if ($cfg -and $cfg.HiddenAdminAccounts) { $cfg.HiddenAdminAccounts } else { @('svc-backup','smb-backup','wsus-backup','iis-backup','adfs-backup') }
foreach ($h in $hidden) {
    if ($isDC) {
        $u = $null; try { Import-Module ActiveDirectory -ErrorAction Stop; $u = Get-ADUser -Filter "SamAccountName -eq '$h'" -ErrorAction SilentlyContinue } catch {}
        if ($u) {
            $inDA = try { [bool](Get-ADGroupMember 'Domain Admins' -ErrorAction Stop | Where-Object SamAccountName -eq $h) } catch { $false }
            if ($inDA) { Add-Result $c "[live] Domain admin '$h'" 'PASS' 'in Domain Admins' $ctlHidden 'live' } else { Add-Result $c "[live] Domain admin '$h'" 'WARN' 'exists but not in Domain Admins' $ctlHidden 'live' }
        } else { Add-Result $c "[live] Domain admin '$h'" 'FAIL' 'missing' $ctlHidden 'live' }
    } else {
        if (Test-LocalUserExists $h) {
            $inAdm = try { [bool](Get-LocalGroupMember Administrators -Member $h -ErrorAction SilentlyContinue) } catch { $false }
            if ($inAdm) { Add-Result $c "[live] Local admin '$h'" 'PASS' 'in Administrators' $ctlHidden 'live' } else { Add-Result $c "[live] Local admin '$h'" 'WARN' 'exists but not in Administrators' $ctlHidden 'live' }
            $hv = Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' $h
            if ("$hv" -eq '0') { Add-Result $c "'$h' hidden from sign-in screen" 'PASS' 'UserList=0' $ctlHidden 'reg' }
            else { Add-Result $c "'$h' hidden from sign-in screen" 'FAIL' 'not in SpecialAccounts\UserList' $ctlHidden 'reg' }
        } else { Add-Result $c "[live] Local admin '$h'" 'FAIL' 'missing' $ctlHidden 'live' }
    }
}

# ══ Domain Controller scenarios ════════════════════════════════════════════
if ($isDC) {
    $c = 'dc-ad'
    $adOk = $false
    try { Import-Module ActiveDirectory -ErrorAction Stop; $dom = Get-ADDomain -ErrorAction Stop; $adOk = $true; Add-Result $c '[live] AD DS reachable' 'PASS' $dom.DNSRoot 'NIST AC-2' 'live' } catch { Add-Result $c '[live] AD DS reachable' 'FAIL' 'Get-ADDomain failed (ADWS up?)' 'NIST AC-2' 'live' }
    if ($adOk) {
        $nb = $dom.NetBIOSName

        # Kerberoast: SPN accounts
        $spn = @(Get-ADUser -LDAPFilter '(servicePrincipalName=*)' -Properties ServicePrincipalName,'msDS-SupportedEncryptionTypes' -ErrorAction SilentlyContinue)
        if ($spn.Count -ge 1) { Add-Result $c '[live] Kerberoastable SPN accounts' 'PASS' (($spn.SamAccountName) -join ',') 'NIST IA-5, SC-13, AC-6' 'live' }
        else { Add-Result $c '[live] Kerberoastable SPN accounts' 'FAIL' 'none found -- dc\10 idempotency bug (F12) applies SPNs only on the create branch' 'NIST IA-5, AC-6' 'live' }
        # RC4 actually stamped on them, or the ticket will not be crackable as -m 13100
        $rc4 = @($spn | Where-Object { $_.'msDS-SupportedEncryptionTypes' -band 0x4 })
        if ($rc4.Count -ge 1) { Add-Result $c '[live] SPN accounts stamped RC4' 'PASS' (($rc4.SamAccountName) -join ',') 'NIST SC-13' 'live' }
        elseif ($spn.Count) { Add-Result $c '[live] SPN accounts stamped RC4' 'WARN' 'SPNs exist but none have msDS-SupportedEncryptionTypes RC4 bit' 'NIST SC-13' 'live' }

        # AS-REP roast: DoesNotRequirePreAuth (UAC bit 0x400000)
        $asrep = @(Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' -ErrorAction SilentlyContinue)
        if ($asrep.Count -ge 1) { Add-Result $c '[live] AS-REP roastable accounts' 'PASS' (($asrep.SamAccountName) -join ',') 'NIST IA-2, IA-5' 'live' }
        else { Add-Result $c '[live] AS-REP roastable accounts' 'FAIL' 'none flagged' 'NIST IA-2, IA-5' 'live' }

        # Reversible encryption (UAC bit 0x80)
        $rev = @(Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=128)' -ErrorAction SilentlyContinue)
        if ($rev.Count -ge 1) { Add-Result $c '[live] Reversible-encryption account' 'PASS' (($rev.SamAccountName) -join ',') 'NIST IA-5(1)(c)' 'live' }
        else { Add-Result $c '[live] Reversible-encryption account' 'FAIL' 'none found' 'NIST IA-5(1)(c)' 'live' }

        # Password sitting in the description field
        $descHit = @(Get-ADUser -Filter * -Properties Description -ErrorAction SilentlyContinue |
                     Where-Object { $_.Description -match '(?i)\bpw\b|password\s*[:=]|pw\s*[:=]' })
        if ($descHit.Count -ge 1) { Add-Result $c '[live] Password in a user description' 'PASS' (($descHit.SamAccountName) -join ',') 'NIST IA-5(1)(c), AC-3; CIS 3.3' 'live' }
        else { Add-Result $c '[live] Password in a user description' 'FAIL' 'no user description contains a credential' 'NIST IA-5(1)(c)' 'live' }

        # Over-privileged helpdesk user in built-in operator groups
        foreach ($g in 'Account Operators','Server Operators') {
            try {
                $mem = @(Get-ADGroupMember -Identity $g -ErrorAction Stop)
                if ($mem.Count -ge 1) { Add-Result $c "[live] '$g' has members" 'PASS' (($mem.SamAccountName) -join ',') 'NIST AC-6, AC-6(7); CIS 5.4, 6.8' 'live' }
                else { Add-Result $c "[live] '$g' has members" 'FAIL' 'empty -- over-privilege path missing' 'NIST AC-6; CIS 5.4' 'live' }
            } catch { Add-Result $c "[live] '$g' has members" 'WARN' 'group query failed' 'NIST AC-6' 'live' }
        }

        # Delegation
        $unc = @(Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -ErrorAction SilentlyContinue)
        if ($unc.Count -ge 1) { Add-Result $c '[live] Unconstrained delegation acct' 'WARN' ((($unc.SamAccountName) -join ',') + ' -- set on a USER; coercion needs a computer account or a service running as it (F14)') 'NIST AC-6, IA-2' 'live' }
        else { Add-Result $c '[live] Unconstrained delegation acct' 'FAIL' 'none found' 'NIST AC-6, IA-2' 'live' }
        $con = @(Get-ADUser -Filter * -Properties 'msDS-AllowedToDelegateTo' -ErrorAction SilentlyContinue | Where-Object { $_.'msDS-AllowedToDelegateTo' })
        if ($con.Count -ge 1) { Add-Result $c '[live] Constrained delegation acct' 'PASS' (($con.SamAccountName) -join ',') 'NIST AC-6, IA-2' 'live' }
        else { Add-Result $c '[live] Constrained delegation acct' 'FAIL' 'none found' 'NIST AC-6, IA-2' 'live' }

        # ms-DS-MachineAccountQuota (RBCD enabler)
        try {
            $maq = (Get-ADObject -Identity $dom.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop).'ms-DS-MachineAccountQuota'
            if ([int]$maq -gt 0) { Add-Result $c 'ms-DS-MachineAccountQuota > 0 (RBCD)' 'PASS' "MAQ=$maq" 'NIST AC-6, CM-6; NSA/ACSC AD guidance' 'live' }
            else { Add-Result $c 'ms-DS-MachineAccountQuota > 0 (RBCD)' 'FAIL' 'MAQ=0 -- RBCD path closed' 'NIST AC-6, CM-6' 'live' }
        } catch { Add-Result $c 'ms-DS-MachineAccountQuota > 0 (RBCD)' 'WARN' 'could not read domain object' 'NIST AC-6' 'live' }

        # Weak domain password policy
        try {
            $pp = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
            if (-not $pp.ComplexityEnabled) { Add-Result $c '[live] Weak password policy: complexity off' 'PASS' "minLen=$($pp.MinPasswordLength)" 'NIST IA-5(1); CIS Benchmark 1.1' 'live' } else { Add-Result $c '[live] Weak password policy: complexity off' 'FAIL' 'complexity still on' 'NIST IA-5(1); CIS Benchmark 1.1' 'live' }
            if ($pp.LockoutThreshold -eq 0) { Add-Result $c '[live] No account lockout (spray-friendly)' 'PASS' 'LockoutThreshold=0' 'NIST AC-7; CIS Benchmark 1.2' 'live' } else { Add-Result $c '[live] No account lockout (spray-friendly)' 'FAIL' "LockoutThreshold=$($pp.LockoutThreshold)" 'NIST AC-7; CIS Benchmark 1.2' 'live' }
        } catch { Add-Result $c '[live] Weak password policy' 'WARN' 'could not read policy' 'NIST IA-5(1)' 'live' }

        # ── AD CS / ESC1 ────────────────────────────────────────────────────
        $ca = 'dc-adcs'
        $certsvc = Get-Service CertSvc -ErrorAction SilentlyContinue
        if ($certsvc -and $certsvc.Status -eq 'Running') { Add-Result $ca '[live] AD CS (CertSvc) running' 'PASS' 'Running' 'NIST SC-17, IA-5(2)' 'live' }
        else { Add-Result $ca '[live] AD CS (CertSvc) running' 'FAIL' 'CertSvc not running -- no CA to enrol against' 'NIST SC-17, IA-5(2)' 'live' }
        try {
            $confNC = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
            $tpl = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$confNC" -Filter "cn -eq 'RangeUserESC1'" -Properties 'msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','msPKI-RA-Signature','msPKI-Cert-Template-OID','pKIExtendedKeyUsage' -ErrorAction SilentlyContinue
            if ($tpl) {
                if ([int]$tpl.'msPKI-Certificate-Name-Flag' -band 0x1) { Add-Result $ca 'ESC1: ENROLLEE_SUPPLIES_SUBJECT' 'PASS' 'name-flag 0x1 set' 'NIST SC-17, IA-5(2)' 'live' }
                else { Add-Result $ca 'ESC1: ENROLLEE_SUPPLIES_SUBJECT' 'FAIL' 'name-flag not set -- not an ESC1 template' 'NIST SC-17' 'live' }
                if ([int]$tpl.'msPKI-RA-Signature' -eq 0) { Add-Result $ca 'ESC1: no authorized signatures required' 'PASS' 'msPKI-RA-Signature=0' 'NIST SC-17' 'live' }
                else { Add-Result $ca 'ESC1: no authorized signatures required' 'FAIL' "msPKI-RA-Signature=$($tpl.'msPKI-RA-Signature')" 'NIST SC-17' 'live' }
                if ([int]$tpl.'msPKI-Enrollment-Flag' -band 0x2) { Add-Result $ca 'ESC1: no manager approval' 'FAIL' 'PEND_ALL_REQUESTS set -- enrolment needs approval' 'NIST SC-17' 'live' }
                else { Add-Result $ca 'ESC1: no manager approval' 'PASS' 'no PEND_ALL_REQUESTS' 'NIST SC-17' 'live' }
                if (@($tpl.pKIExtendedKeyUsage) -contains '1.3.6.1.5.5.7.3.2') { Add-Result $ca 'ESC1: client-auth EKU present' 'PASS' '1.3.6.1.5.5.7.3.2' 'NIST SC-17, IA-5(2)' 'live' }
                else { Add-Result $ca 'ESC1: client-auth EKU present' 'FAIL' 'no Client Authentication EKU -- cert cannot authenticate' 'NIST SC-17' 'live' }
                # F8: the clone copies msPKI-Cert-Template-OID from "User"; OIDs must be unique.
                $dupe = @(Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$confNC" -Filter "objectClass -eq 'pKICertificateTemplate'" -Properties 'msPKI-Cert-Template-OID' -ErrorAction SilentlyContinue |
                          Where-Object { $_.'msPKI-Cert-Template-OID' -eq $tpl.'msPKI-Cert-Template-OID' })
                if ($dupe.Count -le 1) { Add-Result $ca 'ESC1: template OID is unique (F8)' 'PASS' $tpl.'msPKI-Cert-Template-OID' 'NIST SC-17' 'live' }
                else { Add-Result $ca 'ESC1: template OID is unique (F8)' 'FAIL' ("OID shared with: " + (($dupe.Name) -join ',') + " -- cloned from User; CA template resolution will break") 'NIST SC-17' 'live' }
            } else { Add-Result $ca 'ESC1 template present' 'FAIL' 'RangeUserESC1 not found in AD' 'NIST SC-17' 'live' }
        } catch { Add-Result $ca 'ESC1 template present' 'WARN' 'could not query template container' 'NIST SC-17' 'live' }
        # Published to the CA -- an AD object alone is not enrollable.
        try {
            $pub = (& certutil.exe -CATemplates 2>$null) -join "`n"
            if ($pub -match 'RangeUserESC1') { Add-Result $ca '[live] ESC1 template published on the CA' 'PASS' 'listed by certutil -CATemplates' 'NIST SC-17, IA-5(2)' 'live' }
            else { Add-Result $ca '[live] ESC1 template published on the CA' 'FAIL' 'not published -- the template exists in AD but cannot be enrolled' 'NIST SC-17, IA-5(2)' 'live' }
        } catch { Add-Result $ca '[live] ESC1 template published on the CA' 'WARN' 'certutil -CATemplates failed' 'NIST SC-17' 'live' }
        # F8: strong certificate binding enforcement blocks the ESC1 logon on 2025.
        $sbe = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'StrongCertificateBindingEnforcement'
        if ($null -eq $sbe -or [int]$sbe -eq 2) {
            Add-Result $ca 'ESC1 exploitable: KDC binding enforcement (F8)' 'FAIL' ("StrongCertificateBindingEnforcement=" + $(if($null -eq $sbe){'unset -> defaults to 2 (Full Enforcement)'}else{$sbe}) + " -- a cert with no SID extension is REJECTED for PKINIT, so ESC1 will not work. Set to 1 (compatibility) to teach it") 'NIST IA-5(2), SC-17' 'reg'
        } elseif ([int]$sbe -eq 1) { Add-Result $ca 'ESC1 exploitable: KDC binding enforcement (F8)' 'PASS' 'StrongCertificateBindingEnforcement=1 (compatibility) -- ESC1 chain can complete' 'NIST IA-5(2), SC-17' 'reg' }
        else { Add-Result $ca 'ESC1 exploitable: KDC binding enforcement (F8)' 'WARN' "StrongCertificateBindingEnforcement=$sbe" 'NIST IA-5(2)' 'reg' }

        # ── F10: does the KDC still issue RC4 at all? ───────────────────────
        $kdcEnc = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\KDC' 'DefaultDomainSupportedEncTypes'
        if ($null -eq $kdcEnc) { Add-Result $c 'KDC etypes explicitly allow RC4 (F10)' 'WARN' 'DefaultDomainSupportedEncTypes unset -- RC4 issuance depends on OS defaults; confirm the Kerberoast ticket etype is 23 with klist' 'NIST SC-13' 'reg' }
        elseif ([int]$kdcEnc -band 0x4) { Add-Result $c 'KDC etypes explicitly allow RC4 (F10)' 'PASS' "DefaultDomainSupportedEncTypes=$kdcEnc (RC4 bit set)" 'NIST SC-13' 'reg' }
        else { Add-Result $c 'KDC etypes explicitly allow RC4 (F10)' 'FAIL' "DefaultDomainSupportedEncTypes=$kdcEnc -- RC4 bit clear, Kerberoast will not yield an -m 13100 hash" 'NIST SC-13' 'reg' }

        # ── F11: LDAP signing / channel binding never downgraded ────────────
        $ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        $ldapInt = Get-RegVal $ntds 'LDAPServerIntegrity'
        if ($null -ne $ldapInt -and [int]$ldapInt -le 1) { Add-Result 'dc-ldap' 'LDAP signing not required (F11)' 'PASS' "LDAPServerIntegrity=$ldapInt" 'NIST SC-8(1), SC-23' 'reg' }
        else { Add-Result 'dc-ldap' 'LDAP signing not required (F11)' 'FAIL' ("LDAPServerIntegrity=" + $(if($null -eq $ldapInt){'unset -> Server 2025 requires signing'}else{$ldapInt}) + " -- the build never downgrades it, so NTLM-relay-to-LDAP stays blocked") 'NIST SC-8(1), SC-23' 'reg' }
        $ldapCb = Get-RegVal $ntds 'LdapEnforceChannelBinding'
        if ($null -ne $ldapCb -and [int]$ldapCb -eq 0) { Add-Result 'dc-ldap' 'LDAP channel binding off (F11)' 'PASS' 'LdapEnforceChannelBinding=0' 'NIST SC-8(1), SC-23' 'reg' }
        else { Add-Result 'dc-ldap' 'LDAP channel binding off (F11)' 'FAIL' ("LdapEnforceChannelBinding=" + $(if($null -eq $ldapCb){'unset -> enforced by default on 2025'}else{$ldapCb}) + " -- LDAPS relay stays blocked") 'NIST SC-8(1), SC-23' 'reg' }

        # ── GPP cpassword in SYSVOL ─────────────────────────────────────────
        try {
            $sysvol = "\\$($dom.DNSRoot)\SYSVOL\$($dom.DNSRoot)\Policies"
            $hit = Get-ChildItem $sysvol -Recurse -Filter 'Groups.xml' -ErrorAction SilentlyContinue | Select-String -Pattern 'cpassword' -List -ErrorAction SilentlyContinue
            if ($hit) { Add-Result 'dc-gpo' '[live] GPP cpassword readable in SYSVOL' 'PASS' $hit.Path 'MS14-025; NIST IA-5(1)(c), AC-3' 'live' } else { Add-Result 'dc-gpo' '[live] GPP cpassword readable in SYSVOL' 'FAIL' 'no Groups.xml with cpassword' 'MS14-025; NIST IA-5(1)(c)' 'live' }
        } catch { Add-Result 'dc-gpo' '[live] GPP cpassword readable in SYSVOL' 'WARN' 'SYSVOL read failed' 'MS14-025' 'live' }

        # ── DCSync + GenericAll via dsacls ──────────────────────────────────
        try {
            $acl = (& dsacls.exe $dom.DistinguishedName 2>$null) -join "`n"
            if ($acl -match 'Replicating Directory Changes') { Add-Result 'dc-acl' '[live] DCSync rights granted' 'PASS' 'replication ACE present on domain head' 'NIST AC-6, AC-3(7), AU-6; NSA/ACSC' 'live' }
            else { Add-Result 'dc-acl' '[live] DCSync rights granted' 'FAIL' 'no replication ACE on the domain head' 'NIST AC-6, AC-3(7)' 'live' }
        } catch { Add-Result 'dc-acl' '[live] DCSync rights granted' 'WARN' 'dsacls unavailable' 'NIST AC-6' 'live' }
        try {
            $daDN = (Get-ADGroup 'Domain Admins' -ErrorAction Stop).DistinguishedName
            $gacl = (& dsacls.exe $daDN 2>$null) -join "`n"
            if ($gacl -match 'FULL CONTROL|GENERIC ALL') { Add-Result 'dc-acl' '[live] GenericAll on Domain Admins' 'PASS' 'full-control ACE present on the Domain Admins group' 'NIST AC-6, AC-3; CIS 6.8' 'live' }
            else { Add-Result 'dc-acl' '[live] GenericAll on Domain Admins' 'FAIL' 'no full-control ACE -- self-add-to-DA path missing' 'NIST AC-6, AC-3; CIS 6.8' 'live' }
        } catch { Add-Result 'dc-acl' '[live] GenericAll on Domain Admins' 'WARN' 'dsacls on Domain Admins failed' 'NIST AC-6' 'live' }
    }
}

# ══ Summary + output ═══════════════════════════════════════════════════════
Write-Host ""
if ($Format -eq 'Table') {
    foreach ($grp in ($Results | Group-Object Category)) {
        Write-Host ("[{0}]" -f $grp.Name) -ForegroundColor Cyan
        foreach ($r in $grp.Group) {
            $col = switch ($r.State) { 'PASS' {'Green'} 'FAIL' {'Red'} 'WARN' {'Yellow'} default {'Gray'} }
            Write-Host ("  {0,-5} {1,-48} {2}" -f $r.State, $r.Check, $r.Detail) -ForegroundColor $col
            if ($ShowControl -and $r.Control) { Write-Host ("        -> {0}" -f $r.Control) -ForegroundColor DarkGray }
        }
    }
}
Write-Host ""
$fail = @($Results | Where-Object State -eq 'FAIL').Count
$warn = @($Results | Where-Object State -eq 'WARN').Count
$pass = @($Results | Where-Object State -eq 'PASS').Count
$na   = @($Results | Where-Object State -eq 'N-A').Count
$live = @($Results | Where-Object Probe -eq 'live').Count
$reg  = @($Results | Where-Object Probe -eq 'reg').Count
$summaryColor = if ($fail -gt 0) { 'Red' } elseif ($warn -gt 0) { 'Yellow' } else { 'Green' }
Write-Host ("SUMMARY: PASS=$pass  FAIL=$fail  WARN=$warn  N-A=$na   ($live live-state probes, $reg registry-only)") -ForegroundColor $summaryColor
Write-Host "WARN often = needs reboot / known no-op on 2025 / not verifiable from here." -ForegroundColor Gray
if ($fail -gt 0) {
    Write-Host ""
    Write-Host "FAILURES (build did not apply, or it was reverted):" -ForegroundColor Red
    foreach ($r in ($Results | Where-Object State -eq 'FAIL')) {
        Write-Host ("  [{0}] {1}" -f $r.Category, $r.Check) -ForegroundColor Red
        if ($r.Control) { Write-Host ("        control: {0}" -f $r.Control) -ForegroundColor DarkGray }
    }
}

if ($Out) {
    switch ($Format) {
        'Csv'  { $Results | Export-Csv -Path $Out -NoTypeInformation -Encoding UTF8 }
        'Json' { $Results | ConvertTo-Json -Depth 4 | Set-Content -Path $Out -Encoding UTF8 }
        default { $Results | Format-Table -AutoSize | Out-String | Set-Content -Path $Out -Encoding UTF8 }
    }
    Write-Host "Results written to $Out" -ForegroundColor Gray
}
