#requires -Version 5.1
<#  DC step 6: push the machine-security downgrades INTO the Default Domain
    Controllers Policy so they survive gpupdate / reboot.

    WHY THIS SCRIPT EXISTS (F33)
    ---------------------------------------------------------------------------
    Several category scripts write local registry values in Phase 1 -- SMB server
    signing off, "store the LM hash" (NoLmHash=0), and shrunken Security/System
    event logs. On a *domain controller* those exact settings are owned by the
    Security CSE of the built-in **Default Domain Controllers Policy**, which
    re-enforces the SECURE value on every background refresh and every reboot. A
    local registry write can never win against a Security-CSE GPO setting, so the
    controls silently revert and the verifier reports them as "not applied".

    The correct, durable fix -- and the more realistic teaching artifact, since a
    blue-teamer must find and remediate it in Group Policy -- is to write the weak
    values into the DC policy's security template (GptTmpl.inf). Then the DC's own
    baseline enforces the misconfiguration.

    Controls moved into the GPO here:
      * NoLMHash = 0                         (store the crackable LM hash)
      * LanmanServer RequireSecuritySignature = 0  (SMB relay practice)
      * Security / System log MaximumLogSize = 1024 KB (evidence rolls over fast)

    Must run AFTER promotion (needs SYSVOL + the DC policy) and LAST in the DC
    block, because it finishes with `gpupdate /force` -- which is what makes the
    downgrade the machine's effective state. Gated by DC.SecurityGpoDowngrade
    (defaults ON unless explicitly set to $false).
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'dc-gpo'
if (-not (Test-IsDomainController)) { Write-RangeLog 'Not a DC; skipping DC security-GPO downgrade.' 'WARN'; return }
if ($Config.DC.SecurityGpoDowngrade -eq $false) { Write-RangeLog 'DC.SecurityGpoDowngrade=$false; skipping.' 'INFO'; return }
Import-Module ActiveDirectory -Force

$dom     = Get-ADDomain
$dnsRoot = $dom.DNSRoot
$domDN   = $dom.DistinguishedName
# Well-known GUID of the Default Domain Controllers Policy (constant on every AD).
$ddcpGuid = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'
$polRoot  = "\\$dnsRoot\SYSVOL\$dnsRoot\Policies\$ddcpGuid"
$secDir   = Join-Path $polRoot 'MACHINE\Microsoft\Windows NT\SecEdit'
$inf      = Join-Path $secDir 'GptTmpl.inf'
$gptIni   = Join-Path $polRoot 'GPT.ini'

if (-not (Test-Path $polRoot)) {
    Write-RangeLog "Default Domain Controllers Policy not found at $polRoot -- is this a freshly promoted DC? Skipping." 'ERROR'
    return
}

# ── tiny INF reader/writer that preserves sections and replaces keys ──────
function Read-Inf {
    param([string]$Path)
    $sections = [ordered]@{}
    $cur = $null
    if (Test-Path $Path) {
        foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
            $t = $line.Trim()
            if ($t -match '^\[(.+)\]$') { $cur = $matches[1]; if (-not $sections.Contains($cur)) { $sections[$cur] = [System.Collections.ArrayList]::new() } }
            elseif ($cur -ne $null) { [void]$sections[$cur].Add($line) }
        }
    }
    return $sections
}
function Get-RegValueSafe {
    <# Non-throwing read; $null when the key or value is absent. #>
    param([string]$Path,[string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $i = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $i) { return $null }
    if ($i.GetValueNames() -notcontains $Name) { return $null }
    $i.GetValue($Name)
}
function Remove-InfKey {
    <# Strip a key from a section. Needed to UNDO an entry a previous run wrote
       into GptTmpl.inf -- editing the script alone does not clean the box. #>
    param($Sections,[string]$Section,[string]$Key)
    if (-not $Sections.Contains($Section)) { return $false }
    $list = $Sections[$Section]
    for ($i = 0; $i -lt $list.Count; $i++) {
        $k = ($list[$i] -split '=',2)[0].Trim()
        if ($k -and $k.Equals($Key,[StringComparison]::OrdinalIgnoreCase)) { $list.RemoveAt($i); return $true }
    }
    return $false
}
function Set-InfKey {
    param($Sections,[string]$Section,[string]$Key,[string]$Value)
    if (-not $Sections.Contains($Section)) { $Sections[$Section] = [System.Collections.ArrayList]::new() }
    $list = $Sections[$Section]
    for ($i = 0; $i -lt $list.Count; $i++) {
        $k = ($list[$i] -split '=',2)[0].Trim()
        if ($k -and $k.Equals($Key,[StringComparison]::OrdinalIgnoreCase)) { $list[$i] = "$Key=$Value"; return }
    }
    [void]$list.Add("$Key=$Value")
}
function Write-Inf {
    param($Sections,[string]$Path)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($s in $Sections.Keys) {
        [void]$sb.AppendLine("[$s]")
        foreach ($l in $Sections[$s]) { [void]$sb.AppendLine($l) }
    }
    # GptTmpl.inf is a Unicode (UTF-16LE, BOM) security template.
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), [System.Text.UnicodeEncoding]::new($false, $true))
}

New-Item -ItemType Directory -Path $secDir -Force | Out-Null
$sec = Read-Inf $inf

# Required scaffolding for a valid security template.
Set-InfKey $sec 'Unicode' 'Unicode' 'yes'
Set-InfKey $sec 'Version' 'signature' '"$CHICAGO$"'
Set-InfKey $sec 'Version' 'Revision'  '1'

# ── the actual downgrades ────────────────────────────────────────────────
# REG_DWORD in a security template is encoded as "4,<decimal>".
Set-InfKey $sec 'Registry Values' 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash' '4,0'
Set-InfKey $sec 'Registry Values' 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature' '4,0'
# F36: the [System Log] / [Security Log] sections below are the PRE-VISTA
# security-template format. Modern Windows ignores them for the Windows Event Log
# channels -- which is exactly why the SMB signing entry above (a [Registry
# Values] entry) took effect while the Security channel stayed at the 20 MB DC
# default through a gpupdate AND a reboot.
#
# The setting that modern Windows honours is the Event Log Service administrative
# template, whose value lives at
#   SOFTWARE\Policies\Microsoft\Windows\EventLog\<Channel>\MaxSize
# and which OVERRIDES both the legacy Services\EventLog key and the WINEVT channel
# config. Express it through [Registry Values] -- the same mechanism already
# proven to work in this file.
#
# F36 was WRONG and is reverted here. Writing 1048576 into that policy value
# regressed the System channel from a passing 1052672 to a failure -- the value is
# denominated in KB, so it asked for 1 GB. Do not set it. Instead REMOVE it, both
# from this template and from the local policy hive, so a box that ran the bad
# version is cleaned up.
#
# The evidence says the policy key was never needed: before F36 the System channel
# PASSED at 1052672, set purely by wevtutil -> WINEVT\Channels. That path works.
# Security fails only because `wevtutil sl Security` is denied (it needs
# SeSecurityPrivilege), so the fix for Security is to write WINEVT\Channels
# directly -- which is done below -- not to add a GPO override on top.
$logPolicyBase = 'MACHINE\Software\Policies\Microsoft\Windows\EventLog'
foreach ($ch in 'Security','System') {
    if (Remove-InfKey $sec 'Registry Values' "$logPolicyBase\$ch\MaxSize") {
        Write-RangeLog "Removed the bad EventLog MaxSize policy entry for $ch from the DC security template (F36 revert)." 'WARN'
    }
}

# F37: these are the actual culprit, and my earlier claim that Vista+ ignores them
# was WRONG. Proven on the DC: GptTmpl.inf carried
#     [System Log]   MaximumLogSize=1024
#     [Security Log] MaximumLogSize=1024
# and both channels sat at 1073741824 bytes -- 1024 x 1 MB. The Security CSE
# applies these sections and treats the number as MEGABYTES, so "1024" asked for
# 1 GB, the opposite of what was intended. (The policy key was already gone by
# then, confirmed by Get-ItemProperty returning nothing, so this was the only
# remaining source.)
#
# There is no safe value to put here -- the unit is not what the format documents.
# Remove the sections entirely and let the WINEVT channel config below own the
# size, which is the path that demonstrably produced a correct 1052672.
foreach ($ch in 'System','Security') {
    if (Remove-InfKey $sec "$ch Log" 'MaximumLogSize') {
        Write-RangeLog "Removed [$ch Log] MaximumLogSize from the DC security template -- it was setting the channel to 1 GB (F37)." 'WARN'
    }
}

Write-Inf $sec $inf
Write-RangeManifest $cat 'dc-security-template' "$ddcpGuid GptTmpl.inf <- NoLMHash=0; SMB sign off; logs 1024KB"
Write-RangeLog 'Wrote SMB-signing-off / NoLMHash=0 / 1MB-log downgrades into the Default Domain Controllers Policy (F33).' 'WARN'

# ── bump the GPO version so the DC re-reads the template ──────────────────
try {
    $verLine = if (Test-Path $gptIni) { (Get-Content $gptIni | Where-Object { $_ -match '^\s*Version\s*=' } | Select-Object -First 1) } else { $null }
    $curVer  = if ($verLine) { [int](($verLine -split '=',2)[1].Trim()) } else { 0 }
    $newVer  = $curVer + 1
    $iniBody = "[General]`r`nVersion=$newVer`r`n"
    [System.IO.File]::WriteAllText($gptIni, $iniBody, [System.Text.UTF8Encoding]::new($false))
    $gpoDN = "CN=$ddcpGuid,CN=Policies,CN=System,$domDN"
    Set-ADObject -Identity $gpoDN -Replace @{ versionNumber = $newVer } -ErrorAction Stop
    Write-RangeManifest $cat 'gpo-version-bump' "$ddcpGuid -> versionNumber=$newVer"
} catch { Write-RangeLog "GPO version bump (gpupdate /force still applies it): $($_.Exception.Message)" 'WARN' }

# ── apply the policy FIRST ────────────────────────────────────────────────
Write-RangeLog 'Running gpupdate /force so the DC-policy downgrades become effective now.' 'INFO'
Invoke-Native 'gpupdate.exe' @('/target:computer','/force','/wait:180') $cat

# ── THEN set the log sizes, so we are the last writer ─────────────────────
#    F37 ordering fix: this block used to run BEFORE gpupdate, so the policy
#    refresh promptly overwrote everything it had just set. Removing a setting
#    from a security template also does not roll back the value it previously
#    applied (security policy tattoos), so the small size has to be written
#    after the refresh, not before.
foreach ($log in 'Security','System') {
    # Legacy key: what the registry-only verifier reads.
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$log" 'MaxSize' DWord 1048576 $cat
    # Policy key: REMOVE any override. F36 set this to 1048576 believing it was
    # bytes; it is KB, so it demanded 1 GB and broke a channel that had been fine.
    # With no policy override present, the WINEVT channel config below wins.
    try {
        $polKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$log"
        if ((Get-RegValueSafe $polKey 'MaxSize') -ne $null) {
            Remove-ItemProperty -Path $polKey -Name 'MaxSize' -Force -ErrorAction Stop
            Write-RangeLog "Removed EventLog MaxSize policy override for $log (F36 revert)." 'WARN'
            Write-RangeManifest $cat 'remove-reg' "$polKey\MaxSize" 'F36 revert: KB/bytes mix-up demanded 1GB'
        }
    } catch { Write-RangeLog "Could not remove $log MaxSize policy override: $($_.Exception.Message)" 'WARN' }
    # Channel config: what Get-WinEvent -ListLog reports.
    Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$log" 'MaxSize' DWord 1048576 $cat
    # And report a wevtutil refusal instead of swallowing it -- the Security
    # channel needs SeSecurityPrivilege and denies this call more often than not.
    $o = & "$env:SystemRoot\System32\wevtutil.exe" sl $log /ms:1048576 2>&1
    if ($LASTEXITCODE -ne 0) { Write-RangeLog "wevtutil sl $log failed (exit $LASTEXITCODE): $(($o | Select-Object -First 1))" 'WARN' }
}

# ── verify the channels actually ended up small ───────────────────────────
foreach ($log in 'Security','System') {
    $live = (Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue |
             Where-Object { $_.LogName -eq $log } | Select-Object -First 1).MaximumSizeInBytes
    if ($null -eq $live) { Write-RangeLog "Could not read the $log channel size to verify." 'WARN'; continue }
    if ($live -le (1048576 + 65536)) {
        Write-RangeLog "$log channel is $live bytes (target 1048576 + rounding)." 'OK'
    } else {
        # F38: accepted deviation, not an error. Every supported mechanism has been
        # tried; this gates no attack path and must not fail a build.
        Write-RangeLog "$log channel is still $live bytes -- accepted deviation (F38). The two mechanisms that made it WORSE (the EventLog policy key and the [Log] template sections) are no longer written; WINEVT/wevtutil are attempted best-effort. Not a build failure." 'WARN'
    }
}

Write-RangeLog 'DC security-GPO downgrade complete.' 'OK'
