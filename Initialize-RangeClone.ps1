#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    First-boot personalization for one participant VM (WP2 -- closes F16).

.DESCRIPTION
    Run this ONCE on each clone, by a range administrator, before the student
    receives the VM. It gives this clone its own identity and its own operator
    secrets, then hands back to the build engine to promote it into ITS OWN
    forest.

    WHY THIS EXISTS
    ---------------------------------------------------------------------------
    F16: if the golden image is cut AFTER promotion, every clone shares the same
    domain SID, the same krbtgt and the same NT hashes. On a shared range LAN a
    golden ticket forged on one student's box is valid on every other student's
    box. The fix is structural, not a patch: cut the image BEFORE promotion, and
    let each clone promote itself. Unique domain SID and unique krbtgt then come
    for free, because they are generated during promotion.

    This script supplies the rest of the per-clone identity:
      * computer name   RANGE<nn>-DC01
      * domain          r<nn>.range.lab / R<nn>
      * four operator secrets derived from the range master secret

    The master secret is supplied here as a parameter and is NEVER written to
    disk. Only derived values land on the VM, and a derived value does not reveal
    the master or any peer's secrets. The instructor recovers any clone's
    credentials later with Get-RangeCloneSecret.ps1 -- no per-clone bookkeeping.

    ORDER OF OPERATIONS
      1. Verify this really is a pre-promotion golden-image clone.
      2. Derive identity + secrets (shared helper; cannot drift from the recovery tool).
      3. Rewrite the staged config in place, preserving comments.
      4. Re-assert the operator accounts with the NEW derived passwords.
      5. Rename the computer -- a rename MUST settle before promotion.
      6. Set build state to Phase 2, register the resume task, reboot.
         The existing state machine then promotes, seeds and finalizes unattended.

.PARAMETER CloneId
    This participant's number, 01-99. Determines name, domain and all secrets.

.PARAMETER MasterSecret
    The range master secret. Prompted for (hidden) if omitted. Never stored.

.PARAMETER NoReboot
    Do everything except the final reboot, so you can inspect first. The clone is
    NOT finished until it reboots and the resume task runs.

.PARAMETER WhatIf
    Show the derived identity and what would change. Touches nothing.

.EXAMPLE
    .\Initialize-RangeClone.ps1 -CloneId 07
    Personalize this VM as clone 07 and start its own promotion.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$CloneId,
    [System.Security.SecureString]$MasterSecret,
    [string]$BaseDomain = 'range.lab',
    [switch]$NoReboot
)

$ErrorActionPreference = 'Stop'
$LocalRoot = 'C:\CyberRange'
$TaskName  = 'CyberRangeSetup'
$StateDir  = Join-Path $env:ProgramData 'CyberRange'
$StateFile = Join-Path $StateDir 'setup-state.json'
$ConfigPath = Join-Path $LocalRoot 'config\range.config.psd1'

Import-Module (Join-Path $LocalRoot 'modules\RangeCommon.psm1') -Force

# ── 1. guards ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "RANGE CLONE PERSONALIZATION  --  $env:COMPUTERNAME  --  $(Get-Date -Format s)" -ForegroundColor Cyan

$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.DomainRole -ge 4) {
    throw ("This host is ALREADY a domain controller. Personalization must run on a " +
           "pre-promotion golden-image clone -- that is the whole point of F16. A clone " +
           "made from a promoted image already shares krbtgt and the domain SID with " +
           "every other clone and cannot be fixed by renaming it. Re-cut the image with " +
           "Setup-CyberRange.ps1 -Mode Image.")
}
if ($cs.PartOfDomain) {
    throw "This host is joined to domain '$($cs.Domain)'. A clone must be standalone before it promotes its own forest."
}
if (-not (Test-Path $ConfigPath)) {
    throw "Staged config not found at $ConfigPath. Run Stage-CyberRange.ps1 first, or this is not a range image."
}

if (-not $MasterSecret) { $MasterSecret = Read-Host 'Range master secret' -AsSecureString }
$b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($MasterSecret)
try { $plainMaster = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
if (-not $plainMaster) { throw 'Master secret was empty.' }

# ── 2. derive ─────────────────────────────────────────────────────────────
$id = Get-RangeCloneIdentity -CloneId $CloneId -MasterSecret $plainMaster -BaseDomain $BaseDomain
$plainMaster = $null      # not needed again; never written anywhere

Write-Host ""
Write-Host "This clone will become:" -ForegroundColor Yellow
Write-Host "  Computer name        : $($id.ComputerName)   (currently $env:COMPUTERNAME)"
Write-Host "  Domain (DNS/NetBIOS) : $($id.DomainName) / $($id.NetbiosName)"
Write-Host "  Operator secrets     : derived per-clone (recover with Get-RangeCloneSecret.ps1 -CloneId $($id.CloneId))"
Write-Host ""

if ($WhatIfPreference) {
    Write-Host "WhatIf: nothing changed. Re-run without -WhatIf to personalize." -ForegroundColor Cyan
    return
}

# ── 3. rewrite the staged config, preserving comments ─────────────────────
#    A psd1 round-trip through Import-PowerShellDataFile would discard every
#    comment in the file, and those comments are load-bearing documentation.
#    Targeted, scoped replacement instead.
function Set-ConfigValue {
    param([string]$Text,[string]$Key,[string]$Value,[string]$WithinBlock)
    if ($WithinBlock) {
        # Scope to one nested block, because 'Password' appears in more than one.
        $pattern = "(?s)($WithinBlock\s*=\s*@\{.*?)(\b$Key\s*=\s*')[^']*(')"
        if ($Text -notmatch $pattern) { throw "config: could not locate $WithinBlock.$Key" }
        return [regex]::Replace($Text, $pattern, { param($m) $m.Groups[1].Value + $m.Groups[2].Value + $Value + $m.Groups[3].Value }, 1)
    }
    $pattern = "(\b$Key\s*=\s*')[^']*(')"
    if ($Text -notmatch $pattern) { throw "config: could not locate $Key" }
    return [regex]::Replace($Text, $pattern, { param($m) $m.Groups[1].Value + $Value + $m.Groups[2].Value }, 1)
}

$orig = Get-Content $ConfigPath -Raw
$new  = $orig
$new = Set-ConfigValue $new 'DomainName'              $id.DomainName          -WithinBlock 'DC'
$new = Set-ConfigValue $new 'NetbiosName'             $id.NetbiosName         -WithinBlock 'DC'
$new = Set-ConfigValue $new 'SafeModePassword'        $id.DsrmPassword        -WithinBlock 'DC'
$new = Set-ConfigValue $new 'Password'                $id.BreakGlassPassword  -WithinBlock 'BreakGlass'
$new = Set-ConfigValue $new 'Password'                $id.AnalystPassword     -WithinBlock 'Analyst'
$new = Set-ConfigValue $new 'LocalAdminAutoLogonPass' $id.AdminPassword
$new = Set-ConfigValue $new 'HiddenAdminPassword'     $id.HiddenAdminPassword

if ($PSCmdlet.ShouldProcess($ConfigPath, 'rewrite with per-clone identity')) {
    Copy-Item $ConfigPath "$ConfigPath.preclone" -Force
    Set-Content -Path $ConfigPath -Value $new -Encoding UTF8
    # Prove it still loads and actually took, before we depend on it.
    $check = Import-PowerShellDataFile $ConfigPath
    if ($check.DC.DomainName -ne $id.DomainName -or $check.LocalAdminAutoLogonPass -ne $id.AdminPassword -or
        $check.Analyst.Password -ne $id.AnalystPassword -or $check.BreakGlass.Password -ne $id.BreakGlassPassword) {
        Copy-Item "$ConfigPath.preclone" $ConfigPath -Force
        throw 'Config rewrite did not take (restored the original). Do not proceed.'
    }
    Write-Host "  config rewritten and verified (backup: $ConfigPath.preclone)" -ForegroundColor Green
}

# ── 4. operator accounts with the NEW secrets ─────────────────────────────
#    Sysprep resets local account state, and the passwords just changed, so the
#    break-glass and analyst accounts have to be re-asserted BEFORE the reboot --
#    they are the way back in if promotion goes wrong.
foreach ($s in 'scripts\00-break-glass.ps1','scripts\01-analyst-admin.ps1') {
    $p = Join-Path $LocalRoot $s
    if (-not (Test-Path $p)) { Write-Host "  MISSING $s" -ForegroundColor Red; continue }
    Write-Host "  running $s ..." -ForegroundColor DarkGray
    try { & $p -Apply -FromBuild 2>&1 | Out-Null } catch { try { & $p -FromBuild 2>&1 | Out-Null } catch { Write-Host "    $($_.Exception.Message)" -ForegroundColor Yellow } }
}

# ── 5. rename ─────────────────────────────────────────────────────────────
if ($env:COMPUTERNAME -ne $id.ComputerName) {
    if ($PSCmdlet.ShouldProcess($id.ComputerName, 'rename computer')) {
        Rename-Computer -NewName $id.ComputerName -Force -ErrorAction Stop
        Write-Host "  renamed to $($id.ComputerName) (settles on reboot)" -ForegroundColor Green
    }
} else { Write-Host "  computer name already $($id.ComputerName)" -ForegroundColor DarkGray }

# ── 6. hand back to the build engine at Phase 2 ───────────────────────────
#    The rename must settle before promotion, which is why this reboots rather
#    than promoting inline. Setting Phase=2 means the resume task picks up at
#    promotion; the rest of the state machine is untouched.
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
$state = if (Test-Path $StateFile) { Get-Content $StateFile -Raw | ConvertFrom-Json }
         else { [pscustomobject]@{ Phase = 1; LogFile = $null; Manifest = $null; PromoteTries = 0 } }
$state.Phase = 2
$state | Add-Member -NotePropertyName CloneId -NotePropertyValue $id.CloneId -Force
($state | ConvertTo-Json) | Set-Content -Path $StateFile -Encoding UTF8

$action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
             -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$LocalRoot\Setup-CyberRange.ps1`" -Resume"
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 3) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "  resume task registered; build will continue at Phase 2 (promotion)" -ForegroundColor Green

Protect-RangePath -Path $StateDir

Write-Host ""
Write-Host "CLONE $($id.CloneId) PERSONALIZED" -ForegroundColor Green
Write-Host "  After reboot this VM promotes itself into $($id.DomainName) -- its OWN forest," -ForegroundColor Green
Write-Host "  with a domain SID and krbtgt unique to this clone. That is what closes F16." -ForegroundColor Green
Write-Host ""
Write-Host "  Recover its credentials any time with:" -ForegroundColor Cyan
Write-Host "      .\Get-RangeCloneSecret.ps1 -CloneId $($id.CloneId)" -ForegroundColor Cyan
Write-Host "  Watch progress:  Get-Content C:\ProgramData\CyberRange\logs\rangebuild-*.log -Tail 40 -Wait" -ForegroundColor Cyan
Write-Host ""

if ($NoReboot) { Write-Host "-NoReboot: reboot manually to start promotion. The clone is NOT finished yet." -ForegroundColor Yellow; return }
Write-Host "Rebooting in 10s to start promotion. Ctrl+C to cancel." -ForegroundColor Yellow
Start-Sleep -Seconds 10
Restart-Computer -Force
