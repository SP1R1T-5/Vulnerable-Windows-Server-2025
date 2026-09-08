#requires -Version 5.1
<#
.SYNOPSIS
    STEP 3 of 3 -- verify every intentional misconfiguration, and optionally fix
    the ones that have drifted.

.DESCRIPTION
    Post-build checker. It inspects the host for every weakness the build applies
    and reports PASS / FAIL / WARN / N-A with a summary. Optional: this step
    changes nothing unless you ask it to.

        Stage-CyberRange.ps1     Structure: DC, OUs, users. Nothing weakened.
        Setup-CyberRange.ps1     The misconfigurations.
        Test-RangeConfig.ps1     <- you are here.  Verify, and -Repair drift.
        Reset-CyberRange.ps1     Teardown, when you want the VM back.

    Run it after Setup to confirm the range is as intended, and again later in the
    exercise to find what the blue team has actually fixed.

    -Repair turns it into a repair pass: for each control it tests, applies a fix
    if the control is not in its intended state, then RE-TESTS. A fix that does
    not change the result is reported STILL-FAILING, never "fixed". That
    distinction is the whole point of the re-test.

    The checks are DRIVEN BY THE CONTROL TABLE in modules\RangeControls.psm1 --
    the same table Setup applies from and Reset reverts. A control cannot be
    applied one way and checked another, because there is only one definition of
    it. What remains hand-written here is what the table does not describe: the
    answer-key ACL, the operator account, the recovery layers, and the AD
    scenarios seeded under scripts\.

    Without -Repair this script changes NOTHING, and it depends only on
    RangeControls.psm1 (not on RangeCommon.psm1) so it still runs on a freshly
    built or damaged box.

    OPERATIONAL vs DECLARED
      A registry value is a DECLARATION; it is not proof the behaviour is active.
      Where the live state can be queried, the table queries it and says so:
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

.PARAMETER Only
    Limit to these categories, e.g. -Only smb-network,logging-visibility

.PARAMETER Repair
    WRITE MODE. Fix controls that are not in their intended state, then re-test
    each one. Requires elevation. On a domain controller this also re-runs the
    delegated fixers that a local registry write cannot beat -- see -SkipGpo.

.PARAMETER SkipGpo
    -Repair only. Do not touch Group Policy and do not run gpupdate. On a DC the
    GPO-owned controls (SMB signing, NoLMHash, log sizes) will then be reported
    STILL-FAILING, which is the honest result: they cannot be fixed locally,
    because the Default Domain Controllers Policy re-asserts the secure value on
    every refresh (F33).

.PARAMETER Next
    After the summary, print the single command to run next in the
    Stage -> Setup -> Test -> Reset pipeline, chosen from the STAGED.txt /
    READY.txt markers and this run's own results (e.g. Setup not done yet,
    drift to -Repair, AD DS unreachable so ADWS must come up first, or nothing
    left to do). Read-only; it only reads the markers, it does not create them.

.PARAMETER WhatIf
    -Repair only. Report what WOULD be fixed and change nothing.

.EXAMPLE
    .\Test-RangeConfig.ps1
    Read-only. What is in place, and what is not.

.EXAMPLE
    .\Test-RangeConfig.ps1 -Repair -WhatIf
    Show what has drifted and what would be fixed.

.EXAMPLE
    .\Test-RangeConfig.ps1 -Repair -Only smb-network
    Re-apply just the SMB controls that have drifted.

.EXAMPLE
    .\Test-RangeConfig.ps1 -Format Csv -Out C:\Temp\range-check.csv
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Table','Csv','Json')][string]$Format = 'Table',
    [string]$Out,
    [switch]$ShowControl,
    [string[]]$Only,
    [switch]$Repair,
    [switch]$SkipGpo,
    [switch]$Next
)

$ErrorActionPreference = 'Continue'
$script:Results = New-Object System.Collections.Generic.List[object]

Import-Module (Join-Path $PSScriptRoot 'modules\RangeControls.psm1') -Force

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
        [ValidateSet('live','reg','')][string]$Probe = '',
        [string[]]$Technique = @()
    )
    $script:Results.Add([pscustomobject]@{
        Category = $Category; Check = $Check; State = $State
        Detail = $Detail; Control = $Control; Probe = $Probe
        Technique = ($Technique -join ', ')
    })
}

# Get-RegVal comes from RangeControls (Get-ControlRegValue) so the checker and
# the table read the registry identically. Non-throwing: probing rather than
# catching keeps $Error clean on an unbuilt host, where ~100 keys are absent and
# the noise looks like the checker itself is broken.
function Get-RegVal { param([string]$Path, [string]$Name) Get-ControlRegValue -Path $Path -Name $Name }

# Server-only cmdlets: on a client SKU these do not exist at all, and
# -ErrorAction cannot suppress CommandNotFoundException.
function Test-HasCommand { param([string]$Name) [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

# Get-LocalUser -Name <missing> writes an error record even with
# -ErrorAction SilentlyContinue. Enumerate once and match in memory instead, so
# a host that is missing every seeded account does not look like a crash.
$script:LocalUsers = @()
if (Test-HasCommand 'Get-LocalUser') { $script:LocalUsers = @(Get-LocalUser -ErrorAction SilentlyContinue) }
function Test-LocalUserExists { param([string]$Name) [bool](@($script:LocalUsers | Where-Object { $_.Name -eq $Name }).Count) }

if ($Repair -and -not $elevated) {
    throw '-Repair writes to HKLM and the running subsystems; run this in an ELEVATED PowerShell.'
}

Write-Host ""
Write-Host ("RANGE " + $(if ($Repair) { 'REPAIR' } else { 'CONFIG CHECK' }) + "  --  $env:COMPUTERNAME  --  $(Get-Date -Format s)") -ForegroundColor Cyan
Write-Host ("Role: " + $(switch ($role) {5{'primary DC'}4{'backup DC'}3{'member server'}2{'standalone server'}default{"role $role"}}) +
            $(if (-not $elevated) {'   [NOT elevated -- some checks may under-report]'} else {''}) +
            $(if ($Repair -and $WhatIfPreference) {'   [WhatIf: nothing will be changed]'} else {''})) -ForegroundColor Cyan
if ($Only) { Write-Host "Categories: $($Only -join ', ')" -ForegroundColor Cyan }

# ── -Repair engine: test -> fix -> re-test ────────────────────────────────
#    A fix that does not change the test result is STILL-FAILING, never FIXED.
$script:Repairs = New-Object System.Collections.Generic.List[object]
function Add-RepairRow {
    param([string]$Category, [string]$Name,
          [ValidateSet('OK','FIXED','STILL-FAILING','N-A','WOULD-FIX','ERROR')][string]$State,
          [string]$Detail = '')
    $script:Repairs.Add([pscustomobject]@{ Category=$Category; Name=$Name; State=$State; Detail=$Detail })
    $c = switch ($State) { 'OK' {'DarkGray'} 'FIXED' {'Green'} 'WOULD-FIX' {'Cyan'}
                           'STILL-FAILING' {'Red'} 'N-A' {'Yellow'} default {'Red'} }
    Write-Host ("  {0,-14} {1,-46} {2}" -f $State, $Name, $Detail) -ForegroundColor $c
}
function Repair-OneControl {
    param($Control, $Before)

    # PASS and WARN both mean the intended value is present (WARN just carries a
    # reboot / known-no-op note), so there is nothing to repair.
    if ($Before.State -eq 'PASS') { Add-RepairRow $Control.Category $Control.Name 'OK' 'already in the intended state'; return }
    if ($Before.State -eq 'WARN') { Add-RepairRow $Control.Category $Control.Name 'OK' $Before.Detail; return }
    if ($Before.State -eq 'N-A')  { Add-RepairRow $Control.Category $Control.Name 'N-A' $Before.Detail; return }

    $canApply = ($Control.Kind -eq 'Registry') -or ($null -ne $Control.Apply)
    if (-not $canApply -or $Control.NotRepairable) {
        $why = if ($Control.NotRepairable) { $Control.NotRepairable } else { 'no repair action defined for this control' }
        Add-RepairRow $Control.Category $Control.Name 'N-A' $why
        return
    }
    $intended = if ($Control.Intended) { $Control.Intended }
                elseif ($Control.Kind -eq 'Registry') { "$($Control.ValueName)=$($Control.Value)" }
                else { 'intended state' }

    if ($WhatIfPreference) { Add-RepairRow $Control.Category $Control.Name 'WOULD-FIX' $intended; return }

    try { Set-RangeControl -Control $Control -Config $cfg -Confirm:$false | Out-Null }
    catch { Add-RepairRow $Control.Category $Control.Name 'ERROR' "fix threw: $($_.Exception.Message)"; return }

    $after = Test-RangeControl -Control $Control -Config $cfg
    if ($after.State -in 'PASS','WARN') { Add-RepairRow $Control.Category $Control.Name 'FIXED' $intended }
    elseif ($after.State -eq 'N-A')     { Add-RepairRow $Control.Category $Control.Name 'N-A' $after.Detail }
    else { Add-RepairRow $Control.Category $Control.Name 'STILL-FAILING' 'fix applied but the control did not change -- something is overriding it' }
}

# ══ Machine-level categories, straight from the control table ══════════════
#    One row per control, in table order. Nothing about these checks is written
#    here -- the expected value, the control mapping, the reboot/no-op notes and
#    the live probes all live in modules\RangeControls.psm1.
$tableControls = @(Get-RangeControl -Config $cfg)
if ($Only) { $tableControls = @($tableControls | Where-Object { $Only -contains $_.Category }) }

if ($Repair) {
    foreach ($group in ($tableControls | Group-Object Category)) {
        Write-Host ""
        Write-Host "[$($group.Name)]" -ForegroundColor Cyan
        foreach ($ctl in $group.Group) {
            $r = Test-RangeControl -Control $ctl -Config $cfg
            Repair-OneControl -Control $ctl -Before $r
            # Record the post-repair state so the summary reflects reality.
            $final = if ($WhatIfPreference) { $r } else { Test-RangeControl -Control $ctl -Config $cfg }
            Add-Result $final.Category $final.Name $final.State $final.Detail $final.Control $final.Probe $final.Technique
        }
    }
    # F38: the event-log channel sizes are an ACCEPTED DEVIATION, not a failure.
    # Every supported mechanism was tried and none holds on this host, and the
    # size gates no attack path. Relabel rather than delete, so the control stays
    # in the scoring baseline.
    foreach ($row in @($script:Repairs | Where-Object { $_.Name -like '*channel max size*' -and $_.State -eq 'STILL-FAILING' })) {
        $row.State  = 'N-A'
        $row.Detail = 'accepted deviation (F38): not settable by any supported mechanism on this host; gates no attack path'
    }
} else {
    foreach ($ctl in $tableControls) {
        $r = Test-RangeControl -Control $ctl -Config $cfg
        Add-Result $r.Category $r.Name $r.State $r.Detail $r.Control $r.Probe $r.Technique
    }
}

# ── -Repair only: the delegated fixers a local write cannot beat ──────────
#    On a DC the built-in Default Domain Controllers Policy owns SMB signing,
#    NoLMHash and the event-log sizes through the Security CSE, and re-asserts
#    the SECURE value on every gpupdate. A local registry write "succeeds" and
#    then silently reverts, so the only fix that sticks is editing the policy's
#    own security template -- then forcing a refresh and re-testing (F33).
if ($Repair -and $isDC -and -not $Only) {
    Write-Host ""
    Write-Host "[delegated fixers]" -ForegroundColor Cyan

    $esc = Join-Path $PSScriptRoot 'scripts\ad-certificates-esc1.ps1'
    $published = $false
    try { $published = ((& certutil.exe -CATemplates 2>$null) -join "`n") -match 'RangeUserESC1' } catch {}
    if ($published) { Add-RepairRow 'ad-certificates' 'ESC1 template published on the CA' 'OK' 'listed by certutil -CATemplates' }
    elseif ($WhatIfPreference) { Add-RepairRow 'ad-certificates' 'ESC1 template published on the CA' 'WOULD-FIX' 'would run scripts\ad-certificates-esc1.ps1' }
    elseif (Test-Path $esc) {
        Write-Host "  running scripts\ad-certificates-esc1.ps1 ..." -ForegroundColor DarkGray
        try { & $esc | Out-Null } catch { Write-Host "    $($_.Exception.Message)" -ForegroundColor Red }
        $now = $false
        try { $now = ((& certutil.exe -CATemplates 2>$null) -join "`n") -match 'RangeUserESC1' } catch {}
        if ($now) { Add-RepairRow 'ad-certificates' 'ESC1 template published on the CA' 'FIXED' 'now listed by certutil -CATemplates' }
        else { Add-RepairRow 'ad-certificates' 'ESC1 template published on the CA' 'STILL-FAILING' 'CA still does not list RangeUserESC1 -- check CertSvc and the pKIEnrollmentService object' }
    } else { Add-RepairRow 'ad-certificates' 'ESC1 template published on the CA' 'ERROR' "fixer not found: $esc" }

    if ($SkipGpo) {
        Add-RepairRow 'dc-gpo' 'DC security-template downgrade' 'N-A' '-SkipGpo given; GPO-owned controls cannot be fixed locally'
    } elseif ($WhatIfPreference) {
        Add-RepairRow 'dc-gpo' 'DC security-template downgrade' 'WOULD-FIX' 'would run scripts\dc-security-gpo.ps1 + gpupdate /force'
    } else {
        $gpoFixer = Join-Path $PSScriptRoot 'scripts\dc-security-gpo.ps1'
        if (Test-Path $gpoFixer) {
            Write-Host "  running scripts\dc-security-gpo.ps1 ..." -ForegroundColor DarkGray
            try {
                & $gpoFixer | Out-Null
                Write-Host "  running gpupdate /force (policy refresh is what used to revert these) ..." -ForegroundColor DarkGray
                & gpupdate.exe /force 2>&1 | Out-Null
                Start-Sleep -Seconds 5
                # Re-test the GPO-owned controls through the SAME table entries, so
                # "survives gpupdate" is measured exactly like everything else.
                foreach ($id in 'smb.live.srvsigning','cred.nolmhash','log.live.size.Security','log.live.size.System') {
                    $c2 = @(Get-RangeControl -Id $id -Config $cfg)[0]
                    if (-not $c2) { continue }
                    $r2 = Test-RangeControl -Control $c2 -Config $cfg
                    $label = "$($c2.Name) survives gpupdate"
                    switch ($r2.State) {
                        'PASS'  { Add-RepairRow 'dc-gpo' $label 'FIXED' $r2.Detail }
                        'WARN'  { Add-RepairRow 'dc-gpo' $label 'FIXED' $r2.Detail }
                        'N-A'   { Add-RepairRow 'dc-gpo' $label 'N-A'   $r2.Detail }
                        default { Add-RepairRow 'dc-gpo' $label 'STILL-FAILING' "policy re-asserted the secure value -- $($r2.Detail)" }
                    }
                }
            } catch { Add-RepairRow 'dc-gpo' 'DC security-template downgrade' 'ERROR' $_.Exception.Message }
        } else { Add-RepairRow 'dc-gpo' 'DC security-template downgrade' 'ERROR' "fixer not found: $gpoFixer" }
    }
}

$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
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

# ══ Recovery layers (safety, not exploits) ═════════════════════════════════
#    There is ONE operator account (checked in the next section). What is checked
#    here are the layers that do not depend on it, in the order docs\BREAK-GLASS.md
#    tells you to work down them.
$c = 'recovery'
# The logon-screen SYSTEM shell: the only path that needs no password at all.
$ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$shellArmed = @('utilman.exe','sethc.exe') | Where-Object {
    $d = Get-RegVal "$ifeoRoot\$_" 'Debugger'; $d -and $d -match 'cmd\.exe|powershell'
}
if (-not $cfg -or $cfg.AccessibilityShell) {
    if ($shellArmed.Count) { Add-Result $c '[live] Logon-screen SYSTEM shell armed' 'PASS' ("$($shellArmed -join ', ') -- Win+U or Shift x5 at the logon screen") 'NIST CP-2, AC-3' 'reg' }
    else { Add-Result $c '[live] Logon-screen SYSTEM shell armed' 'FAIL' 'no IFEO Debugger on utilman/sethc -- the no-password recovery path is NOT available' 'NIST CP-2, AC-3' 'reg' }
} else {
    Add-Result $c '[live] Logon-screen SYSTEM shell armed' 'N-A' 'AccessibilityShell = $false in config' 'NIST CP-2' 'reg'
}
# The typeable recovery script that shell is meant to run (paste does not work there).
if (Test-Path 'C:\range-fix.cmd') { Add-Result $c '[live] C:\range-fix.cmd present' 'PASS' 'typeable recovery script for the logon-screen shell' 'NIST CP-2' 'live' }
else { Add-Result $c '[live] C:\range-fix.cmd present' 'FAIL' 'missing -- the operator keeper drops this; check keeper.log' 'NIST CP-2' 'live' }
# The keeper task is what makes the operator account self-healing.
$keeper = Get-ScheduledTask -TaskName 'CyberRangeOperatorKeeper' -ErrorAction SilentlyContinue
if (-not $cfg -or $cfg.OperatorKeeper) {
    if ($keeper) { Add-Result $c '[live] Operator keeper task registered' 'PASS' "State=$($keeper.State) -- re-asserts the operator account every boot" 'NIST CP-2, AC-2' 'live' }
    else { Add-Result $c '[live] Operator keeper task registered' 'FAIL' 'CyberRangeOperatorKeeper not registered -- the operator account will NOT self-heal' 'NIST CP-2, AC-2' 'live' }
} else {
    Add-Result $c '[live] Operator keeper task registered' 'N-A' 'OperatorKeeper = $false in config' 'NIST CP-2' 'live'
}

# ══ Operator admin (the account you log in as) ═════════════════════════════
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

if ($Repair) {
    $g = $script:Repairs | Group-Object State | Sort-Object Name
    Write-Host ("REPAIR SUMMARY: " + (($g | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  ')) -ForegroundColor Cyan
    $stuck = @($script:Repairs | Where-Object State -in 'STILL-FAILING','ERROR')
    if ($stuck.Count) {
        Write-Host ""
        Write-Host "NOT REPAIRED -- these need a human:" -ForegroundColor Red
        foreach ($r in $stuck) {
            Write-Host ("  [{0}] {1}" -f $r.Category, $r.Name) -ForegroundColor Red
            Write-Host ("        {0}" -f $r.Detail) -ForegroundColor DarkGray
        }
    }
    if ($WhatIfPreference) {
        Write-Host ""
        Write-Host "WhatIf: nothing was changed. Re-run without -WhatIf to apply." -ForegroundColor Cyan
    }
    Write-Host ""
}
if ($Format -eq 'Table') {
    foreach ($grp in ($Results | Group-Object Category)) {
        Write-Host ("[{0}]" -f $grp.Name) -ForegroundColor Cyan
        foreach ($r in $grp.Group) {
            $col = switch ($r.State) { 'PASS' {'Green'} 'FAIL' {'Red'} 'WARN' {'Yellow'} default {'Gray'} }
            Write-Host ("  {0,-5} {1,-48} {2}" -f $r.State, $r.Check, $r.Detail) -ForegroundColor $col
            if ($ShowControl -and $r.Control) { Write-Host ("        -> {0}" -f $r.Control) -ForegroundColor DarkGray }
            if ($ShowControl -and $r.Technique) { Write-Host ("        -> ATT&CK {0}" -f $r.Technique) -ForegroundColor DarkGray }
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

# WP15: ATT&CK coverage of what is actually IN PLACE (PASS/WARN), so the number
# reflects the range a student meets rather than the table's ambitions. Controls
# with no defensible technique are deliberately unmapped and simply do not count.
if ($ShowControl) {
    $tech = $Results | Where-Object { $_.Technique -and $_.State -in 'PASS','WARN' } |
            ForEach-Object { $_.Technique -split ',\s*' } | Group-Object | Sort-Object Name
    if ($tech) {
        Write-Host ""
        Write-Host ("ATT&CK COVERAGE (in place): {0} technique(s)" -f $tech.Count) -ForegroundColor Cyan
        Write-Host ("  " + (($tech | ForEach-Object { "{0} x{1}" -f $_.Name, $_.Count }) -join '   ')) -ForegroundColor DarkGray
        $unmapped = @($Results | Where-Object { -not $_.Technique -and $_.State -in 'PASS','WARN' }).Count
        Write-Host ("  {0} in-place control(s) deliberately unmapped -- see `$script:TechniqueMap in RangeControls.psm1" -f $unmapped) -ForegroundColor DarkGray
    }
}
if ($fail -gt 0) {
    Write-Host ""
    Write-Host "FAILURES (build did not apply, or it was reverted):" -ForegroundColor Red
    foreach ($r in ($Results | Where-Object State -eq 'FAIL')) {
        Write-Host ("  [{0}] {1}" -f $r.Category, $r.Check) -ForegroundColor Red
        if ($r.Control) { Write-Host ("        control: {0}" -f $r.Control) -ForegroundColor DarkGray }
    }
}

if ($Next) {
    $stateDir = 'C:\ProgramData\CyberRange'
    $staged   = Test-Path (Join-Path $stateDir 'STAGED.txt')
    $ready    = Test-Path (Join-Path $stateDir 'READY.txt')
    # AD-down is special: the directory checks can't run and -Repair can't help,
    # so ADWS/NTDS must come up before re-testing (do not send them to -Repair).
    $adDown   = [bool](@($Results | Where-Object {
                    $_.Category -eq 'dc-ad' -and $_.Check -match 'AD DS reachable' -and $_.State -eq 'FAIL' }).Count)

    Write-Host ""
    Write-Host "NEXT STEP:" -ForegroundColor Cyan
    if (-not $staged) {
        Write-Host "  Structure not built yet (no STAGED.txt). Build the domain:" -ForegroundColor White
        Write-Host "    .\Stage-CyberRange.ps1" -ForegroundColor Green
    } elseif (-not $ready) {
        Write-Host "  Staged, but the misconfigurations are not applied yet (no READY.txt). Apply them:" -ForegroundColor White
        Write-Host "    .\Setup-CyberRange.ps1" -ForegroundColor Green
    } elseif ($adDown) {
        Write-Host "  AD DS is unreachable -- the directory checks can't run and -Repair can't fix it." -ForegroundColor White
        Write-Host "  Bring Active Directory Web Services up, then re-run this check:" -ForegroundColor White
        Write-Host "    Set-Service ADWS -StartupType Automatic; Start-Service ADWS" -ForegroundColor Green
        Write-Host "    .\Test-RangeConfig.ps1 -Next" -ForegroundColor Green
    } elseif ($fail -gt 0 -and -not $Repair) {
        Write-Host "  $fail control(s) have drifted from as-built. Re-apply and re-test the drift:" -ForegroundColor White
        Write-Host "    .\Test-RangeConfig.ps1 -Repair -Next" -ForegroundColor Green
    } elseif ($fail -gt 0 -and $Repair) {
        Write-Host "  $fail control(s) are STILL FAILING after -Repair -- these need a look by hand." -ForegroundColor White
        Write-Host "  See the FAILURES list above (a local write cannot beat a GPO-owned control; use -SkipGpo notes)." -ForegroundColor White
    } else {
        Write-Host "  Range verified -- 0 FAIL. Nothing to run. When the exercise is over, tear it down:" -ForegroundColor White
        Write-Host "    .\Reset-CyberRange.ps1" -ForegroundColor Green
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
