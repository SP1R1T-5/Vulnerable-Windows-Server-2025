#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    ONE-SHOT unattended builder for the Windows Server 2025 cyber range.

.DESCRIPTION
    The build ENGINE (Stage 2). You normally launch Stage-CyberRange.ps1, which
    stages the repo to C:\CyberRange and calls this; the SYSTEM resume task then
    re-invokes this local copy across reboots. It:
      1. Runs only from the staged local copy at C:\CyberRange (guarded below).
      2. PHASE 1  - applies every machine-level misconfiguration (Defender,
         updates, UAC/LSA/VBS, SMB, RDP/WinRM, logging, legacy services,
         persistence, CVE artifacts), optionally uninstalls Defender, and pre-
         installs the AD DS role -> reboot.
      3. PHASE 2  - promotes this host to the first DC of a new forest (if
         DC.Enabled) -> reboot (automatic, from the promotion itself).
      4. PHASE 3  - seeds the AD attack paths (Kerberoast/AS-REP fodder, AD CS
         ESC1, weak ACLs / delegation, GPP cpassword) plus hidden DOMAIN admins;
         on a non-DC build it creates hidden LOCAL admins instead.
      5. PHASE 4  - removes the resume task and drops a READY marker.

    Progress is tracked in C:\ProgramData\CyberRange\setup-state.json. After each
    reboot the run resumes UNATTENDED via a SYSTEM-at-startup scheduled task (no
    login required -- essential on a DC, where the accounts you would log in with
    do not exist until Phase 3 runs). Watch C:\ProgramData\CyberRange\logs; when
    READY.txt appears, log in as 'analyst'. Run `-Resume` by hand for a prompt.
    A single continuous log + change-manifest live in C:\ProgramData\CyberRange\logs.

    FOR ISOLATED, AUTHORIZED EDUCATIONAL USE ONLY. Requires Confirmed = $true in
    config\range.config.psd1.

.PARAMETER Resume
    Used by the auto-resume scheduled task after a reboot. You never pass this by
    hand -- just run the script with no arguments the first time.

.PARAMETER Force
    Advance to the next phase even if steps in the current phase failed. Without
    it a phase with any failed step stops the build instead of rebooting into DC
    promotion on top of a broken machine (finding F7).
#>
[CmdletBinding()]
param([switch]$Resume, [switch]$Force)

$ErrorActionPreference = 'Stop'
$LocalRoot = 'C:\CyberRange'
$TaskName  = 'CyberRangeSetup'
$StateDir  = Join-Path $env:ProgramData 'CyberRange'
$StateFile = Join-Path $StateDir 'setup-state.json'
$ReadyFile = Join-Path $StateDir 'READY.txt'

# ── 0. Guard: this ENGINE runs only from the staged local copy ────────────
#    Stage-CyberRange.ps1 (Stage 1) copies the repo to $LocalRoot and launches
#    this. Mapped/removable drives are not present for the SYSTEM resume task at
#    boot, so the engine and its resume task must live on local disk.
if ($PSScriptRoot.TrimEnd('\') -ine $LocalRoot.TrimEnd('\')) {
    throw ("Setup-CyberRange.ps1 is the build ENGINE and must run from $LocalRoot " +
           "(currently '$PSScriptRoot').`nRun Stage-CyberRange.ps1 first -- it stages " +
           "the repo here and launches this. The SYSTEM resume task re-invokes this " +
           "local copy across reboots, which is why it cannot run from a share.")
}

Import-Module (Join-Path $LocalRoot 'modules\RangeCommon.psm1') -Force
$Config = Import-PowerShellDataFile (Join-Path $LocalRoot 'config\range.config.psd1')

# ── State helpers ─────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
function Get-State {
    if (Test-Path $StateFile) { return (Get-Content $StateFile -Raw | ConvertFrom-Json) }
    [pscustomobject]@{ Phase = 1; LogFile = $null; Manifest = $null; PromoteTries = 0 }
}
function Save-State { param($s) ($s | ConvertTo-Json) | Set-Content -Path $StateFile -Encoding UTF8 }
$state = Get-State

# One continuous log/manifest across all reboots.
if ($state.LogFile) { $env:RANGE_LOGFILE = $state.LogFile; $env:RANGE_MANIFEST = $state.Manifest }
Initialize-RangeContext
if (-not $state.LogFile) {
    $state.LogFile = $env:RANGE_LOGFILE; $state.Manifest = $env:RANGE_MANIFEST; Save-State $state
}

# NOTE: the staged tree at $LocalRoot is deliberately NOT ACL-locked. Locking it
# was the repeated source of "access denied" failures (a re-run or a
# non-elevated child could not read its own scripts). The genuinely sensitive
# artifact -- the change manifest / answer key -- lives in C:\ProgramData\CyberRange
# and IS locked by Initialize-RangeContext. The staged config also holds secrets,
# but on a built box the operator is Administrator and can read them regardless
# (finding F18), and getting the answer key off-box is handled by WP2/WP3. So we
# leave $LocalRoot on normal inherited permissions.

if ([int]$state.Phase -ge 99) {
    Write-RangeLog 'Setup already completed (state = done). Nothing to do.' 'OK'
    return
}

Assert-RangeSafety -Config $Config -AllowPlaceholderCredentials:$Force
Write-RangeLog "==== One-shot range setup on $env:COMPUTERNAME (phase $($state.Phase)$(if($Resume){', resumed'})) ====" 'WARN'

# F29 pre-flight: a DC build promotes a STANDALONE server into its OWN new forest.
# A box already joined to a domain AS A MEMBER (DomainRole 1/3, PartOfDomain=$true,
# not yet a DC) cannot create a new forest -- promotion fails prereqs, and by then
# Phase 1 has already weakened the box. Refuse BEFORE any weakening. (A promoted DC
# is DomainRole 4/5 and passes; a true standalone is PartOfDomain=$false.)
if ($Config.DC.Enabled) {
    $cs0 = Get-CimInstance Win32_ComputerSystem
    if ($cs0.PartOfDomain -and $cs0.DomainRole -lt 4) {
        throw ("This host is a MEMBER of domain '$($cs0.Domain)' (DomainRole $($cs0.DomainRole)). A DC.Enabled build " +
               "promotes a STANDALONE server into its OWN new forest and cannot run on a domain member (nothing has " +
               "been changed yet).`nMove it to a workgroup and reboot:  Add-Computer -WorkgroupName WORKGROUP -Force -Restart`n" +
               "...or start from a clean standalone snapshot that was never domain-joined, then re-run.")
    }
}

# After a reboot the resume runs here in a visible, elevated window (see
# Register-ResumeTask). Prompt the operator so the continuation is obvious and
# under their control, rather than a silent background task. Guarded so a
# non-interactive context (or a stopped console) just proceeds.
if ($Resume) {
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host " CYBER RANGE SETUP -- RESUMING AFTER REBOOT" -ForegroundColor Cyan
    Write-Host ("   Host: $env:COMPUTERNAME    Phase to run: $($state.Phase)    $(Get-Date -Format s)") -ForegroundColor Cyan
    Write-Host " The build will continue (promotion / AD seeding / finalize as needed)." -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    # F30: NEVER prompt when this is the SYSTEM resume task.
    #
    # [Environment]::UserInteractive is TRUE for a scheduled task -- it only goes
    # false for a service without desktop interaction -- so the old guard did not
    # guard anything. At boot the task reached Read-Host and blocked forever on a
    # console no one can type into. With -ExecutionTimeLimit Zero nothing ever
    # killed it, and because the task is -MultipleInstances IgnoreNew, the hung
    # instance then suppressed every later trigger. That is why the build "does
    # not auto-resume": the task fires, hangs on a prompt, and blocks its own
    # retries. Identity, not UserInteractive, is the reliable test.
    $isSystem = try { [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem } catch { $false }
    if ($isSystem -or -not [Environment]::UserInteractive) {
        Write-RangeLog 'Unattended resume (SYSTEM / no interactive console); continuing without a prompt.' 'INFO'
    } else {
        try {
            Read-Host " Press ENTER to continue now (or close this window / Ctrl+C to stop and resume later)" | Out-Null
        } catch { Write-RangeLog 'No console for the resume prompt; continuing automatically.' 'WARN' }
    }
}

# ── Task + helper functions ───────────────────────────────────────────────
function Register-ResumeTask {
    # SYSTEM at STARTUP -- runs with NO interactive login. This is essential on a
    # DC: promotion destroys the local SAM, so the domain 'analyst' / break-glass
    # accounts do not exist until Phase 3 (re)creates them. A login-gated resume
    # deadlocks -- you cannot log in to trigger the phase that creates the account
    # you would log in with, which is exactly the lockout seen in the field.
    # SYSTEM on a DC can create the domain accounts unattended, so the build
    # finishes on its own; when READY.txt appears, log in as 'analyst'. Progress
    # is in C:\ProgramData\CyberRange\logs. (Run `Setup-CyberRange.ps1 -Resume`
    # by hand to get the visible ENTER prompt instead.)
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                 -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$LocalRoot\Setup-CyberRange.ps1`" -Resume"
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # F30: a FINITE limit. With TimeSpan::Zero (no limit) a wedged instance ran
    # forever and, being -MultipleInstances IgnoreNew, suppressed every later
    # trigger -- the build could never retry itself. 3h is far longer than a real
    # build needs, so this only ever fires on a genuine hang.
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 3) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-RangeLog "Resume task '$TaskName' registered (SYSTEM at startup -- unattended, no login needed)."
}
function Write-ResumeHint {
    <# Printed immediately before every reboot. The build is supposed to resume
       itself, but if it does not, the operator should not have to go looking for
       the command -- it is the last thing on screen before the box goes down. #>
    Write-Host ""
    Write-Host "----------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host " REBOOTING. The build should resume by itself (SYSTEM task at startup)." -ForegroundColor Yellow
    Write-Host " If it does NOT, open an elevated PowerShell after boot and run:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "     C:\CyberRange\Resume-CyberRange.ps1" -ForegroundColor Green
    Write-Host ""
    Write-Host " Add -StatusOnly to just see where the build stopped. Watch progress:" -ForegroundColor Yellow
    Write-Host "     Get-Content C:\ProgramData\CyberRange\logs\rangebuild-*.log -Tail 40 -Wait" -ForegroundColor Green
    Write-Host "----------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host ""
    Write-RangeLog 'Manual resume if needed: C:\CyberRange\Resume-CyberRange.ps1' 'WARN'
}
function Unregister-ResumeTask {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-RangeLog "Resume task '$TaskName' removed."
}
function Register-KeeperTask {
    # PERMANENT SYSTEM-at-startup task (NOT removed at the end) that re-asserts the
    # operator 'analyst' account on every boot, so a stalled phase, GPO, lockout or
    # promotion can never leave the operator locked out. Separate from the resume
    # task, which is temporary.
    if (-not $Config.OperatorKeeper) { return }
    $a = New-ScheduledTaskAction -Execute 'powershell.exe' `
         -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$LocalRoot\scripts\02-operator-keeper.ps1`" -FromBoot"
    $t = New-ScheduledTaskTrigger -AtStartup
    $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName 'CyberRangeOperatorKeeper' -Action $a -Trigger $t -Principal $pr -Settings $s -Force | Out-Null
    Write-RangeLog "Operator keeper task registered (SYSTEM at startup, PERMANENT) -- 'analyst' self-heals every boot."
}
$script:PhaseFailures    = 0
$script:BuildHadFailures = $false
function Test-AdQueryable {
    <# $true = AD answered, $false = AD is unreachable (ADWS down / no DC located).
       Distinguishing "AD is down" from "the account is missing" matters: the
       existence checks below used to report a missing account whenever the query
       itself failed, which sent operators hunting for the wrong problem. #>
    try { Import-Module ActiveDirectory -ErrorAction Stop; Get-ADDomain -ErrorAction Stop | Out-Null; $true }
    catch { $false }
}
function Invoke-Step {
    param([string]$Rel)
    $p = Join-Path $LocalRoot $Rel
    Write-RangeLog "---- $Rel ----" 'WARN'
    try { & $p -Config $Config; return $true }
    catch {
        Write-RangeLog "$Rel failed: $($_.Exception.Message)" 'ERROR'
        $script:PhaseFailures++
        return $false
    }
}
function Test-PhaseClean {
    <# F7: a phase with failed steps must not advance. Rebooting into DC
       promotion on top of a half-applied machine is how builds get unrecoverable. #>
    param([int]$Phase)
    if ($script:PhaseFailures -eq 0) { return $true }
    if ($Force) {
        Write-RangeLog "PHASE $Phase had $($script:PhaseFailures) failed step(s); -Force given, continuing anyway." 'WARN'
        $script:BuildHadFailures = $true
        return $true
    }
    Write-RangeLog "PHASE $Phase had $($script:PhaseFailures) failed step(s). NOT advancing." 'ERROR'
    Write-RangeLog "Review the log above, fix the cause, and re-run (steps are idempotent)." 'WARN'
    Write-RangeLog "To proceed regardless: .\Setup-CyberRange.ps1 -Force" 'WARN'
    return $false
}
function Invoke-BreakGlass {
    <# F2: provision the operator recovery account BEFORE the box is weakened,
       and again after promotion (a DC has no local SAM, so the Phase-1 local
       account does not survive).
       F21: provisioning failure is now FATAL -- it counts as a phase failure so
       Test-PhaseClean blocks the reboot. Weakening the box and rebooting with no
       recovery account is the exact condition that produced the field lockout. #>
    param([string]$Why)
    if (-not ($Config.BreakGlass -and $Config.BreakGlass.Enabled)) {
        Write-RangeLog 'BreakGlass disabled in config -- building with NO operator recovery account.' 'WARN'
        return
    }
    Write-RangeLog "---- break-glass ($Why) ----" 'WARN'
    try { & (Join-Path $LocalRoot 'scripts\00-break-glass.ps1') -Apply -FromBuild }
    catch { Write-RangeLog "Break-glass provisioning threw: $($_.Exception.Message)" 'ERROR' }

    # F21: confirm a usable recovery account actually exists now; a printed gate
    # failure inside the child script does not surface here, so verify directly.
    $u = $Config.BreakGlass.User
    if ((Test-IsDomainController) -and -not (Test-AdQueryable)) {
        Write-RangeLog "Cannot verify break-glass account '$u': ACTIVE DIRECTORY IS UNREACHABLE (ADWS down / no DC located). This is the real fault -- the account may well exist. Check: Get-Service ADWS,NTDS,DNS  and  nltest /dsgetdc:$($Config.DC.DomainName)" 'ERROR'
        $script:PhaseFailures++
        return
    }
    $exists = if (Test-IsDomainController) {
        [bool](Get-ADUser -Filter "SamAccountName -eq '$u'" -ErrorAction SilentlyContinue)
    } else {
        [bool](Get-LocalUser -Name $u -ErrorAction SilentlyContinue)
    }
    if (-not $exists) {
        Write-RangeLog "Break-glass account '$u' does NOT exist after provisioning; refusing to weaken the box (F21). Fix the cause, or pass -Force to override." 'ERROR'
        $script:PhaseFailures++
    } else {
        Write-RangeLog "Break-glass account '$u' present and provisioned." 'OK'
    }
}
function Invoke-Analyst {
    <# Provision the stable operator admin ('analyst') the build never rewrites:
       LOCAL in Phase 1, DOMAIN admin after promotion (Phase 3), re-asserted in
       Phase 4. Like break-glass, a provisioning failure counts as a phase failure. #>
    param([string]$Why)
    if (-not ($Config.Analyst -and $Config.Analyst.Enabled)) {
        Write-RangeLog 'Analyst account disabled in config -- skipping stable operator admin.' 'WARN'
        return
    }
    Write-RangeLog "---- analyst admin ($Why) ----" 'WARN'
    try { & (Join-Path $LocalRoot 'scripts\01-analyst-admin.ps1') -FromBuild }
    catch { Write-RangeLog "Analyst provisioning threw: $($_.Exception.Message)" 'ERROR' }

    $u = $Config.Analyst.User
    if ((Test-IsDomainController) -and -not (Test-AdQueryable)) {
        Write-RangeLog "Cannot verify analyst admin '$u': ACTIVE DIRECTORY IS UNREACHABLE (ADWS down / no DC located). Fix AD first -- every AD-dependent step this phase will fail for the same reason." 'ERROR'
        $script:PhaseFailures++
        return
    }
    $exists = if (Test-IsDomainController) {
        [bool](Get-ADUser -Filter "SamAccountName -eq '$u'" -ErrorAction SilentlyContinue)
    } else {
        [bool](Get-LocalUser -Name $u -ErrorAction SilentlyContinue)
    }
    if (-not $exists) {
        Write-RangeLog "Analyst admin '$u' does NOT exist after provisioning." 'ERROR'
        $script:PhaseFailures++
    } else {
        Write-RangeLog "Analyst admin '$u' present." 'OK'
    }
}
function Wait-ForAd {
    # F28: the #1 cause of the Phase-3 wipeout ("Unable to find a default server
    # with Active Directory Web Services running") is a DC that resolves DNS via an
    # upstream/NAT server instead of ITSELF -- it then cannot resolve its own SRV
    # records, ADWS/Get-ADDomain fail, and all seven AD steps die. A DC must be its
    # own DNS client. Repair that once, up front, before waiting.
    try {
        $ipv4 = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count }
        if (-not ($ipv4 | Where-Object { $_.ServerAddresses -contains '127.0.0.1' })) {
            $idx = (Get-NetIPConfiguration -ErrorAction SilentlyContinue |
                    Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up' } |
                    Select-Object -First 1).InterfaceIndex
            if ($idx) {
                Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses '127.0.0.1' -ErrorAction SilentlyContinue
                & ipconfig /flushdns | Out-Null
                Write-RangeLog 'Repaired DC DNS client -> 127.0.0.1 (a DC must resolve via itself, or ADWS never answers).' 'WARN'
            }
        }
    } catch {}
    Write-RangeLog 'Waiting for AD DS (ADWS) to come up...'
    for ($i = 0; $i -lt 60; $i++) {
        try { Start-Service NTDS,ADWS,DNS,Netlogon -ErrorAction SilentlyContinue } catch {}
        try {
            if ((Get-Service ADWS -ErrorAction SilentlyContinue).Status -eq 'Running') {
                Import-Module ActiveDirectory -ErrorAction Stop
                Get-ADDomain -ErrorAction Stop | Out-Null
                Write-RangeLog 'AD is ready.' 'OK'; return $true
            }
        } catch {}
        Start-Sleep -Seconds 10
    }
    # F27: this used to warn and fall through, so every AD-dependent step then
    # failed one by one with "Unable to find a default server with Active Directory
    # Web Services running" -- seven confusing errors instead of one clear cause.
    # AD being down is a hard stop for Phase 3; there is nothing useful to do next.
    Write-RangeLog 'AD DID NOT COME UP in ~10 min. ADWS is not answering, so every AD step this phase would fail.' 'ERROR'
    Write-RangeLog 'Diagnose before re-running:' 'WARN'
    Write-RangeLog '   Get-Service ADWS,NTDS,DNS,Netlogon | Select Name,Status,StartType' 'WARN'
    Write-RangeLog ("   nltest /dsgetdc:" + $Config.DC.DomainName) 'WARN'
    Write-RangeLog '   Get-DnsClientServerAddress -AddressFamily IPv4      # a DC must point at ITSELF (127.0.0.1)' 'WARN'
    Write-RangeLog '   Get-WinEvent -LogName "Directory Service" -MaxEvents 20' 'WARN'
    $script:PhaseFailures++
    return $false
}

# ═══ PHASE 1: machine-level misconfigurations ═════════════════════════════
if ([int]$state.Phase -le 1) {
    Write-RangeLog '==== PHASE 1: machine-level misconfigurations ====' 'WARN'
    # FIRST, before a single thing is weakened. The dangerous window opens at the
    # reboot at the end of this phase; the seeded *-backup admins do not arrive
    # until Phase 3, which is exactly why the field lockout had no way out (F2).
    Invoke-BreakGlass 'pre-weakening, local account'
    Invoke-Analyst    'pre-weakening, local account'
    $plan = [ordered]@{
        UpdatesDefender    = 'scripts\10-updates-defender.ps1'
        CredentialExposure = 'scripts\20-credential-exposure.ps1'
        UacLsaVbs          = 'scripts\30-uac-lsa-vbs.ps1'
        SmbNetwork         = 'scripts\40-smb-network.ps1'
        RdpWinrm           = 'scripts\50-rdp-winrm.ps1'
        LoggingVisibility  = 'scripts\60-logging-visibility.ps1'
        LegacyServices     = 'scripts\70-legacy-services.ps1'
        Persistence        = 'scripts\80-persistence.ps1'
    }
    foreach ($k in $plan.Keys) {
        if ($Config.Categories[$k]) { Invoke-Step $plan[$k] } else { Write-RangeLog "skip $k (disabled in config)" }
    }
    Invoke-Step 'scripts\75-cve-repro.ps1'   # PrintNightmare / HiveNightmare artifacts

    # Operator break-glass + persistence artifact: SYSTEM shell at the logon screen.
    # HKLM-only, so it survives the promotion reboot and guarantees a no-password
    # recovery path if any account login fails.
    if ($Config.AccessibilityShell) { Invoke-Step 'scripts\05-accessibility-shell.ps1' }

    # Operator keeper: run once now (drops C:\range-fix.cmd, disables lockout,
    # asserts 'analyst') and register the PERMANENT boot task so analyst self-heals
    # on every reboot -- the decisive end to the recurring lockouts.
    if ($Config.OperatorKeeper) { Invoke-Step 'scripts\02-operator-keeper.ps1'; Register-KeeperTask }

    if ($Config.RemoveDefenderFeature) {
        Write-RangeLog 'Uninstalling Windows-Defender feature (settles on the upcoming reboot).' 'WARN'
        try { Uninstall-WindowsFeature Windows-Defender -ErrorAction Stop | Out-Null } catch { Write-RangeLog "Defender removal: $($_.Exception.Message)" 'WARN' }
    }
    if ($Config.DC.Enabled -and -not (Test-IsDomainController)) {
        Write-RangeLog 'Pre-installing AD DS role + tools so promotion is reboot-ready next phase.' 'WARN'
        try { Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools -ErrorAction Stop | Out-Null } catch { Write-RangeLog "AD DS role: $($_.Exception.Message)" 'WARN' }
    }

    if (-not (Test-PhaseClean 1)) { return }

    # ── WP2 / F16: golden-image checkpoint ────────────────────────────────
    #    In Image mode the build STOPS here, unpromoted. That is the whole fix
    #    for F16: an image cut after promotion gives every clone the same domain
    #    SID and the same krbtgt, so a golden ticket forged on one student's VM
    #    is valid on every other student's VM. Cut it here instead and let each
    #    clone promote its own forest -- unique domain SID and krbtgt then come
    #    for free. Deliberately does NOT register the resume task: this image
    #    must not promote itself on next boot.
    if ($Mode -eq 'Image') {
        $state.Phase = 2; Save-State $state
        @"
GOLDEN IMAGE READY (unpromoted)  -  $(Get-Date -Format s)  -  $env:COMPUTERNAME

Phase 1 is applied and the AD DS role is staged. This host is deliberately NOT a
domain controller, and will not promote itself on reboot.

NEXT STEPS
  1. (Recommended) sysprep /generalize /oobe /shutdown so each clone gets its own
     machine SID and install id. If sysprep fails on this weakened image, clone
     anyway -- the credential isolation that matters comes from per-clone
     promotion, not from sysprep.
  2. Snapshot / export this VM as the golden image.
  3. Clone it per participant.
  4. On EACH clone, as a range administrator:
         C:\CyberRange\Initialize-RangeClone.ps1 -CloneId <nn>
     That names it, derives its own operator secrets, and starts its own
     promotion into r<nn>.range.lab.

DO NOT promote this image before cloning. That reintroduces F16.
"@ | Set-Content -Path (Join-Path $StateDir 'IMAGE-READY.txt') -Encoding UTF8
        Protect-RangePath -Path $StateDir
        Write-RangeLog '==== IMAGE MODE: Phase 1 complete, stopping BEFORE promotion (F16). ====' 'OK'
        Write-RangeLog "Marker: $(Join-Path $StateDir 'IMAGE-READY.txt')" 'OK'
        Write-RangeLog 'Sysprep + snapshot + clone, then run Initialize-RangeClone.ps1 on each clone.' 'WARN'
        return
    }

    $state.Phase = 2; Save-State $state
    Register-ResumeTask
    Write-RangeLog '==== PHASE 1 done. Rebooting to settle LSA/VBS/PPL + features; will auto-resume. ====' 'OK'
    Write-ResumeHint
    Start-Sleep -Seconds 3
    Restart-Computer -Force
    return
}

# ═══ PHASE 2: DC promotion ════════════════════════════════════════════════
if ([int]$state.Phase -eq 2) {
    if (-not $Config.DC.Enabled) {
        Write-RangeLog 'DC.Enabled = $false; skipping promotion.' 'INFO'
        $state.Phase = 3; Save-State $state
    }
    elseif (Test-IsDomainController) {
        Write-RangeLog 'Host is now a Domain Controller; promotion complete.' 'OK'
        $state.Phase = 3; Save-State $state
    }
    else {
        Write-RangeLog '==== PHASE 2: promoting to Domain Controller ====' 'WARN'
        if (-not (Get-Module -ListAvailable -Name ADDSDeployment)) {
            Write-RangeLog 'AD DS tools still missing after reboot; cannot promote unattended.' 'ERROR'
            Write-RangeLog 'Resume task left in place. Fix servicing, then reboot to retry, or run scripts\dc\00-promote-dc.ps1 manually.' 'WARN'
            return
        }
        $state.PromoteTries = [int]$state.PromoteTries + 1; Save-State $state
        if ([int]$state.PromoteTries -gt 3) {
            Write-RangeLog 'Promotion attempted 3x without success; stopping to avoid a reboot loop. Run scripts\dc\00-promote-dc.ps1 by hand.' 'ERROR'
            Unregister-ResumeTask; return
        }
        Register-ResumeTask
        $promoted = Invoke-Step 'scripts\dc\00-promote-dc.ps1'   # on success Install-ADDSForest reboots automatically
        if (-not $promoted) {
            # F29: a PREREQUISITE failure is not fixed by rebooting -- do not force a
            # reboot loop. Stop so the operator can read the detailed prereq reasons
            # the promote script logged (domain-joined already, pending reboot, DNS,
            # name conflict, ...) and fix the actual cause.
            Write-RangeLog 'Promotion FAILED -- see the prerequisite detail logged just above. NOT rebooting (a reboot does not clear a prerequisite failure). Fix the cause, then re-run .\Setup-CyberRange.ps1.' 'ERROR'
            Write-RangeLog 'If the only blocker was a PENDING REBOOT, reboot once by hand -- the resume task will retry promotion automatically.' 'WARN'
            return
        }
        # Only reached if Install-ADDSForest returned WITHOUT rebooting (unusual).
        Write-RangeLog 'Promotion returned without an automatic reboot; forcing one to continue.' 'WARN'
        Write-ResumeHint
        Start-Sleep -Seconds 5
        Restart-Computer -Force
        return
    }
}

# ═══ PHASE 3: attack-path seeding ═════════════════════════════════════════
if ([int]$state.Phase -eq 3) {
    Write-RangeLog '==== PHASE 3: attack-path seeding ====' 'WARN'
    $script:PhaseFailures = 0
    if (Test-IsDomainController) {
        # Hard gate: if AD never came up there is no point running seven AD steps
        # that will each fail with the same underlying cause (F27).
        if (-not (Wait-ForAd)) {
            if (-not (Test-PhaseClean 3)) { return }
        }

        # F31: relax the domain password policy BEFORE seeding anything. The DEFAULT
        # policy (complexity on, min length 7, and "password must not contain the
        # account name") rejects the intentionally-weak roast passwords in dc\10 --
        # e.g. helpdesk / 'Helpdesk@1' contains its own SamAccountName. dc\40
        # re-asserts this later; doing it first just lets the weak seeds take.
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot `
                -ComplexityEnabled $false -MinPasswordLength 4 -MinPasswordAge '0.00:00:00' `
                -PasswordHistoryCount 0 -ErrorAction Stop
            Write-RangeLog 'Relaxed domain password policy (complexity off, min len 4) so weak seeded passwords are accepted (F31).' 'WARN'
        } catch { Write-RangeLog "Could not relax password policy before seeding: $($_.Exception.Message)" 'WARN' }

        # Promotion destroyed the local SAM, so the Phase-1 local break-glass
        # account is gone. Re-create it as a DOMAIN account before anything else.
        Invoke-BreakGlass 'post-promotion, domain account'
        Invoke-Analyst    'post-promotion, domain account'

        # Re-assert autologon: DefaultDomainName has to change from '.' to the
        # NetBIOS name now that Administrator is a domain principal, and the
        # credential is re-validated against the domain. Idempotent; every write
        # in that script is a forced registry set (F1).
        Invoke-Step 'scripts\20-credential-exposure.ps1'

        # dc\60 runs LAST: it pushes the SMB-signing / NoLMHash / log-size
        # downgrades into the Default Domain Controllers Policy and ends with
        # gpupdate /force. Anything after it that writes those same registry
        # values locally would just be re-reverted by the next refresh (F33).
        foreach ($s in 'scripts\dc\10-ad-users-roast.ps1','scripts\dc\20-adcs-esc1.ps1',
                       'scripts\dc\30-acl-delegation.ps1','scripts\dc\40-gpo-legacy.ps1',
                       'scripts\dc\50-hidden-domain-admins.ps1','scripts\dc\60-dc-security-gpo.ps1') { Invoke-Step $s }
    } else {
        # Local hidden admins are only meaningful on a non-DC. Honour the config
        # toggle -- Categories.HiddenAccounts was previously read nowhere (F2).
        if ($Config.Categories.HiddenAccounts) { Invoke-Step 'scripts\90-hidden-accounts.ps1' }
        else { Write-RangeLog 'skip HiddenAccounts (disabled in config)' }
    }
    if (-not (Test-PhaseClean 3)) { return }
    $state.Phase = 4; Save-State $state
}

# ═══ PHASE 4: finalize ════════════════════════════════════════════════════
if ([int]$state.Phase -ge 4) {
    Write-RangeLog '==== PHASE 4: finalize ====' 'WARN'
    Unregister-ResumeTask
    # Final guarantee: the stable operator admin exists no matter what happened in
    # earlier phases. Idempotent; validated inside the script.
    Invoke-Analyst 'final assert'
    # F35 catch-all: any phase may have run a servicing operation (AD CS role,
    # SNMP capability, TFTP/PSv2 features) and the servicing stack re-enables
    # wuauserv behind us. Re-assert before the range is declared ready.
    Disable-RangeUpdateServices -Because 'Phase 4 finalize'
    # NOTE: Protect-RangePath is deliberately the LAST thing in this phase (F27).
    # It used to run here, before READY.txt and Save-State -- which meant the
    # build locked itself out of $StateDir and then failed to record Phase 99,
    # leaving the run stuck re-executing Phase 4 forever.
    # F27/item5: the READY marker itself must state the outcome. A -Force run over a
    # failing phase must NOT leave a file that looks like a clean, hand-out-ready box.
    $statusLine = if ($script:BuildHadFailures) {
        'STATUS: *** BUILD FINISHED WITH FAILURES -- NOT READY TO CLONE OR HAND OUT. *** One or more phases had failed steps and were forced past (-Force). Run Test-RangeConfig.ps1 and fix the FAIL rows first.'
    } else {
        'STATUS: build completed cleanly.'
    }
    @"
Cyber range setup COMPLETE  -  $(Get-Date -Format s)  -  $env:COMPUTERNAME
Build log: $($env:RANGE_LOGFILE)
$statusLine

This machine is INTENTIONALLY VULNERABLE for authorized red-vs-blue training.

OPERATOR NOTES (not for participants)
  Log in as:           $(if ($Config.Analyst -and $Config.Analyst.Enabled) { "$($Config.Analyst.User)  ($(if($Config.DC.Enabled){'Domain Admins'}else{'local Administrators'}))" } else { '(Analyst disabled)' })
  Break-glass account: $(if ($Config.BreakGlass -and $Config.BreakGlass.Enabled) { $Config.BreakGlass.User } else { '(none -- BreakGlass disabled)' })
  NOTE: the built-in Administrator password is set to LocalAdminAutoLogonPass by
  the build (the exposed-credential lesson). Use the analyst account for your own
  stable login -- the build never rewrites it.
  Recovery runbook:    docs\BREAK-GLASS.md
  F19: the change manifest and the staged config hold every seeded password in
  cleartext -- they are the ANSWER KEY, not an after-action handout. They live
  under ACL-locked paths (SYSTEM + Administrators only). Do NOT relax those ACLs
  and do NOT give the manifest to a participant; collect it off-box for review.
"@ | Set-Content -Path $ReadyFile -Encoding UTF8
    $state.Phase = 99; Save-State $state

    # F3/F27: lock the ANSWER-KEY directory only now that every write is done.
    # The staged tree ($LocalRoot) is left on inherited permissions on purpose --
    # see the note after staging.
    Protect-RangePath -Path $StateDir

    if ($script:BuildHadFailures) {
        Write-RangeLog "==== BUILD FINISHED WITH FAILURES. Marker: $ReadyFile ====" 'ERROR'
        Write-RangeLog 'This VM is NOT ready to hand out: one or more phases had failed steps and were forced past.' 'ERROR'
        Write-RangeLog 'Run .\Test-RangeConfig.ps1 and fix the FAIL rows before cloning.' 'WARN'
    } else {
        Write-RangeLog "==== RANGE READY. Marker: $ReadyFile ====" 'OK'
        Write-RangeLog 'Safe to hand this VM to the participant.' 'OK'
    }
}
