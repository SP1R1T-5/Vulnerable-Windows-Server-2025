#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    ONE-SHOT unattended builder for the Windows Server 2025 cyber range.

.DESCRIPTION
    Run this ONCE, as Administrator, and walk away. It:
      1. Stages the range files to a LOCAL path (C:\CyberRange) so the reboot-
         resume task still works even though you launched from a mapped drive.
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

    Progress is tracked in C:\ProgramData\CyberRange\setup-state.json and the run
    auto-resumes after each reboot via a SYSTEM scheduled task, so no babysitting.
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

# ── 0. Stage to a LOCAL path ──────────────────────────────────────────────
#    Mapped/removable drives (Y:\, USB) are NOT present for the SYSTEM resume
#    task at boot, so everything must run from a fixed local directory.
if ($PSScriptRoot.TrimEnd('\') -ine $LocalRoot.TrimEnd('\')) {
    Write-Host "Staging range files to $LocalRoot ..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $LocalRoot -Force | Out-Null
    Copy-Item -Path (Join-Path $PSScriptRoot '*') -Destination $LocalRoot -Recurse -Force
    Get-ChildItem $LocalRoot -Recurse -File | Unblock-File -ErrorAction SilentlyContinue  # strip mark-of-the-web
    # F3: the staged tree contains range.config.psd1 -- DSRM, autologon and
    # hidden-admin passwords in cleartext. C:\ grants BUILTIN\Users
    # ReadAndExecute by inheritance, so lock it before anything else runs.
    & icacls.exe $LocalRoot /inheritance:r /grant 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' /T /C 2>&1 | Out-Null
    Write-Host "Relaunching from $LocalRoot ..." -ForegroundColor Yellow
    $fwd = @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $LocalRoot 'Setup-CyberRange.ps1'))
    if ($Force) { $fwd += '-Force' }
    & powershell.exe @fwd
    return
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

if ([int]$state.Phase -ge 99) {
    Write-RangeLog 'Setup already completed (state = done). Nothing to do.' 'OK'
    return
}

Assert-RangeSafety -Config $Config
Write-RangeLog "==== One-shot range setup on $env:COMPUTERNAME (phase $($state.Phase)$(if($Resume){', resumed'})) ====" 'WARN'

# ── Task + helper functions ───────────────────────────────────────────────
function Register-ResumeTask {
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                 -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$LocalRoot\Setup-CyberRange.ps1`" -Resume"
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Write-RangeLog "Resume task '$TaskName' registered (SYSTEM, at startup)."
}
function Unregister-ResumeTask {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-RangeLog "Resume task '$TaskName' removed."
}
$script:PhaseFailures = 0
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
       account does not survive). Never fatal to the build. #>
    param([string]$Why)
    if (-not ($Config.BreakGlass -and $Config.BreakGlass.Enabled)) {
        Write-RangeLog 'BreakGlass disabled in config -- building with NO operator recovery account.' 'WARN'
        return
    }
    Write-RangeLog "---- break-glass ($Why) ----" 'WARN'
    try { & (Join-Path $LocalRoot 'scripts\00-break-glass.ps1') -Apply -FromBuild }
    catch { Write-RangeLog "Break-glass provisioning failed: $($_.Exception.Message)" 'ERROR' }
}
function Wait-ForAd {
    Write-RangeLog 'Waiting for AD DS (ADWS) to come up...'
    for ($i = 0; $i -lt 60; $i++) {
        try {
            if ((Get-Service ADWS -ErrorAction SilentlyContinue).Status -eq 'Running') {
                Import-Module ActiveDirectory -ErrorAction Stop
                Get-ADDomain -ErrorAction Stop | Out-Null
                Write-RangeLog 'AD is ready.' 'OK'; return
            }
        } catch {}
        Start-Sleep -Seconds 10
    }
    Write-RangeLog 'AD did not report ready in ~10 min; DC seeding may partially fail.' 'WARN'
}

# ═══ PHASE 1: machine-level misconfigurations ═════════════════════════════
if ([int]$state.Phase -le 1) {
    Write-RangeLog '==== PHASE 1: machine-level misconfigurations ====' 'WARN'
    # FIRST, before a single thing is weakened. The dangerous window opens at the
    # reboot at the end of this phase; the seeded *-backup admins do not arrive
    # until Phase 3, which is exactly why the field lockout had no way out (F2).
    Invoke-BreakGlass 'pre-weakening, local account'
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

    if ($Config.RemoveDefenderFeature) {
        Write-RangeLog 'Uninstalling Windows-Defender feature (settles on the upcoming reboot).' 'WARN'
        try { Uninstall-WindowsFeature Windows-Defender -ErrorAction Stop | Out-Null } catch { Write-RangeLog "Defender removal: $($_.Exception.Message)" 'WARN' }
    }
    if ($Config.DC.Enabled -and -not (Test-IsDomainController)) {
        Write-RangeLog 'Pre-installing AD DS role + tools so promotion is reboot-ready next phase.' 'WARN'
        try { Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools -ErrorAction Stop | Out-Null } catch { Write-RangeLog "AD DS role: $($_.Exception.Message)" 'WARN' }
    }

    if (-not (Test-PhaseClean 1)) { return }

    $state.Phase = 2; Save-State $state
    Register-ResumeTask
    Write-RangeLog '==== PHASE 1 done. Rebooting to settle LSA/VBS/PPL + features; will auto-resume. ====' 'OK'
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
        Invoke-Step 'scripts\dc\00-promote-dc.ps1'   # Install-ADDSForest reboots automatically
        Write-RangeLog 'Promotion returned without an automatic reboot; forcing one to continue.' 'WARN'
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
        Wait-ForAd

        # Promotion destroyed the local SAM, so the Phase-1 local break-glass
        # account is gone. Re-create it as a DOMAIN account before anything else.
        Invoke-BreakGlass 'post-promotion, domain account'

        # Re-assert autologon: DefaultDomainName has to change from '.' to the
        # NetBIOS name now that Administrator is a domain principal, and the
        # credential is re-validated against the domain. Idempotent; every write
        # in that script is a forced registry set (F1).
        Invoke-Step 'scripts\20-credential-exposure.ps1'

        foreach ($s in 'scripts\dc\10-ad-users-roast.ps1','scripts\dc\20-adcs-esc1.ps1',
                       'scripts\dc\30-acl-delegation.ps1','scripts\dc\40-gpo-legacy.ps1',
                       'scripts\dc\50-hidden-domain-admins.ps1') { Invoke-Step $s }
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
    # F3: re-assert the lockdown. Later phases created new files (manifest rows,
    # READY.txt, the break-glass card) and the DC scripts may have reset ACLs.
    Protect-RangePath -Path $StateDir
    Protect-RangePath -Path $LocalRoot
    @"
Cyber range setup COMPLETE  -  $(Get-Date -Format s)  -  $env:COMPUTERNAME
Log:      $($env:RANGE_LOGFILE)
Manifest: $($env:RANGE_MANIFEST)

This machine is INTENTIONALLY VULNERABLE for red-vs-blue training.
Hand it to the participant. Blue team: the manifest above lists every change.

OPERATOR NOTES
  Break-glass account: $(if ($Config.BreakGlass -and $Config.BreakGlass.Enabled) { $Config.BreakGlass.User } else { '(none -- BreakGlass disabled)' })
  Recovery runbook:    docs\BREAK-GLASS.md
  The log/manifest directory and $LocalRoot are ACL-restricted to SYSTEM +
  Administrators: they contain every seeded password in cleartext. Do NOT
  relax those ACLs or participants can read the answer key.
"@ | Set-Content -Path $ReadyFile -Encoding UTF8
    $state.Phase = 99; Save-State $state
    Write-RangeLog "==== RANGE READY. Marker: $ReadyFile ====" 'OK'
    Write-RangeLog 'Safe to hand this VM to the participant.' 'OK'
}
