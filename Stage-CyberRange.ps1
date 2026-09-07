#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    FIRST-RUN bootstrapper for the Windows Server 2025 cyber range.

.DESCRIPTION
    Stage 1 of a two-stage setup. Run this ONCE, elevated, from wherever the repo
    lives (a mapped share like Y:\, a USB stick, etc.). It:

      1. Copies the whole range to a fixed LOCAL path, C:\CyberRange. This is
         required: the SYSTEM auto-resume task that drives the build across
         reboots runs at boot, before any user logs on, and mapped/removable
         drives do not exist in that context. Everything must run from local disk.
      2. Heals any stale/mangled ACL on a previous C:\CyberRange (e.g. a manual
         `icacls Everyone:F` workaround) so the copy succeeds.
      3. Strips mark-of-the-web from the copied files.
      4. Hands off to Stage 2 -- C:\CyberRange\Setup-CyberRange.ps1 -- which runs
         the actual build (phases, reboots, auto-resume) from the local copy.

    It does NOT lock the ACL or weaken anything itself; the engine does that once
    it is safely running locally. FOR ISOLATED, AUTHORIZED EDUCATIONAL USE ONLY.

.PARAMETER Force
    Passed through to Setup-CyberRange.ps1: advance past a phase that had failed
    steps instead of stopping (finding F7). Also lets the build run with the
    shipped placeholder credentials for an off-network dry run (F20).

.PARAMETER Continue
    Proceed even though a previous build's state exists -- the engine picks up at
    the recorded phase instead of starting at Phase 1. Use this to carry on after
    a failed/interrupted run on the SAME box.

.PARAMETER Fresh
    Clear the previous build's BOOKKEEPING (setup-state.json, READY.txt, the
    resume task) so the engine starts again at Phase 1.
    This does NOT undo anything the previous run already did to the machine --
    no misconfiguration is reverted, no account is removed. Starting Phase 1 over
    on an already-weakened box is usually the wrong move; the clean way to
    re-build is to revert the VM snapshot. Use -Fresh only when you know the
    previous run changed nothing meaningful.

.EXAMPLE
    .\Stage-CyberRange.ps1
    Stage locally and start the build.

.EXAMPLE
    .\Stage-CyberRange.ps1 -Continue
    Re-stage updated scripts, then carry on from the recorded phase.
#>
[CmdletBinding()]
param([switch]$Force, [switch]$Continue, [switch]$Fresh,
      [ValidateSet('AllInOne','Image')][string]$Mode = 'AllInOne')

$ErrorActionPreference = 'Stop'
$LocalRoot = 'C:\CyberRange'
$src       = $PSScriptRoot
$StateDir  = Join-Path $env:ProgramData 'CyberRange'
$StateFile = Join-Path $StateDir 'setup-state.json'
$ReadyFile = Join-Path $StateDir 'READY.txt'
$TaskName  = 'CyberRangeSetup'

if ($src.TrimEnd('\') -ieq $LocalRoot.TrimEnd('\')) {
    Write-Host "Already at $LocalRoot; skipping copy." -ForegroundColor Yellow
}
else {
    Write-Host "Staging range files to $LocalRoot ..." -ForegroundColor Yellow
    if (Test-Path $LocalRoot) {
        # Heal any prior/mangled ACL from earlier runs (a manual Everyone:F, or a
        # SYSTEM+Administrators lock a previous build applied) so the copy and the
        # engine can read the tree. Take ownership first -- an over-locked dir can
        # otherwise refuse the reset. Going forward the engine never locks this
        # tree, so there is normally nothing to heal.
        & takeown.exe /F $LocalRoot /R /D Y 2>&1 | Out-Null
        & icacls.exe $LocalRoot /reset /T /C 2>&1 | Out-Null
    }
    New-Item -ItemType Directory -Path $LocalRoot -Force | Out-Null
    Copy-Item -Path (Join-Path $src '*') -Destination $LocalRoot -Recurse -Force
    Get-ChildItem $LocalRoot -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
    Write-Host "Staged." -ForegroundColor Green
}

$setup = Join-Path $LocalRoot 'Setup-CyberRange.ps1'
if (-not (Test-Path $setup)) {
    throw "Setup-CyberRange.ps1 not found at '$setup' after staging. Is the repo layout intact?"
}
Write-Host ("Staged files: " + (Get-ChildItem $LocalRoot -Recurse -File).Count) -ForegroundColor Gray

# ── F32: refuse to silently inherit a previous build's state ──────────────
#    Staging copies files; it does NOT reset the build's progress, which lives in
#    C:\ProgramData\CyberRange. So on a box that has been built before, this
#    "first-run bootstrapper" hands off to an engine that either announces
#    "Setup already completed. Nothing to do." (Phase 99) and exits -- looking
#    exactly like Stage did nothing -- or silently jumps into DC promotion / AD
#    seeding at the recorded phase on a box the operator believes is starting
#    fresh. Make the operator choose.
$priorPhase = $null
$stateUnreadable = $false
if (Test-Path $StateFile) {
    try { $priorPhase = (Get-Content $StateFile -Raw -ErrorAction Stop | ConvertFrom-Json).Phase }
    catch { $stateUnreadable = $true }
}
$priorTask = [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)

if ($null -ne $priorPhase -or $stateUnreadable -or (Test-Path $ReadyFile) -or $priorTask) {
    Write-Host ""
    Write-Host "PREVIOUS BUILD STATE DETECTED on this host:" -ForegroundColor Yellow
    if ($stateUnreadable)      { Write-Host "  - setup-state.json exists but is NOT READABLE (ACL). Reclaim it:" -ForegroundColor Red
                                 Write-Host "      takeown /f $StateDir /r /d y" -ForegroundColor Yellow
                                 Write-Host "      icacls $StateDir /reset /T /C" -ForegroundColor Yellow }
    elseif ($null -ne $priorPhase) {
        Write-Host "  - recorded PHASE $priorPhase$(if ([int]$priorPhase -ge 99) { '  (99 = finished: the engine will do NOTHING)' })" -ForegroundColor Yellow
    }
    if (Test-Path $ReadyFile) { Write-Host "  - READY.txt present (a build completed here before)" -ForegroundColor Yellow }
    if ($priorTask)           { Write-Host "  - resume task '$TaskName' still registered" -ForegroundColor Yellow }

    if ($Fresh) {
        Write-Host ""
        Write-Host "-Fresh: clearing build BOOKKEEPING only. Nothing already applied to this" -ForegroundColor Red
        Write-Host "machine is being undone -- if the previous run weakened the box, it stays" -ForegroundColor Red
        Write-Host "weakened. Reverting the VM snapshot is the clean way to rebuild." -ForegroundColor Red
        Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
        Remove-Item $ReadyFile -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Cleared. The engine will start at Phase 1. (Logs/manifest kept as the audit trail.)" -ForegroundColor Green
    }
    elseif ($Continue) {
        Write-Host ""
        Write-Host "-Continue: handing off; the engine resumes at the recorded phase." -ForegroundColor Green
    }
    else {
        throw ("This host already has build state (above), and staging does not reset it. " +
               "Nothing has been handed off yet.`n`n" +
               "  Carry on from where it stopped :  .\Stage-CyberRange.ps1 -Continue`n" +
               "  Start the phases over           :  .\Stage-CyberRange.ps1 -Fresh   (bookkeeping only -- does NOT unweaken the box)`n" +
               "  Clean rebuild (recommended)     :  revert the VM snapshot, then re-run this script`n`n" +
               "Just continuing the build after a reboot? Use  C:\CyberRange\Resume-CyberRange.ps1  instead.")
    }
}

Write-Host "Handing off to Setup-CyberRange.ps1 (the build engine) ..." -ForegroundColor Yellow
# Fresh elevated child, ExecutionPolicy Bypass, so a Restricted policy on the box
# cannot block the engine. The child inherits this session's elevation.
$fwd = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$setup)
if ($Force) { $fwd += '-Force' }
if ($Mode -ne 'AllInOne') { $fwd += @('-Mode',$Mode) }
& powershell.exe @fwd
exit $LASTEXITCODE
