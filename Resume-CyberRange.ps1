#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    Manually continue a cyber-range build after a reboot.

.DESCRIPTION
    The build normally resumes itself via the SYSTEM-at-startup task
    'CyberRangeSetup'. This script is the manual path for when it does not:
    run it in an elevated PowerShell after the box comes back up.

    It is safe to run at any point. It:
      1. Reports where the build actually is (phase, resume-task state, last log
         lines) so you can see what happened before you continue.
      2. Stops the resume task if it is stuck Running. This matters: the task is
         registered -MultipleInstances IgnoreNew, so while a hung instance is
         still "Running", every later trigger -- including Start-ScheduledTask --
         is silently ignored. A hung instance therefore blocks its own retries.
      3. Hands off to the engine with -Resume, in THIS console, where you can see
         the output and answer prompts.

    Phases are idempotent, so re-running a phase is not destructive.

.PARAMETER StatusOnly
    Report state and exit. Changes nothing, starts nothing.

.PARAMETER Force
    Passed through to the engine: advance past a phase that had failed steps,
    and allow the shipped placeholder credentials. Use only once you know what
    failed -- see docs\SETUP-GUIDE.md.

.EXAMPLE
    .\Resume-CyberRange.ps1
    Continue the build from wherever it stopped.

.EXAMPLE
    .\Resume-CyberRange.ps1 -StatusOnly
    Just tell me where the build is.
#>
[CmdletBinding()]
param([switch]$StatusOnly, [switch]$Force)

$ErrorActionPreference = 'Stop'
$LocalRoot = 'C:\CyberRange'
$TaskName  = 'CyberRangeSetup'
$StateDir  = Join-Path $env:ProgramData 'CyberRange'
$StateFile = Join-Path $StateDir 'setup-state.json'
$ReadyFile = Join-Path $StateDir 'READY.txt'
$Engine    = Join-Path $LocalRoot 'Setup-CyberRange.ps1'

function Say { param([string]$m, [string]$c = 'Gray') Write-Host $m -ForegroundColor $c }

Say ""
Say "CYBER RANGE -- MANUAL RESUME  --  $env:COMPUTERNAME  --  $(Get-Date -Format s)" 'Cyan'
Say "======================================================================" 'Cyan'

# ── Where is the build? ───────────────────────────────────────────────────
if (Test-Path $ReadyFile) {
    Say "READY.txt exists -- this build already finished." 'Green'
    Say "  $ReadyFile"
    Say "  (Re-running the engine will report 'already completed' and do nothing.)"
}

$phase = $null
if (Test-Path $StateFile) {
    try {
        $phase = (Get-Content $StateFile -Raw | ConvertFrom-Json).Phase
        Say "Build state: PHASE $phase   (99 = finished)" 'Yellow'
    } catch {
        Say "Build state: setup-state.json exists but could NOT be read: $($_.Exception.Message)" 'Red'
        Say "  If this is 'access denied', the answer-key ACL locked the build out of its own" 'Red'
        Say "  state directory. Reclaim it, elevated, then re-run this script:" 'Red'
        Say "      takeown /f $StateDir /r /d y" 'Yellow'
        Say "      icacls $StateDir /reset /T /C" 'Yellow'
    }
} else {
    Say "Build state: no setup-state.json -- the build has not started yet." 'Yellow'
    Say "  Run .\Stage-CyberRange.ps1 instead of this script." 'Yellow'
}

$role = (Get-CimInstance Win32_ComputerSystem).DomainRole
Say ("Host role:   " + $(switch ($role) {0{'standalone workstation'}2{'standalone server'}1{'member workstation'}3{'member server'}4{'backup DC'}5{'primary DC'}default{"role $role"}}))

# ── Resume-task state: the usual reason nothing happened ──────────────────
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) {
    Say "Resume task: NOT REGISTERED." 'Yellow'
    Say "  Normal after Phase 4 (the build removes it). Otherwise the build never got" 'Yellow'
    Say "  far enough to register it -- continuing manually below is the right move." 'Yellow'
} else {
    $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
    Say "Resume task: registered, State=$($task.State), LastRun=$($info.LastRunTime), LastResult=$($info.LastTaskResult)"
    if ($task.State -eq 'Running') {
        Say "  *** The resume task is STUCK RUNNING. ***" 'Red'
        Say "  It is registered -MultipleInstances IgnoreNew, so while this instance is" 'Red'
        Say "  'Running' every later trigger is ignored -- it blocks its own retries." 'Red'
    }
}

# ── Last log lines ────────────────────────────────────────────────────────
$log = Get-ChildItem (Join-Path $StateDir 'logs') -Filter 'rangebuild-*.log' -ErrorAction SilentlyContinue |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($log) {
    Say ""
    Say "Last 15 lines of $($log.Name):" 'Cyan'
    Get-Content $log.FullName -Tail 15 | ForEach-Object { Say "  $_" }
} else {
    Say "No build log found under $StateDir\logs." 'Yellow'
}
Say ""

if ($StatusOnly) { Say "-StatusOnly: nothing started." 'Cyan'; return }

# ── Clear a hung instance so it cannot block us ───────────────────────────
if ($task -and $task.State -eq 'Running') {
    Say "Stopping the stuck resume task so it cannot conflict with this run ..." 'Yellow'
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop; Start-Sleep -Seconds 2; Say "  stopped." 'Green' }
    catch { Say "  could not stop it: $($_.Exception.Message)" 'Red' }
}

if (-not (Test-Path $Engine)) {
    throw ("Build engine not found at '$Engine'. The staged copy is missing -- " +
           "re-run .\Stage-CyberRange.ps1 from the repo to restage, then try again.")
}

Say "Continuing the build (engine: $Engine) ..." 'Yellow'
Say "======================================================================" 'Cyan'
Say ""

# Run in a fresh elevated child with Bypass, exactly like Stage-CyberRange does,
# so a Restricted machine policy cannot block the engine. -Resume makes the engine
# pick up at the recorded phase.
$fwd = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$Engine,'-Resume')
if ($Force) { $fwd += '-Force' }
& powershell.exe @fwd
exit $LASTEXITCODE
