#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    Manual / partial orchestrator for the cyber range. No reboots, no state
    machine, no scheduled tasks.

.DESCRIPTION
    Setup-CyberRange.ps1 is the one-shot builder: it stages, phases, reboots and
    auto-resumes. This script is the surgical alternative -- it applies whichever
    categories you name, in place, and returns. Use it to:

      * re-apply one category after changing the config,
      * repair a specific area on a box that is already built,
      * apply the machine-level categories without triggering DC promotion,
      * seed the DC scenarios by hand after promoting manually.

    It shares the config, module, log and manifest with the one-shot builder, so
    changes still land in the same answer key.

    It does NOT create the break-glass account, promote a DC, or reboot. Run
    scripts\00-break-glass.ps1 yourself first -- this script warns if you have not.

    FOR ISOLATED, AUTHORIZED EDUCATIONAL USE ONLY. Requires Confirmed = $true.

.PARAMETER Only
    Category names to run. Omit to run every category enabled in the config.
    Machine-level: UpdatesDefender, CredentialExposure, UacLsaVbs, SmbNetwork,
                   RdpWinrm, LoggingVisibility, LegacyServices, Persistence,
                   CveRepro, HiddenAccounts
    Domain (DC only): DcUsers, DcAdcs, DcAcls, DcGpo, DcHiddenAdmins
    Use -List to print them without running anything.

.PARAMETER SkipDC
    Ignore the domain categories even on a promoted DC.

.PARAMETER List
    Print the category table and exit. Changes nothing.

.EXAMPLE
    .\Invoke-RangeBuild.ps1 -List

.EXAMPLE
    .\Invoke-RangeBuild.ps1 -Only SmbNetwork,Persistence

.EXAMPLE
    .\Invoke-RangeBuild.ps1 -Only CredentialExposure
    Re-apply autologon after changing LocalAdminAutoLogonPass in the config.

.EXAMPLE
    .\Invoke-RangeBuild.ps1 -SkipDC
    Every enabled machine-level category, nothing domain-related.
#>
[CmdletBinding()]
param(
    [string[]]$Only,
    [switch]$SkipDC,
    [switch]$List
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot

# Category -> script. Order matters: this is the same order Setup-CyberRange uses.
$MachineMap = [ordered]@{
    UpdatesDefender    = 'scripts\10-updates-defender.ps1'
    CredentialExposure = 'scripts\20-credential-exposure.ps1'
    UacLsaVbs          = 'scripts\30-uac-lsa-vbs.ps1'
    SmbNetwork         = 'scripts\40-smb-network.ps1'
    RdpWinrm           = 'scripts\50-rdp-winrm.ps1'
    LoggingVisibility  = 'scripts\60-logging-visibility.ps1'
    LegacyServices     = 'scripts\70-legacy-services.ps1'
    CveRepro           = 'scripts\75-cve-repro.ps1'
    Persistence        = 'scripts\80-persistence.ps1'
    HiddenAccounts     = 'scripts\90-hidden-accounts.ps1'
}
$DcMap = [ordered]@{
    DcUsers        = 'scripts\dc\10-ad-users-roast.ps1'
    DcAdcs         = 'scripts\dc\20-adcs-esc1.ps1'
    DcAcls         = 'scripts\dc\30-acl-delegation.ps1'
    DcGpo          = 'scripts\dc\40-gpo-legacy.ps1'
    DcHiddenAdmins = 'scripts\dc\50-hidden-domain-admins.ps1'
}
# CveRepro has no config toggle in Setup-CyberRange either; it always runs.
$AlwaysOn = @('CveRepro')

if ($List) {
    Write-Host ""
    Write-Host "Machine-level categories:" -ForegroundColor Cyan
    $MachineMap.Keys | ForEach-Object { Write-Host ("  {0,-20} {1}" -f $_, $MachineMap[$_]) }
    Write-Host ""
    Write-Host "Domain categories (promoted DC only):" -ForegroundColor Cyan
    $DcMap.Keys | ForEach-Object { Write-Host ("  {0,-20} {1}" -f $_, $DcMap[$_]) }
    Write-Host ""
    Write-Host "Promotion is NOT a category. Run scripts\dc\00-promote-dc.ps1 by hand (it reboots)." -ForegroundColor Yellow
    return
}

Import-Module (Join-Path $Root 'modules\RangeCommon.psm1') -Force
$Config = Import-PowerShellDataFile (Join-Path $Root 'config\range.config.psd1')
Initialize-RangeContext
Assert-RangeSafety -Config $Config

$isDC = Test-IsDomainController
Write-RangeLog "==== Manual range build on $env:COMPUTERNAME (DC=$isDC) ====" 'WARN'

# Validate requested names before touching anything -- a typo should not
# half-apply a build.
$known = @($MachineMap.Keys) + @($DcMap.Keys)
if ($Only) {
    $bad = $Only | Where-Object { $_ -notin $known }
    if ($bad) {
        throw "Unknown categor$(if($bad.Count -gt 1){'ies'}else{'y'}): $($bad -join ', ').`nRun with -List to see valid names."
    }
}

# Break-glass advisory. This script is often the recovery path, so warn rather
# than block -- but do not let anyone weaken a box silently without a way back.
if ($Config.BreakGlass -and $Config.BreakGlass.Enabled) {
    $bgUser = $Config.BreakGlass.User
    $bgHere = if ($isDC) {
        try { Import-Module ActiveDirectory -ErrorAction Stop
              [bool](Get-ADUser -Filter "SamAccountName -eq '$bgUser'" -ErrorAction SilentlyContinue) } catch { $false }
    } else {
        [bool](Get-LocalUser -Name $bgUser -ErrorAction SilentlyContinue)
    }
    if (-not $bgHere) {
        Write-RangeLog "No break-glass account '$bgUser' on this host. Run scripts\00-break-glass.ps1 -Apply first." 'WARN'
    } else {
        Write-RangeLog "Break-glass account '$bgUser' present." 'OK'
    }
}

function Invoke-Category {
    param([string]$Name, [string]$Rel)
    $p = Join-Path $Root $Rel
    if (-not (Test-Path $p)) { Write-RangeLog "$Name -> $Rel MISSING; skipped." 'ERROR'; return $false }
    Write-RangeLog "---- $Name ($Rel) ----" 'WARN'
    try { & $p -Config $Config; return $true }
    catch { Write-RangeLog "$Name failed: $($_.Exception.Message)" 'ERROR'; return $false }
}

$ran = 0; $failed = 0; $skipped = @()

foreach ($name in $MachineMap.Keys) {
    if ($Only -and $name -notin $Only) { continue }
    # An explicit -Only overrides the config toggle: you asked for it by name.
    if (-not $Only -and $name -notin $AlwaysOn -and -not $Config.Categories[$name]) {
        $skipped += "$name (disabled in config)"; continue
    }
    if ($name -eq 'HiddenAccounts' -and $isDC) {
        $skipped += 'HiddenAccounts (DC has no local SAM -- use DcHiddenAdmins)'; continue
    }
    $ran++
    if (-not (Invoke-Category $name $MachineMap[$name])) { $failed++ }
}

foreach ($name in $DcMap.Keys) {
    if ($Only -and $name -notin $Only) { continue }
    if ($SkipDC)     { $skipped += "$name (-SkipDC)"; continue }
    if (-not $isDC)  { $skipped += "$name (host is not a domain controller)"; continue }
    if (-not $Only -and -not $Config.DC.Enabled) { $skipped += "$name (DC.Enabled=`$false)"; continue }
    $ran++
    if (-not (Invoke-Category $name $DcMap[$name])) { $failed++ }
}

foreach ($s in $skipped) { Write-RangeLog "skip $s" }

Write-RangeLog "==== Manual build finished: $ran run, $failed failed, $($skipped.Count) skipped ====" $(if ($failed) { 'ERROR' } else { 'OK' })
Write-RangeLog "Manifest: $($env:RANGE_MANIFEST)"
if ($failed) {
    Write-RangeLog 'Some categories failed. This script does NOT reboot -- review the log and re-run the failures.' 'WARN'
}
