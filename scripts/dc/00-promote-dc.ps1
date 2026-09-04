#requires -Version 5.1
#requires -RunAsAdministrator
<#  DC step 0: Promote this host to the first DC of a new forest.

    RUN THIS MANUALLY, ONCE, BEFORE the DC scenario scripts. It installs AD-DS
    (+ DNS) and promotes the box, which REBOOTS the machine. After the reboot,
    log back in and run Invoke-RangeBuild.ps1 again -- the orchestrator will
    detect the DC role and run dc\10..40.

    2025 notes:
      * Forest/Domain functional level is pinned to 'WinThreshold' (Server 2016)
        on purpose: nearly every red-team AD tool (Rubeus, Certipy, impacket,
        BloodHound collectors) is validated against 2016-2022 FLs, and a brand
        new Server 2025 FL (level 10) occasionally trips older parsers. Bump it
        later with Set-ADForestMode / Set-ADDomainMode if you want to teach FL
        upgrades. Change via -ForestMode/-DomainMode below if you prefer.
      * After promotion the LOCAL Administrator becomes the DOMAIN Administrator
        and keeps its current password. Make sure LocalAdminAutoLogonPass in the
        config matches the password this box currently uses, or fix autologon
        afterwards.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Stop'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'dc-promote'

if (Test-IsDomainController) {
    Write-RangeLog 'Host is already a domain controller. Nothing to promote.' 'OK'
    return
}

$dcCfg = $Config.DC
if (-not $dcCfg.Enabled) {
    Write-RangeLog 'DC.Enabled is $false in the config. Refusing to promote. Set it to $true first.' 'WARN'
    return
}

Write-RangeLog "Installing AD-Domain-Services + DNS for forest '$($dcCfg.DomainName)'." 'WARN'
$feat = Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools
Write-RangeLog "Feature install: Success=$($feat.Success) ExitCode=$($feat.ExitCode) RestartNeeded=$($feat.RestartNeeded)"
Write-RangeManifest $cat 'install-feature' 'AD-Domain-Services;DNS' "Success=$($feat.Success);Restart=$($feat.RestartNeeded)"

# The ADDSDeployment PowerShell module ships with the AD DS management tools
# (RSAT-ADDS). On some trimmed images -IncludeManagementTools reports success
# without placing the tools, so verify and install them explicitly if missing.
if (-not (Get-Module -ListAvailable -Name ADDSDeployment)) {
    Write-RangeLog 'ADDSDeployment module not present yet; installing RSAT-ADDS explicitly.' 'WARN'
    try { Install-WindowsFeature -Name RSAT-ADDS -IncludeAllSubFeature -ErrorAction Stop | Out-Null }
    catch { Write-RangeLog "RSAT-ADDS install failed: $($_.Exception.Message)" 'WARN' }
}

# If a restart is pending, or the module still isn't on disk, the tools aren't
# usable in THIS session. Stop cleanly and tell the operator to reboot + re-run.
if ($feat.RestartNeeded -eq 'Yes' -or -not (Get-Module -ListAvailable -Name ADDSDeployment)) {
    Write-RangeLog 'AD DS tools require a restart before promotion can continue.' 'ERROR'
    Write-RangeLog "REBOOT this box, then re-run:  $PSCommandPath" 'WARN'
    return
}

Import-Module ADDSDeployment -Force
$safe = ConvertTo-SecureString $dcCfg.SafeModePassword -AsPlainText -Force

$params = @{
    DomainName                    = $dcCfg.DomainName
    DomainNetbiosName             = $dcCfg.NetbiosName
    ForestMode                    = 'WinThreshold'   # 2016 FL for broad tool compatibility
    DomainMode                    = 'WinThreshold'
    InstallDns                    = $true
    SafeModeAdministratorPassword = $safe
    NoRebootOnCompletion          = $false           # reboots to finish promotion
    Force                         = $true
}

Write-RangeManifest $cat 'promote-forest' "$($dcCfg.DomainName) / $($dcCfg.NetbiosName) (FL=WinThreshold)"
Write-RangeLog 'Promoting now. The machine WILL REBOOT. Re-run Invoke-RangeBuild.ps1 after it comes back.' 'WARN'
Install-ADDSForest @params
