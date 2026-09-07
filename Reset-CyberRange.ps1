#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    Tear down the cyber range: undo the misconfigurations and remove the artifacts.

.DESCRIPTION
    The inverse of the build, for when you want the VM back without reverting a
    snapshot. It re-hardens the machine to sane defaults and removes the range's
    accounts, persistence, shares and AD attack paths.

    DRY RUN BY DEFAULT. Nothing changes until you pass -Execute.

    READ THIS FIRST -- what a teardown CANNOT do
    ---------------------------------------------------------------------------
    This is a re-hardening pass, not a time machine. The build never captured the
    machine's prior state, so this restores KNOWN-GOOD values rather than YOUR
    old values. Several things cannot be undone at all:

      * DC PROMOTION. The domain, its SID, and krbtgt persist. -RemoveDomain will
        attempt a demotion, but a demoted DC is not a never-promoted server.
      * EXPOSED CREDENTIALS. Every seeded password, the Administrator password
        (which the build overwrote), and the DSRM password have been written to
        disk in cleartext and are in the manifest. Teardown can change them; it
        cannot un-expose them.
      * MISSING PATCHES. Windows Update was frozen for the life of the range.
        Re-enabling the service does not make the box current -- it must actually
        patch before you trust it.
      * STORED LM HASHES / CACHED CREDENTIALS from while the weakening was live.
        These clear on password change and cache rollover, not on a registry write.

    If the box is going back to anything that matters, REBUILD IT. Use this to
    reclaim a lab VM, decommission a range, or re-run a scenario from clean-ish.

    CONNECTION WARNING: re-hardening re-enables the firewall, RDP NLA and WinRM
    encryption. If you are connected over RDP or WinRM you may be disconnected
    mid-run. The Remote Desktop firewall rule is deliberately left enabled to
    reduce that risk, but run this from the console when you can.

.PARAMETER Execute
    Actually make the changes. Without it, every action is reported and skipped.

.PARAMETER Only
    Limit to categories: persistence, credentials, machine-security, network,
    logging, defenses, artifacts, accounts, dc.

.PARAMETER KeepAccounts
    Do not touch any account. Useful when you only want the machine settings back.

.PARAMETER RemoveOperatorAccounts
    Also remove 'analyst' and the break-glass account. Off by default -- these are
    YOUR way back in, and removing them while the box is still weakened is how
    people get locked out.

.PARAMETER RemoveDomain
    Attempt to demote the domain controller. Prompts for a local Administrator
    password, reboots, and is NOT equivalent to a never-promoted host.

.EXAMPLE
    .\Reset-CyberRange.ps1
    Dry run. Shows everything that would be undone.

.EXAMPLE
    .\Reset-CyberRange.ps1 -Execute
    Tear down, keeping the operator accounts and the domain.

.EXAMPLE
    .\Reset-CyberRange.ps1 -Execute -Only persistence,artifacts
    Just remove the implants and dropped files.
#>
[CmdletBinding()]
param(
    [switch]$Execute,
    [string[]]$Only,
    [switch]$KeepAccounts,
    [switch]$RemoveOperatorAccounts,
    [switch]$RemoveDomain
)

$ErrorActionPreference = 'Continue'
$RepoRoot = $PSScriptRoot
$results  = New-Object System.Collections.Generic.List[object]

Import-Module (Join-Path $RepoRoot 'modules\RangeControls.psm1') -Force

$role = (Get-CimInstance Win32_ComputerSystem).DomainRole
$isDC = $role -ge 4
$me   = [Security.Principal.WindowsIdentity]::GetCurrent().Name

$cfg = $null
$cfgPath = Join-Path $RepoRoot 'config\range.config.psd1'
if (Test-Path $cfgPath) { try { $cfg = Import-PowerShellDataFile $cfgPath } catch {} }

# ── helpers ───────────────────────────────────────────────────────────────
function Get-RegVal {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $i = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $i) { return $null }
    if ($i.GetValueNames() -notcontains $Name) { return $null }
    $i.GetValue($Name)
}
function Add-Step {
    param([string]$Category,[string]$Name,
          [ValidateSet('WOULD','DONE','SKIP','N-A','ERROR')][string]$State,
          [string]$Detail='')
    $results.Add([pscustomobject]@{ Category=$Category; Name=$Name; State=$State; Detail=$Detail })
    $c = switch ($State) { 'DONE' {'Green'} 'WOULD' {'Cyan'} 'SKIP' {'DarkGray'} 'N-A' {'Yellow'} default {'Red'} }
    Write-Host ("  {0,-6} {1,-46} {2}" -f $State, $Name, $Detail) -ForegroundColor $c
}
function Invoke-Teardown {
    <# Only acts when the range state is actually present, so a second run is a
       no-op instead of a pile of errors. #>
    param([string]$Category,[string]$Name,[scriptblock]$Needed,[scriptblock]$Action,[string]$Intended='')
    if ($Only -and ($Only -notcontains $Category)) { return }
    $need = $false
    try { $need = [bool](& $Needed) } catch { Add-Step $Category $Name 'ERROR' "check threw: $($_.Exception.Message)"; return }
    if (-not $need) { Add-Step $Category $Name 'SKIP' 'nothing to undo'; return }
    if (-not $Execute) { Add-Step $Category $Name 'WOULD' $Intended; return }
    try { & $Action; Add-Step $Category $Name 'DONE' $Intended }
    catch { Add-Step $Category $Name 'ERROR' $_.Exception.Message }
}
function Set-Reg {
    param([string]$Path,[string]$Name,[string]$Type,$Value)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction Stop | Out-Null
}
function Remove-Reg {
    param([string]$Path,[string]$Name)
    if (Test-Path -LiteralPath $Path) { Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue }
}

# ── banner + consent ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "CYBER RANGE TEARDOWN  --  $env:COMPUTERNAME  --  $(Get-Date -Format s)" -ForegroundColor Cyan
Write-Host ("Role: " + $(switch ($role) {5{'primary DC'}4{'backup DC'}3{'member server'}2{'standalone server'}default{"role $role"}})) -ForegroundColor Cyan
Write-Host ("Running as: $me") -ForegroundColor Cyan
if (-not $Execute) {
    Write-Host "DRY RUN -- nothing will be changed. Re-run with -Execute to apply." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "This restores KNOWN-GOOD defaults, not your previous values -- the build" -ForegroundColor Yellow
Write-Host "never captured them. Promotion, exposed credentials and missed patches" -ForegroundColor Yellow
Write-Host "are NOT undone. Rebuild the VM if it is going back to anything that matters." -ForegroundColor Yellow
Write-Host ""

if ($Execute) {
    $remote = $false
    try { $remote = [bool]$env:SESSIONNAME -and $env:SESSIONNAME -notlike 'Console*' } catch {}
    if ($remote) {
        Write-Host "You appear to be on a REMOTE session ($env:SESSIONNAME). Re-enabling the" -ForegroundColor Red
        Write-Host "firewall / NLA / WinRM encryption may disconnect you mid-teardown." -ForegroundColor Red
        Write-Host ""
    }
    $ans = Read-Host "Type TEARDOWN to proceed"
    if ($ans -cne 'TEARDOWN') { Write-Host "Aborted; nothing changed." -ForegroundColor Green; return }
    Write-Host ""
}

# ══ 1-7. THE CONTROL SET, reverted from the table ═════════════════════════
#    Every intentional misconfiguration is declared once in
#    modules\RangeControls.psm1 with the KNOWN-GOOD value to restore. This block
#    walks that table instead of carrying a fourth hand-written copy of it, so a
#    control added to the build is reverted here automatically.
#
#    The teardown's category names are kept (they are the -Only vocabulary and
#    they group by what an operator wants to undo, not by which script applied
#    it), and each maps to one or more table categories.
$categoryMap = [ordered]@{
    'persistence'      = @('persistence')
    'credentials'      = @('credential-exposure')
    'machine-security' = @('uac-lsa-vbs','cve-repro')
    'network'          = @('smb-network','rdp-winrm')
    'logging'          = @('logging-visibility')
    'defenses'         = @('updates-defender')
    'artifacts'        = @('legacy-services')
}

# Re-enabling the firewall can cut off a remote operator, so it goes LAST in the
# network block -- after RDP and WinRM have been re-secured, not before.
$runLast = @('fw.live.alloff')

foreach ($group in $categoryMap.Keys) {
    if ($Only -and ($Only -notcontains $group)) { continue }
    Write-Host "[$group]" -ForegroundColor Cyan

    $controls = @(Get-RangeControl -Category $categoryMap[$group] -Config $cfg)
    $ordered  = @($controls | Where-Object { $runLast -notcontains $_.Id }) +
                @($controls | Where-Object { $runLast -contains  $_.Id })

    foreach ($ctl in $ordered) {
        $needed = $false
        try { $needed = Test-RangeControlRevertNeeded -Control $ctl }
        catch { Add-Step $group $ctl.Name 'ERROR' "check threw: $($_.Exception.Message)"; continue }

        $note = Get-RangeControlRevertNote -Control $ctl
        if (-not $needed) { Add-Step $group $ctl.Name 'SKIP' 'nothing to undo'; continue }
        if (-not $Execute) { Add-Step $group $ctl.Name 'WOULD' $note; continue }
        try { $null = Reset-RangeControl -Control $ctl -Confirm:$false; Add-Step $group $ctl.Name 'DONE' $note }
        catch { Add-Step $group $ctl.Name 'ERROR' $_.Exception.Message }
    }
}

# ══ what the control table does not own ═══════════════════════════════════

# The build's own scheduled tasks. Not misconfigurations -- they are the resume
# task and the operator keeper -- but they must not outlive the range.
if (-not $Only -or $Only -contains 'persistence') {
    Write-Host "[persistence: build tasks]" -ForegroundColor Cyan
    foreach ($t in 'CyberRangeStage','CyberRangeSetup','CyberRangeOperatorKeeper') {
        $taskName = $t
        Invoke-Teardown 'persistence' "Scheduled task '$taskName'" `
            { [bool](Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) } `
            { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop } 'unregistered'
    }
}

# Dropped files and directories -- paths, not settings.
if (-not $Only -or $Only -contains 'artifacts') {
    Write-Host "[artifacts: dropped files]" -ForegroundColor Cyan
    foreach ($p in 'C:\ProgramData\SysTasks','C:\Public','C:\range-fix.cmd') {
        $path = $p
        Invoke-Teardown 'artifacts' "Path $path" `
            { Test-Path $path } { Remove-Item $path -Recurse -Force -ErrorAction Stop } 'deleted'
    }
    # The table restores each Defender policy VALUE; remove the now-redundant
    # policy tree outright so the box does not carry range policy keys forever.
    Invoke-Teardown 'artifacts' 'Defender policy key tree' `
        { Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' } `
        { Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Recurse -Force -ErrorAction Stop } `
        'policy keys removed'
    # SNMP communities live under a key the table clears value-by-value; drop the
    # container too.
    Invoke-Teardown 'artifacts' 'SNMP ValidCommunities key' `
        { Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities' } `
        { Remove-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities' -Force -ErrorAction Stop } `
        'communities cleared'
}

# ══ 8. ACCOUNTS ═══════════════════════════════════════════════════════════
Write-Host "[accounts]" -ForegroundColor Cyan
if ($KeepAccounts) {
    Add-Step 'accounts' 'All account changes' 'SKIP' '-KeepAccounts given'
} else {
    $hidden = if ($cfg -and $cfg.HiddenAdminAccounts) { $cfg.HiddenAdminAccounts } else { @('svc-backup','smb-backup','wsus-backup','iis-backup','adfs-backup') }
    $seeded = @('svc_mssql','svc_web','svc_backup','jsmith','agarcia','legacyapp','tmpadmin','helpdesk')
    $operator = @()
    if ($cfg -and $cfg.Analyst -and $cfg.Analyst.User) { $operator += $cfg.Analyst.User }
    # 'rangebreak' is not created by builds from 2026-09-07 onward, but a box
    # built before that still has it and teardown must still clear it.
    $operator += 'rangebreak'

    $toRemove = @($hidden + $seeded)
    if ($RemoveOperatorAccounts) { $toRemove += $operator }
    else { Add-Step 'accounts' 'Operator accounts' 'SKIP' ("kept: " + ($operator -join ', ') + " -- use -RemoveOperatorAccounts to drop them") }

    foreach ($u in ($toRemove | Select-Object -Unique)) {
        $user = $u
        # Never remove the account running this script.
        if ($me -like "*\$user") { Add-Step 'accounts' "Account '$user'" 'SKIP' 'this is the account you are logged in as'; continue }
        if ($isDC) {
            Invoke-Teardown 'accounts' "Domain account '$user'" `
                { try { Import-Module ActiveDirectory -ErrorAction Stop
                        [bool](Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue) } catch { $false } } `
                { Remove-ADUser -Identity $user -Confirm:$false -ErrorAction Stop } 'removed from AD'
        } else {
            Invoke-Teardown 'accounts' "Local account '$user'" `
                { [bool](Get-LocalUser -Name $user -ErrorAction SilentlyContinue) } `
                { Remove-LocalUser -Name $user -ErrorAction Stop } 'removed'
        }
        Invoke-Teardown 'accounts' "Sign-in hiding for '$user'" `
            { $null -ne (Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' $user) } `
            { Remove-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' $user } 'unhidden'
    }
}

# ══ 9. DOMAIN / AD SCENARIOS ══════════════════════════════════════════════
if ($isDC) {
    Write-Host "[dc]" -ForegroundColor Cyan
    $adOk = $false
    try { Import-Module ActiveDirectory -ErrorAction Stop; Get-ADDomain -ErrorAction Stop | Out-Null; $adOk = $true } catch {}
    if (-not $adOk) {
        Add-Step 'dc' 'AD scenarios' 'ERROR' 'AD is unreachable (ADWS?) -- cannot undo the AD attack paths'
    } else {
        $dom = Get-ADDomain

        Invoke-Teardown 'dc' 'ESC1 certificate template' `
            { $confNC = (Get-ADRootDSE).configurationNamingContext
              [bool](Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$confNC" -Filter "cn -eq 'RangeUserESC1'" -ErrorAction SilentlyContinue) } `
            { & certutil.exe -SetCATemplates -RangeUserESC1 2>&1 | Out-Null
              $confNC = (Get-ADRootDSE).configurationNamingContext
              Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$confNC" -Filter "cn -eq 'RangeUserESC1'" |
                  Remove-ADObject -Confirm:$false -ErrorAction Stop } 'unpublished and deleted'

        Invoke-Teardown 'dc' 'KDC certificate binding downgrade' `
            { (Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'StrongCertificateBindingEnforcement') -eq 1 } `
            { Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'StrongCertificateBindingEnforcement' DWord 2 } 'Full Enforcement restored'

        Invoke-Teardown 'dc' 'LDAP channel binding' `
            { (Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding') -eq 0 } `
            { Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding' DWord 1 } 'enforced again'

        Invoke-Teardown 'dc' 'DCSync + GenericAll grants' `
            { $true } `
            { $dn = $dom.DistinguishedName; $nb = $dom.NetBIOSName
              foreach ($r in 'Replicating Directory Changes','Replicating Directory Changes All','Replicating Directory Changes In Filtered Set') {
                  & dsacls.exe $dn '/R' "$nb\jsmith" 2>&1 | Out-Null }
              $daDN = (Get-ADGroup 'Domain Admins').DistinguishedName
              & dsacls.exe $daDN '/R' "$nb\agarcia" 2>&1 | Out-Null } 'ACEs revoked for jsmith / agarcia'

        Invoke-Teardown 'dc' 'GPP cpassword GPO' `
            { [bool](Get-GPO -Name 'Legacy Local Admin Provisioning' -ErrorAction SilentlyContinue) } `
            { Import-Module GroupPolicy -ErrorAction Stop
              Remove-GPO -Name 'Legacy Local Admin Provisioning' -ErrorAction Stop } 'GPO and its SYSVOL Groups.xml removed'

        Invoke-Teardown 'dc' 'Weak domain password policy' `
            { (Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled -eq $false } `
            { Set-ADDefaultDomainPasswordPolicy -Identity $dom.DNSRoot -ComplexityEnabled $true `
                -MinPasswordLength 14 -LockoutThreshold 10 -PasswordHistoryCount 24 `
                -MaxPasswordAge '60.00:00:00' -ErrorAction Stop } 'complexity on, minlen 14, lockout 10'

        Invoke-Teardown 'dc' 'MachineAccountQuota (RBCD)' `
            { [int](Get-ADObject -Identity $dom.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota' -gt 0 } `
            { Set-ADObject -Identity $dom.DistinguishedName -Replace @{ 'ms-DS-MachineAccountQuota' = 0 } -ErrorAction Stop } 'set to 0'

        Invoke-Teardown 'dc' 'DC security-template downgrades' `
            { $g='{6AC1786C-016F-11D2-945F-00C04FB984F9}'
              $i="\\$($dom.DNSRoot)\SYSVOL\$($dom.DNSRoot)\Policies\$g\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
              (Test-Path $i) -and ((Get-Content $i -Raw) -match 'NoLMHash|RequireSecuritySignature|MaximumLogSize') } `
            { Write-Host "        (edit GptTmpl.inf by hand or via GPMC -- automated removal of a live" -ForegroundColor DarkGray
              Write-Host "         DC security template is riskier than the misconfiguration)" -ForegroundColor DarkGray
              throw 'left for manual removal on purpose' } 'MANUAL -- see note'
    }

    if ($RemoveDomain) {
        Write-Host ""
        Write-Host "-RemoveDomain: demoting this domain controller." -ForegroundColor Red
        Write-Host "A demoted DC is NOT a never-promoted server. The domain SID, krbtgt history" -ForegroundColor Red
        Write-Host "and SYSVOL remnants persist. Rebuild if this matters." -ForegroundColor Red
        if ($Execute) {
            $lap = Read-Host "Local Administrator password for the demoted server" -AsSecureString
            try {
                Import-Module ADDSDeployment -ErrorAction Stop
                Uninstall-ADDSDomainController -LocalAdministratorPassword $lap -LastDomainControllerInDomain `
                    -RemoveApplicationPartitions -IgnoreLastDNSServerForZone -Force -ErrorAction Stop
                Add-Step 'dc' 'Domain controller demotion' 'DONE' 'reboots automatically'
            } catch { Add-Step 'dc' 'Domain controller demotion' 'ERROR' $_.Exception.Message }
        } else { Add-Step 'dc' 'Domain controller demotion' 'WOULD' 'demote + reboot' }
    }
}

# ══ SUMMARY ═══════════════════════════════════════════════════════════════
Write-Host ""
$g = $results | Group-Object State | Sort-Object Name
Write-Host ("SUMMARY: " + (($g | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  ')) -ForegroundColor Cyan
$bad = @($results | Where-Object State -eq 'ERROR')
if ($bad.Count) {
    Write-Host ""
    Write-Host "NOT UNDONE:" -ForegroundColor Red
    foreach ($r in $bad) { Write-Host ("  [{0}] {1} -- {2}" -f $r.Category, $r.Name, $r.Detail) -ForegroundColor Red }
}

Write-Host ""
Write-Host "STILL TRUE AFTER THIS TEARDOWN:" -ForegroundColor Yellow
Write-Host "  * Every seeded password, the Administrator password and the DSRM password" -ForegroundColor Yellow
Write-Host "    were exposed in cleartext. Change them, and treat them as burned." -ForegroundColor Yellow
Write-Host "  * The manifest under C:\ProgramData\CyberRange is the answer key. Collect" -ForegroundColor Yellow
Write-Host "    it off-box, then delete it." -ForegroundColor Yellow
Write-Host "  * The host missed every update while the range was live. Patch it." -ForegroundColor Yellow
if ($isDC -and -not $RemoveDomain) {
    Write-Host "  * This is still a domain controller for $(try{(Get-ADDomain).DNSRoot}catch{'the range domain'})." -ForegroundColor Yellow
}
Write-Host "  * UAC and LSA PPL changes need a REBOOT to take effect." -ForegroundColor Yellow
Write-Host ""
if (-not $Execute) { Write-Host "Dry run only. Re-run with -Execute to apply." -ForegroundColor Cyan }
else { Write-Host "Verify with: .\Test-RangeConfig.ps1  (expect most controls to now FAIL -- that is the point)" -ForegroundColor Green }
