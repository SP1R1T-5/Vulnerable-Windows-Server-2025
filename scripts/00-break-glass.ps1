#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    Break-glass pre-flight and recovery-account provisioning for the cyber range.

.DESCRIPTION
    Run this BEFORE Setup-CyberRange.ps1, every time. It is the Part A pre-flight
    from docs\VERIFICATION-SESSION.md made executable, plus the recovery account
    that the build itself does not create until Phase 3 -- far too late to help.

    This script does NOT weaken the host and is not part of the misconfiguration
    set. It is deliberately standalone: no dependency on RangeCommon.psm1, so it
    still runs on a half-built or damaged box.

    MODES
      (default)          Read-only pre-flight. Prints PASS/FAIL/BLOCKED per gate
                         and exits 1 if any blocking gate fails. Changes nothing.
      -Apply             Creates/repairs the break-glass administrator and
                         re-runs the pre-flight. The only mutating mode.
      -RepairAutologon   RECOVERY: clears AutoAdminLogon/ForceAutoLogon so a
                         failed forced-autologon loop stops. Run from any working
                         admin session; see docs\BREAK-GLASS.md for the offline
                         (Windows RE) equivalent when you cannot log in at all.

.PARAMETER User
    Break-glass account name. Default 'rangebreak'. Deliberately NOT one of the
    Config.HiddenAdminAccounts -- those are red-team loot and are hidden from the
    sign-in screen. This account is meant to be visible and is yours.

.PARAMETER Password
    SecureString. Omit to fall back to Config.BreakGlass.Password, and to be
    prompted only if that is absent too.

.PARAMETER FromBuild
    Set by Setup-CyberRange.ps1 when it calls this script unattended. Suppresses
    every interactive prompt and returns instead of calling exit, so a failed gate
    surfaces to the orchestrator rather than killing it.

.PARAMETER EnableDsrmLogon
    DC only. Sets DsrmAdminLogonBehavior=2 so the DSRM account can log on while
    the DC is running, not just in Directory Services Restore Mode. This is a
    real weakening of the DC -- it is here because on a promoted DC, DSRM is the
    last recovery path that survives the loss of every domain account. Opt in
    knowingly, and note it in the manifest/scenario brief.

.EXAMPLE
    .\scripts\00-break-glass.ps1
    Read-only pre-flight. Run this first.

.EXAMPLE
    .\scripts\00-break-glass.ps1 -Apply
    Create the break-glass admin, validate it authenticates, then re-run the gates.

.EXAMPLE
    .\scripts\00-break-glass.ps1 -RepairAutologon
    Stop a failed-autologon loop from a working admin session.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$RepairAutologon,
    [string]$User,
    [System.Security.SecureString]$Password,
    [switch]$EnableDsrmLogon,
    [switch]$FromBuild
)

$ErrorActionPreference = 'Continue'

$RepoRoot   = Split-Path $PSScriptRoot -Parent
$ConfigPath = Join-Path $RepoRoot 'config\range.config.psd1'
$CardDir    = Join-Path $env:ProgramData 'CyberRange'
$CardPath   = Join-Path $CardDir 'BREAK-GLASS-CARD.txt'
$WinlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$UserListKey = "$WinlogonKey\SpecialAccounts\UserList"

$script:Blocked = 0

function Write-Gate {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('PASS','FAIL','WARN','INFO','BLOCKED')][string]$Result,
        [Parameter(Mandatory)][string]$Message
    )
    if ($Result -eq 'BLOCKED' -or $Result -eq 'FAIL') { $script:Blocked++ }
    $color = switch ($Result) { 'PASS' {'Green'} 'WARN' {'Yellow'} 'INFO' {'Gray'} default {'Red'} }
    Write-Host ("  {0,-22} {1,-8} {2}" -f $Id, $Result, $Message) -ForegroundColor $color
}

function Test-CredentialWorks {
    <# Returns $true/$false/$null. $null = could not test (context unavailable). #>
    param([string]$Account, [string]$Plain, [switch]$Domain)
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $ctxType = if ($Domain) { 'Domain' } else { 'Machine' }
        $ctx = [System.DirectoryServices.AccountManagement.PrincipalContext]::new($ctxType)
        return $ctx.ValidateCredentials($Account, $Plain)
    } catch { return $null }
}

function ConvertFrom-Secure {
    param([System.Security.SecureString]$S)
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($S)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

# ── Config is loaded up front: -Apply needs BreakGlass.User/Password from it ──
$cfg = $null
$cfgError = $null
try { $cfg = Import-PowerShellDataFile $ConfigPath -ErrorAction Stop }
catch { $cfgError = $_.Exception.Message }

if (-not $User) {
    $User = if ($cfg -and $cfg.BreakGlass -and $cfg.BreakGlass.User) { $cfg.BreakGlass.User } else { 'rangebreak' }
}

$role     = (Get-CimInstance Win32_ComputerSystem).DomainRole
$isDC     = $role -ge 4
$roleName = switch ($role) { 0 {'standalone workstation'} 1 {'member workstation'} 2 {'standalone server'} 3 {'member server'} 4 {'backup DC'} 5 {'primary DC'} default {"unknown ($role)"} }

Write-Host ""
Write-Host "BREAK-GLASS PRE-FLIGHT  --  $env:COMPUTERNAME  --  $(Get-Date -Format s)" -ForegroundColor Cyan
Write-Host ("Role: $roleName" + $(if ($isDC) { '  [DC: local SAM is gone; recovery is domain or DSRM only]' } else { '' })) -ForegroundColor Cyan
Write-Host ""

# ── RECOVERY MODE: stop a forced-autologon loop ───────────────────────────
if ($RepairAutologon) {
    Write-Host "RECOVERY: clearing autologon" -ForegroundColor Yellow
    foreach ($v in 'ForceAutoLogon','AutoAdminLogon','DefaultPassword') {
        try {
            Remove-ItemProperty -Path $WinlogonKey -Name $v -Force -ErrorAction Stop
            Write-Gate $v 'PASS' 'removed'
        } catch {
            Write-Gate $v 'INFO' 'not present (nothing to remove)'
        }
    }
    Write-Host ""
    Write-Host "Autologon cleared. Reboot and log in normally." -ForegroundColor Green
    Write-Host "If you still cannot log in, see docs\BREAK-GLASS.md (Layer 4/5)." -ForegroundColor Yellow
    return
}

# ── APPLY MODE: provision the break-glass administrator ───────────────────
if ($Apply) {
    Write-Host "APPLY: provisioning break-glass administrator '$User'" -ForegroundColor Yellow
    if (-not $Password) {
        if ($cfg -and $cfg.BreakGlass -and $cfg.BreakGlass.Password) {
            $Password = ConvertTo-SecureString ([string]$cfg.BreakGlass.Password) -AsPlainText -Force
            Write-Gate 'password source' 'INFO' 'Config.BreakGlass.Password'
            if ([string]$cfg.BreakGlass.Password -match 'ChangeMe') {
                Write-Gate 'password source' 'WARN' 'still the shipped placeholder -- change it in range.config.psd1'
            }
        }
        elseif ($FromBuild) {
            Write-Gate 'password' 'BLOCKED' 'No Config.BreakGlass.Password and cannot prompt during an unattended build.'
            return
        }
        else {
            $Password = Read-Host "Password for break-glass account '$User'" -AsSecureString
            $confirm  = Read-Host "Confirm" -AsSecureString
            if ((ConvertFrom-Secure $Password) -ne (ConvertFrom-Secure $confirm)) {
                Write-Gate 'password' 'BLOCKED' 'Passwords did not match. Nothing changed.'
                if ($FromBuild) { return } else { exit 1 }
            }
        }
    }
    $plain = ConvertFrom-Secure $Password

    if ($isDC) {
        # No local SAM on a DC -- the break-glass account must be a domain account.
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $dom = Get-ADDomain -ErrorAction Stop
            if (Get-ADUser -Filter "SamAccountName -eq '$User'" -ErrorAction SilentlyContinue) {
                Set-ADAccountPassword -Identity $User -Reset -NewPassword $Password -ErrorAction Stop
                Set-ADUser -Identity $User -Enabled $true -PasswordNeverExpires $true -ErrorAction Stop
                Write-Gate 'account' 'PASS' "domain user '$User' updated"
            } else {
                New-ADUser -SamAccountName $User -Name $User -UserPrincipalName "$User@$($dom.DNSRoot)" `
                    -AccountPassword $Password -Enabled $true -PasswordNeverExpires $true `
                    -Path $dom.UsersContainer -Description 'RANGE BREAK-GLASS - operator recovery account. Not part of the exercise.' `
                    -ErrorAction Stop
                Write-Gate 'account' 'PASS' "domain user '$User' created"
            }
            foreach ($g in 'Domain Admins','Enterprise Admins') {
                try { Add-ADGroupMember -Identity $g -Members $User -ErrorAction Stop; Write-Gate "group:$g" 'PASS' 'added' }
                catch { Write-Gate "group:$g" 'WARN' $_.Exception.Message }
            }
        } catch {
            Write-Gate 'account' 'BLOCKED' "domain account provisioning failed: $($_.Exception.Message)"
        }
    }
    else {
        try {
            if (Get-LocalUser -Name $User -ErrorAction SilentlyContinue) {
                Set-LocalUser -Name $User -Password $Password -PasswordNeverExpires $true -ErrorAction Stop
                Enable-LocalUser -Name $User -ErrorAction SilentlyContinue
                Write-Gate 'account' 'PASS' "local user '$User' updated"
            } else {
                New-LocalUser -Name $User -Password $Password -PasswordNeverExpires -AccountNeverExpires `
                    -Description 'RANGE BREAK-GLASS - operator recovery account. Not part of the exercise.' `
                    -ErrorAction Stop | Out-Null
                Write-Gate 'account' 'PASS' "local user '$User' created"
            }
            foreach ($g in 'Administrators','Remote Desktop Users') {
                try {
                    if (-not (Get-LocalGroupMember -Group $g -Member $User -ErrorAction SilentlyContinue)) {
                        Add-LocalGroupMember -Group $g -Member $User -ErrorAction Stop
                    }
                    Write-Gate "group:$g" 'PASS' 'member'
                } catch { Write-Gate "group:$g" 'WARN' $_.Exception.Message }
            }
        } catch {
            Write-Gate 'account' 'BLOCKED' "local account provisioning failed: $($_.Exception.Message)"
        }
    }

    # The build hides accounts from the sign-in screen. This one must stay visible.
    try {
        if (Test-Path $UserListKey) {
            Remove-ItemProperty -Path $UserListKey -Name $User -Force -ErrorAction SilentlyContinue
        }
        Write-Gate 'sign-in visibility' 'PASS' 'not hidden (SpecialAccounts\UserList clear)'
    } catch { Write-Gate 'sign-in visibility' 'WARN' $_.Exception.Message }

    if ($EnableDsrmLogon) {
        if ($isDC) {
            New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DsrmAdminLogonBehavior' `
                -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue | Out-Null
            Write-Gate 'DSRM logon' 'WARN' 'DsrmAdminLogonBehavior=2 -- DSRM usable while the DC is running (deliberate weakening)'
        } else {
            Write-Gate 'DSRM logon' 'INFO' 'not a DC; skipped'
        }
    }

    # Recovery card, restricted to SYSTEM + Administrators.
    try {
        New-Item -ItemType Directory -Path $CardDir -Force | Out-Null
        @"
RANGE BREAK-GLASS CARD  --  $env:COMPUTERNAME  --  $(Get-Date -Format s)
Role at provisioning time: $roleName

Break-glass account : $User   ($(if ($isDC) { 'DOMAIN (Domain Admins)' } else { 'LOCAL (Administrators)' }))
Password            : <not stored here -- record it in your password manager NOW>

If you are locked out, work through docs\BREAK-GLASS.md in order.
Fastest path is always: revert to the pre-build snapshot.
"@ | Set-Content -Path $CardPath -Encoding UTF8
        & icacls.exe $CardPath /inheritance:r /grant 'SYSTEM:(F)' 'Administrators:(F)' 2>&1 | Out-Null
        Write-Gate 'recovery card' 'PASS' $CardPath
    } catch { Write-Gate 'recovery card' 'WARN' $_.Exception.Message }

    $ok = Test-CredentialWorks -Account $User -Plain $plain -Domain:$isDC
    if ($ok -eq $true)      { Write-Gate 'AUTH VALIDATION' 'PASS' "'$User' authenticates. Break-glass is live." }
    elseif ($ok -eq $false) { Write-Gate 'AUTH VALIDATION' 'BLOCKED' "'$User' does NOT authenticate. DO NOT BUILD." }
    else                    { Write-Gate 'AUTH VALIDATION' 'WARN' 'could not validate (no directory context); test by logging in before you build' }

    $plain = $null
    Write-Host ""
}

# ── PART A GATES (always run) ─────────────────────────────────────────────
Write-Host "PART A GATES" -ForegroundColor Cyan

Write-Gate 'A1 snapshot' 'WARN' 'CANNOT BE CHECKED FROM INSIDE THE VM -- confirm a current checkpoint on the hypervisor'

if ($cfg) { Write-Gate 'A5 config loads' 'PASS' $ConfigPath }
else      { Write-Gate 'A5 config loads' 'BLOCKED' "cannot read config: $cfgError" }

if ($cfg) {
    if ($cfg.Confirmed) { Write-Gate 'A5 Confirmed' 'PASS' 'safety guard acknowledged' }
    else                { Write-Gate 'A5 Confirmed' 'INFO' 'Confirmed=$false -- the build will refuse to run' }

    # A2/A3 -- the lockout gates. Since the F1 fix, 20-credential-exposure.ps1
    # SETS the account password to LocalAdminAutoLogonPass and validates it
    # before enabling autologon, so a current mismatch is no longer fatal --
    # the build reconciles it. What IS fatal is the build reverting to blind
    # ForceAutoLogon, so verify that in source rather than trusting the docs.
    $autoUser   = $cfg.LocalAdminAutoLogonUser
    $autoPass   = $cfg.LocalAdminAutoLogonPass
    $credScript = Join-Path $PSScriptRoot '20-credential-exposure.ps1'

    if (Test-Path $credScript) {
        $setsForce = Select-String -Path $credScript -Pattern "Set-RegValue.*ForceAutoLogon" -Quiet
        $setsPw    = Select-String -Path $credScript -Pattern "Set-LocalUser|Set-ADAccountPassword" -Quiet
        $setsDom   = Select-String -Path $credScript -Pattern "DefaultDomainName" -Quiet

        if ($setsForce) { Write-Gate 'A3 ForceAutoLogon' 'BLOCKED' 'the build sets ForceAutoLogon -- a failed autologon will loop (F1 regression)' }
        else            { Write-Gate 'A3 ForceAutoLogon' 'PASS' 'never set by the build' }

        if ($setsPw)  { Write-Gate 'A2 password reconciled' 'PASS' "the build sets '$autoUser' to LocalAdminAutoLogonPass before enabling autologon" }
        else          { Write-Gate 'A2 password reconciled' 'BLOCKED' "nothing sets '$autoUser' password -- autologon can diverge (F1 regression)" }

        if ($setsDom) { Write-Gate 'A2 DefaultDomainName' 'PASS' 'set by the build' }
        else          { Write-Gate 'A2 DefaultDomainName' 'BLOCKED' 'never set -- autologon fails after DC promotion (F1 regression)' }
    } else {
        Write-Gate 'A2/A3 autologon' 'WARN' 'could not locate 20-credential-exposure.ps1'
    }

    # Informational: what the credential does RIGHT NOW, pre-build.
    $res = Test-CredentialWorks -Account $autoUser -Plain $autoPass -Domain:$isDC
    if ($res -eq $true)      { Write-Gate 'A2 current state' 'PASS' "'$autoUser' already authenticates with LocalAdminAutoLogonPass" }
    elseif ($res -eq $false) { Write-Gate 'A2 current state' 'WARN' "'$autoUser' does not match yet -- the build WILL CHANGE this account's password to LocalAdminAutoLogonPass" }
    else                     { Write-Gate 'A2 current state' 'INFO' 'could not validate (no directory context)' }

    # A5b -- placeholder detection.
    $stale = @()
    if ($cfg.DC.SafeModePassword -match 'ChangeMe') { $stale += 'DC.SafeModePassword' }
    if ($cfg.LocalAdminAutoLogonPass -eq 'Password!') { $stale += 'LocalAdminAutoLogonPass' }
    if ($stale.Count) { Write-Gate 'A5 placeholders' 'WARN' ("still placeholder: " + ($stale -join ', ')) }
    else              { Write-Gate 'A5 placeholders' 'PASS' 'no known placeholder values' }

    # A5c -- beacon containment. Must be non-routable.
    $bh = [string]$cfg.BeaconHost
    if ($bh -match '^192\.0\.2\.' -or $bh -match '^198\.51\.100\.' -or $bh -match '^203\.0\.113\.') {
        Write-Gate 'A5 beacon target' 'PASS' "$bh is RFC 5737 documentation space"
    } else {
        Write-Gate 'A5 beacon target' 'FAIL' "$bh is NOT RFC 5737 documentation space -- every clone will connect to a real host"
    }
}

# A4 -- does a usable recovery path exist right now?
$haveBreakGlass = $false
if ($isDC) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        if (Get-ADUser -Filter "SamAccountName -eq '$User'" -ErrorAction SilentlyContinue) { $haveBreakGlass = $true }
    } catch {}
} else {
    if (Get-LocalUser -Name $User -ErrorAction SilentlyContinue) { $haveBreakGlass = $true }
}
if ($haveBreakGlass) {
    Write-Gate 'A4 break-glass acct' 'PASS' "'$User' exists"
} else {
    Write-Gate 'A4 break-glass acct' 'BLOCKED' "'$User' does not exist -- run this script with -Apply before building"
}

if ($isDC) {
    $dsrm = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue).DsrmAdminLogonBehavior
    Write-Gate 'A4 DSRM' 'INFO' ("DsrmAdminLogonBehavior=" + $(if ($null -ne $dsrm) { $dsrm } else { 'unset (DSRM boot only)' }) + " -- DSRM password must be recorded off-box")
}

# A6 -- right host, and is it actually isolated?
Write-Gate 'A6 host' 'INFO' "$env:COMPUTERNAME / $roleName -- confirm this is the intended lab VM"
$gw = (Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4DefaultGateway }).IPv4DefaultGateway.NextHop
if ($gw) { Write-Gate 'A6 isolation' 'WARN' "default gateway present ($($gw -join ', ')) -- confirm it cannot reach the internet; the build disables the firewall entirely" }
else     { Write-Gate 'A6 isolation' 'PASS' 'no default gateway (isolated)' }

# Answer-key exposure (see finding F3).
foreach ($p in (Join-Path $env:ProgramData 'CyberRange'), 'C:\CyberRange') {
    if (Test-Path $p) {
        $open = (Get-Acl $p).Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and $_.IdentityReference -match 'BUILTIN\\Users|Everyone|Authenticated Users'
        }
        if ($open) { Write-Gate 'answer-key ACL' 'FAIL' "$p is readable by non-admins -- every seeded password is exposed (F3)" }
        else       { Write-Gate 'answer-key ACL' 'PASS' "$p restricted" }
    }
}

Write-Host ""
if ($script:Blocked -gt 0) {
    Write-Host "PRE-FLIGHT: BLOCKED ($script:Blocked failing gate(s)). DO NOT BUILD." -ForegroundColor Red
    Write-Host "See docs\BREAK-GLASS.md and docs\VERIFICATION-REPORT-2026-09-03.md." -ForegroundColor Red
    if ($FromBuild) { return } else { exit 1 }
}
Write-Host "PRE-FLIGHT: PASS. Snapshot the VM, then run Setup-CyberRange.ps1." -ForegroundColor Green
if ($FromBuild) { return } else { exit 0 }
