#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    Break-glass pre-flight and recovery-account provisioning for the cyber range.

.DESCRIPTION
    Normally you do not run this by hand -- Stage-CyberRange.ps1 runs it for you
    (with -Apply) as the first thing it does. Run it directly when you are
    diagnosing a gate failure or repairing an already-built box.

    It is the Part A pre-flight from docs\VERIFICATION-SESSION.md made executable,
    plus the operator recovery account -- provisioned before the domain is built
    and long before Setup weakens anything, so there is never a window where the
    box is weakened and you have no way in.

    ONE RECOVERY ACCOUNT, NOT TWO
    ---------------------------------------------------------------------------
    This used to provision a second account ('rangebreak') alongside the operator
    admin ('analyst'). They were the same thing built twice: same role-aware
    local-or-domain provisioning, same admin group membership, same un-hiding
    from the sign-in screen, same authentication check -- read from the same
    config file, so they even shared a failure mode. 'analyst' is strictly
    better, because scripts\operator-keeper.ps1 re-asserts it on EVERY boot.
    So there is now one operator account, provisioned here and owned by
    scripts\operator-account.ps1, which this script calls rather than
    reimplementing.

    The recovery LAYERS are unchanged and are what actually matter: the VM
    snapshot, 'analyst' (self-healing every boot), the logon-screen accessibility
    shell (SYSTEM, no password), C:\range-fix.cmd, the seeded *-backup admins,
    DSRM, and an offline Windows RE registry edit. See docs\BREAK-GLASS.md.

    This script does NOT weaken the host and is not part of the misconfiguration
    set. It is deliberately standalone: no dependency on RangeCommon.psm1, so it
    still runs on a half-built or damaged box.

    MODES
      (default)          Read-only pre-flight. Prints PASS/FAIL/BLOCKED per gate
                         and exits 1 if any blocking gate fails. Changes nothing.
      -Apply             Creates/repairs the operator recovery account and
                         re-runs the pre-flight. The only mutating mode.
      -RepairAutologon   RECOVERY: clears AutoAdminLogon/ForceAutoLogon so a
                         failed forced-autologon loop stops. Run from any working
                         admin session; see docs\BREAK-GLASS.md for the offline
                         (Windows RE) equivalent when you cannot log in at all.

.PARAMETER User
    Operator recovery account name. Defaults to Config.Analyst.User, else
    'analyst'. Deliberately NOT one of the Config.HiddenAdminAccounts -- those
    are red-team loot and are hidden from the sign-in screen. This account is
    meant to be visible and is yours.

.PARAMETER Password
    SecureString. Omit to fall back to Config.Analyst.Password, and to be
    prompted only if that is absent too.

.PARAMETER FromBuild
    Set when this script is called unattended. Suppresses every interactive
    prompt and returns instead of calling exit, so a failed gate surfaces to the
    caller rather than killing it.

.PARAMETER EnableDsrmLogon
    DC only. Sets DsrmAdminLogonBehavior=2 so the DSRM account can log on while
    the DC is running, not just in Directory Services Restore Mode. This is a
    real weakening of the DC -- it is here because on a promoted DC, DSRM is the
    last recovery path that survives the loss of every domain account. Opt in
    knowingly, and note it in the manifest/scenario brief.

.EXAMPLE
    .\scripts\preflight.ps1
    Read-only pre-flight. Run this first.

.EXAMPLE
    .\scripts\preflight.ps1 -Apply
    Create the operator recovery admin, validate it authenticates, then re-run
    the gates. This is what Stage-CyberRange.ps1 runs for you.

.EXAMPLE
    .\scripts\preflight.ps1 -RepairAutologon
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

# ── Config is loaded up front: -Apply needs Analyst.User/Password from it ──
$cfg = $null
$cfgError = $null
try { $cfg = Import-PowerShellDataFile $ConfigPath -ErrorAction Stop }
catch { $cfgError = $_.Exception.Message }

if (-not $User) {
    $User = if ($cfg -and $cfg.Analyst -and $cfg.Analyst.User) { $cfg.Analyst.User } else { 'analyst' }
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
    Write-Host "If you still cannot log in, see docs\BREAK-GLASS.md (Layers 3-6)." -ForegroundColor Yellow
    return
}

# ── APPLY MODE: provision the operator recovery account ───────────────────
#    The account itself is owned by scripts\operator-account.ps1: it is
#    role-aware (LOCAL user in Administrators on a standalone host, DOMAIN user
#    in Domain Admins on a DC), un-hides itself from the sign-in screen, and
#    validates that it authenticates before returning. This script CALLS it
#    rather than carrying a second implementation that could drift from it.
if ($Apply) {
    Write-Host "APPLY: provisioning operator recovery account '$User'" -ForegroundColor Yellow
    if (-not $Password) {
        if ($cfg -and $cfg.Analyst -and $cfg.Analyst.Password) {
            $Password = ConvertTo-SecureString ([string]$cfg.Analyst.Password) -AsPlainText -Force
            Write-Gate 'password source' 'INFO' 'Config.Analyst.Password'
            if ([string]$cfg.Analyst.Password -match 'ChangeMe') {
                Write-Gate 'password source' 'WARN' 'still the shipped placeholder -- change it in range.config.psd1'
            }
        }
        elseif ($FromBuild) {
            Write-Gate 'password' 'BLOCKED' 'No Config.Analyst.Password and cannot prompt during an unattended build.'
            return
        }
        else {
            $Password = Read-Host "Password for operator account '$User'" -AsSecureString
            $confirm  = Read-Host "Confirm" -AsSecureString
            if ((ConvertFrom-Secure $Password) -ne (ConvertFrom-Secure $confirm)) {
                Write-Gate 'password' 'BLOCKED' 'Passwords did not match. Nothing changed.'
                if ($FromBuild) { return } else { exit 1 }
            }
        }
    }
    $plain = ConvertFrom-Secure $Password

    $provisioner = Join-Path $PSScriptRoot 'operator-account.ps1'
    if (-not (Test-Path $provisioner)) {
        Write-Gate 'account' 'BLOCKED' "provisioner not found: $provisioner"
    } else {
        try {
            & $provisioner -User $User -Password $Password -FromBuild
            Write-Gate 'account' 'PASS' "'$User' provisioned by operator-account.ps1 ($(if ($isDC) { 'DOMAIN' } else { 'LOCAL' }))"
        } catch {
            Write-Gate 'account' 'BLOCKED' "account provisioning failed: $($_.Exception.Message)"
        }
    }

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

Operator account : $User   ($(if ($isDC) { 'DOMAIN (Domain Admins)' } else { 'LOCAL (Administrators)' }))
Password         : <not stored here -- record it in your password manager NOW>

This account is re-asserted on EVERY boot by the operator keeper task
(CyberRangeOperatorKeeper), so a stalled phase, a GPO or a lockout cannot take
it away from you.

If you are locked out, work through docs\BREAK-GLASS.md in order.
Fastest path is always: revert to the pre-build snapshot.
"@ | Set-Content -Path $CardPath -Encoding UTF8
        & icacls.exe $CardPath /inheritance:r /grant 'SYSTEM:(F)' 'Administrators:(F)' 2>&1 | Out-Null
        Write-Gate 'recovery card' 'PASS' $CardPath
    } catch { Write-Gate 'recovery card' 'WARN' $_.Exception.Message }

    $ok = Test-CredentialWorks -Account $User -Plain $plain -Domain:$isDC
    if ($ok -eq $true)      { Write-Gate 'AUTH VALIDATION' 'PASS' "'$User' authenticates. You have a way back in." }
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

    # A2/A3 -- the lockout gates. Since the F1 fix, the autologon block in
    # Setup-CyberRange.ps1 SETS the account password to LocalAdminAutoLogonPass
    # and validates it before enabling autologon, so a current mismatch is no
    # longer fatal -- the build reconciles it. What IS fatal is the build
    # reverting to blind ForceAutoLogon, so verify that in SOURCE rather than
    # trusting the docs. This is a regression test against the code that will
    # actually run, and it is why this gate reads a file instead of the registry.
    $autoUser   = $cfg.LocalAdminAutoLogonUser
    $autoPass   = $cfg.LocalAdminAutoLogonPass
    $setupPath  = Join-Path (Split-Path $PSScriptRoot -Parent) 'Setup-CyberRange.ps1'

    if (Test-Path $setupPath) {
        # Only a WRITE of ForceAutoLogon is a regression -- Setup deliberately
        # mentions the value in order to REMOVE it, so match the write form.
        $setsForce = Select-String -Path $setupPath -Pattern "Set-RegValue[^\r\n]*ForceAutoLogon" -Quiet
        $setsPw    = Select-String -Path $setupPath -Pattern "Set-LocalUser|Set-ADAccountPassword" -Quiet
        $setsDom   = Select-String -Path $setupPath -Pattern "DefaultDomainName" -Quiet

        if ($setsForce) { Write-Gate 'A3 ForceAutoLogon' 'BLOCKED' 'Setup sets ForceAutoLogon -- a failed autologon will loop (F1 regression)' }
        else            { Write-Gate 'A3 ForceAutoLogon' 'PASS' 'never written by the build' }

        if ($setsPw)  { Write-Gate 'A2 password reconciled' 'PASS' "the build sets '$autoUser' to LocalAdminAutoLogonPass before enabling autologon" }
        else          { Write-Gate 'A2 password reconciled' 'BLOCKED' "nothing sets '$autoUser' password -- autologon can diverge (F1 regression)" }

        if ($setsDom) { Write-Gate 'A2 DefaultDomainName' 'PASS' 'set by the build' }
        else          { Write-Gate 'A2 DefaultDomainName' 'BLOCKED' 'never set -- autologon fails after DC promotion (F1 regression)' }
    } else {
        Write-Gate 'A2/A3 autologon' 'WARN' "could not locate Setup-CyberRange.ps1 at $setupPath"
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
$haveOperator = $false
if ($isDC) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        if (Get-ADUser -Filter "SamAccountName -eq '$User'" -ErrorAction SilentlyContinue) { $haveOperator = $true }
    } catch {}
} else {
    if (Get-LocalUser -Name $User -ErrorAction SilentlyContinue) { $haveOperator = $true }
}
if ($haveOperator) {
    Write-Gate 'A4 operator account' 'PASS' "'$User' exists"
} else {
    Write-Gate 'A4 operator account' 'BLOCKED' "'$User' does not exist -- run this script with -Apply before building"
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

# A0 -- clean standalone base for a DC build (F29). A domain MEMBER cannot create
# a new forest; promotion fails prereqs after Phase 1 has already weakened the box.
$cs0          = Get-CimInstance Win32_ComputerSystem
$partOfDomain = $cs0.PartOfDomain
if ($cfg -and $cfg.DC -and $cfg.DC.Enabled) {
    if (-not $partOfDomain) {
        Write-Gate 'A0 standalone base' 'PASS' 'workgroup / not domain-joined -- can promote into its own new forest'
    } elseif ($isDC) {
        Write-Gate 'A0 standalone base' 'INFO' 'already a DC -- promotion has run; a build resume will detect this'
    } else {
        Write-Gate 'A0 standalone base' 'BLOCKED' "host is a MEMBER of domain '$($cs0.Domain)' -- a DC build needs a STANDALONE server. Fix: Add-Computer -WorkgroupName WORKGROUP -Force -Restart, or revert to a clean never-joined snapshot (F29)."
    }
} else {
    Write-Gate 'A0 standalone base' 'INFO' 'DC build not enabled; standalone base not required'
}

# Answer-key exposure (finding F3). The manifest/answer key under
# C:\ProgramData\CyberRange MUST stay locked -> a FAIL blocks the build. The staged
# tree C:\CyberRange is deliberately left on inherited permissions (we stopped
# locking it because that caused repeated access-denied lockouts; the operator is
# Administrator on a built box anyway -- F18). So an open C:\CyberRange is a WARN,
# not a blocker; off-boxing the staged config is WP2/WP3 work.
$answerKeyDir = Join-Path $env:ProgramData 'CyberRange'
foreach ($p in $answerKeyDir, 'C:\CyberRange') {
    if (-not (Test-Path $p)) { continue }
    $open = (Get-Acl $p).Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and $_.IdentityReference -match 'BUILTIN\\Users|Everyone|Authenticated Users'
    }
    if (-not $open) { Write-Gate 'answer-key ACL' 'PASS' "$p restricted"; continue }
    if ($p -eq $answerKeyDir) { Write-Gate 'answer-key ACL' 'FAIL' "$p is readable by non-admins -- the change manifest / answer key is exposed (F3)" }
    else { Write-Gate 'answer-key ACL' 'WARN' "$p readable by non-admins (staged config; intentional per F18, off-boxed by WP2/WP3)" }
}

Write-Host ""
if ($script:Blocked -gt 0) {
    Write-Host "PRE-FLIGHT: BLOCKED ($script:Blocked failing gate(s)). DO NOT BUILD." -ForegroundColor Red
    Write-Host "See docs\USER-GUIDE.md section 9 (Troubleshooting) and docs\BREAK-GLASS.md." -ForegroundColor Red
    if ($FromBuild) { return } else { exit 1 }
}
Write-Host "PRE-FLIGHT: PASS. Snapshot the VM, then run Stage-CyberRange.ps1." -ForegroundColor Green
if ($FromBuild) { return } else { exit 0 }
