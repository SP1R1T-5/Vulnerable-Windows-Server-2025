#requires -Version 5.1
<#
    Operator keeper -- guarantees the range operator can ALWAYS log in.

    The build intentionally rewrites the built-in Administrator password (the
    exposed-credential lesson), promotion wipes local accounts, and phases/GPO can
    drift things across reboots. Rather than chase every case, this keeps ONE
    account (`analyst`) permanently good: it runs at EVERY boot via a SYSTEM
    scheduled task (CyberRangeOperatorKeeper) and re-asserts the account --
    exists, enabled, unlocked, in the admin group, password = Config.Analyst.Password,
    and NOT hidden from the sign-in screen. Role-aware (local vs domain); on a DC it
    waits for AD DS, then asserts the domain account.

    It also:
      * disables ACCOUNT LOCKOUT, so the correct password is never rejected, and
      * drops C:\range-fix.cmd -- a SHORT, TYPEABLE recovery command for the
        logon-screen SYSTEM shell (Win+U / Shift x5), where clipboard paste does
        NOT work. Typing `C:\range-fix.cmd` there repairs analyst and makes a
        `rescue` admin, no paste needed.

    Operator-safety only -- `analyst` is NOT part of the exercise. Standalone (no
    RangeCommon dependency) so it runs reliably at boot. Toggle: Config.OperatorKeeper.
#>
param([switch]$FromBoot, [hashtable]$Config)   # -Config accepted so Invoke-Step can call it; config is read from file below

$ErrorActionPreference = 'Continue'
$RepoRoot = Split-Path $PSScriptRoot -Parent
$cfg = $null
try { $cfg = Import-PowerShellDataFile (Join-Path $RepoRoot 'config\range.config.psd1') } catch {}
$user = if ($cfg -and $cfg.Analyst -and $cfg.Analyst.User)     { $cfg.Analyst.User }     else { 'analyst' }
$pass = if ($cfg -and $cfg.Analyst -and $cfg.Analyst.Password) { [string]$cfg.Analyst.Password } else { 'bb123#123' }

$logDir = 'C:\ProgramData\CyberRange'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$log = Join-Path $logDir 'keeper.log'
function L($m) { $line = ('{0}  {1}' -f (Get-Date -Format s), $m); Write-Host $line; try { Add-Content -Path $log -Value $line } catch {} }

L "operator-keeper start (user=$user, fromBoot=$FromBoot)"
$secure = ConvertTo-SecureString $pass -AsPlainText -Force
$isDC   = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4

# ── Short typeable recovery batch for the logon-screen SYSTEM shell ───────
# NOTE: every `net user` / `net localgroup` / `net accounts` command targets the
# LOCAL SAM, which a domain controller does not have. The original card was
# therefore inert on exactly the host where recovery matters most. The card is now
# role-aware, and step 1 repairs the Kerberos encryption types first -- if the KDC
# has been pinned to RC4-only, NO domain account can log in and no amount of
# account repair helps, because the failure is in the auth protocol, not the account.
if ($isDC) {
    $fix = @"
@echo off
REM Range operator recovery (DOMAIN CONTROLLER) -- run from the logon-screen
REM SYSTEM shell (Win+U or Shift x5). No local SAM here, so `net user` is useless.
echo [1/3] Repairing Kerberos encryption types (RC4+AES) ...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 28 /f
echo [2/3] Removing account lockout and repairing the operator account ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Import-Module ActiveDirectory; Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -LockoutThreshold 0 -ErrorAction SilentlyContinue; Unlock-ADAccount -Identity '$user' -ErrorAction SilentlyContinue"
powershell -NoProfile -ExecutionPolicy Bypass -File C:\CyberRange\scripts\01-analyst-admin.ps1
echo [3/3] REBOOT for the Kerberos change to take effect, then log in as: $user / $pass
echo(
pause
"@
} else {
    $fix = @"
@echo off
REM Range operator recovery -- run from the logon-screen SYSTEM shell (Win+U or Shift x5).
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 28 /f
net user $user "$pass"
net user $user /active:yes
net localgroup administrators $user /add
net user rescue "Rescue#Range2026!" /add
net localgroup administrators rescue /add
net accounts /lockoutthreshold:0
echo(
echo Done. Log in as:  $user / $pass   (or  rescue / Rescue#Range2026!)
pause
"@
}
try { Set-Content -Path 'C:\range-fix.cmd' -Value $fix -Encoding ASCII; L "wrote C:\range-fix.cmd (role-aware: $(if($isDC){'DC'}else{'local'}))" } catch { L "range-fix.cmd write failed: $($_.Exception.Message)" }

# ── Never let a correct password be rejected: disable account lockout ─────
#    `net accounts` edits the LOCAL SAM policy and is a silent no-op on a DC,
#    where lockout comes from the Default Domain Policy instead.
if ($isDC) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -LockoutThreshold 0 -ErrorAction Stop
        L 'domain lockout threshold set to 0'
    } catch { L "domain lockout disable failed (AD not ready yet?): $($_.Exception.Message)" }
} else {
    try { & net.exe accounts /lockoutthreshold:0 2>&1 | Out-Null; L 'local account lockout threshold set to 0' } catch {}
}

# ── Guarantee the KDC can still do AES, every boot ────────────────────────
#    Cheap insurance against a re-run of a weakening script pinning this to RC4-only.
try {
    $kp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    $cur = (Get-ItemProperty -Path $kp -Name SupportedEncryptionTypes -ErrorAction SilentlyContinue).SupportedEncryptionTypes
    if ($null -ne $cur -and -not ([int]$cur -band 0x18)) {   # neither AES128 nor AES256 allowed
        New-Item -Path $kp -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path $kp -Name SupportedEncryptionTypes -PropertyType DWord -Value 0x1C -Force -ErrorAction Stop | Out-Null
        L "REPAIRED Kerberos SupportedEncryptionTypes: $cur -> 28 (RC4+AES). RC4-only breaks every domain logon."
    }
} catch { L "Kerberos etype check failed: $($_.Exception.Message)" }

# ── Assert the operator account for this host role ───────────────────────
if ($isDC) {
    # F28: a DC must resolve DNS via itself, or ADWS never answers. Repair it.
    try {
        $ipv4 = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count }
        if (-not ($ipv4 | Where-Object { $_.ServerAddresses -contains '127.0.0.1' })) {
            $idx = (Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1).InterfaceIndex
            if ($idx) { Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses '127.0.0.1' -ErrorAction SilentlyContinue; & ipconfig /flushdns | Out-Null; L 'repaired DC DNS client -> 127.0.0.1' }
        }
    } catch {}
    $adReady = $false
    for ($i = 0; $i -lt 30; $i++) {
        try { Start-Service NTDS,ADWS,DNS,Netlogon -ErrorAction SilentlyContinue } catch {}
        if ((Get-Service ADWS -ErrorAction SilentlyContinue).Status -eq 'Running') {
            try { Import-Module ActiveDirectory -ErrorAction Stop; Get-ADDomain -ErrorAction Stop | Out-Null; $adReady = $true; break } catch {}
        }
        Start-Sleep -Seconds 5
    }
    if ($adReady) {
        try {
            if (Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue) {
                Set-ADAccountPassword -Identity $user -Reset -NewPassword $secure -ErrorAction Stop
                Set-ADUser -Identity $user -Enabled $true -PasswordNeverExpires $true -ErrorAction Stop
            } else {
                $dom = Get-ADDomain
                New-ADUser -SamAccountName $user -Name $user -UserPrincipalName "$user@$($dom.DNSRoot)" `
                    -AccountPassword $secure -Enabled $true -PasswordNeverExpires $true `
                    -Path $dom.UsersContainer -Description 'RANGE operator admin' -ErrorAction Stop
            }
            try { Unlock-ADAccount -Identity $user -ErrorAction SilentlyContinue } catch {}
            Add-ADGroupMember -Identity 'Domain Admins' -Members $user -ErrorAction SilentlyContinue
            L "domain '$user' asserted (Domain Admins, enabled, unlocked, password set)"
        } catch { L "domain assert failed: $($_.Exception.Message)" }
    } else { L 'AD DS not ready this boot; keeper will retry next boot' }
} else {
    try {
        if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) {
            Set-LocalUser -Name $user -Password $secure -PasswordNeverExpires $true -ErrorAction Stop
            Enable-LocalUser -Name $user -ErrorAction SilentlyContinue
        } else {
            New-LocalUser -Name $user -Password $secure -PasswordNeverExpires -AccountNeverExpires `
                -Description 'RANGE operator admin' -ErrorAction Stop | Out-Null
        }
        if (-not (Get-LocalGroupMember -Group 'Administrators' -Member $user -ErrorAction SilentlyContinue)) {
            Add-LocalGroupMember -Group 'Administrators' -Member $user -ErrorAction SilentlyContinue
        }
        L "local '$user' asserted (Administrators, enabled, password set)"
    } catch { L "local assert failed: $($_.Exception.Message)" }
}

# ── Keep it visible at the sign-in screen ────────────────────────────────
$ul = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
try { if (Test-Path $ul) { Remove-ItemProperty -Path $ul -Name $user -Force -ErrorAction SilentlyContinue } } catch {}

L 'operator-keeper done'
