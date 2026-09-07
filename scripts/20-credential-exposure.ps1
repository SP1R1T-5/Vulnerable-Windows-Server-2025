#requires -Version 5.1
<#  Category: Credential exposure (LSASS plaintext, weak hashes, autologon)

    Classic credential-theft surface. All of these still work on Server 2025.
    (LSA-Protection / Credential-Guard / UAC live in 30-uac-lsa-vbs.ps1.)
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'credential-exposure'
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

# WDigest — caches plaintext credentials in LSASS (mimikatz sekurlsa::wdigest)
$wd = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
Set-RegValue $wd 'UseLogonCredential' DWord 1 $cat
Set-RegValue $wd 'Negotiate'          DWord 1 $cat

# Weak hashing / auth downgrade
Set-RegValue $lsa 'NoLmHash'            DWord 0 $cat   # store the crackable LM hash
Set-RegValue $lsa 'LmCompatibilityLevel' DWord 0 $cat # send LM & NTLMv1, never refuse

# Anonymous / null enumeration of SAM + shares
Set-RegValue $lsa 'RestrictAnonymous'        DWord 0 $cat
Set-RegValue $lsa 'RestrictAnonymousSAM'     DWord 0 $cat
Set-RegValue $lsa 'EveryoneIncludesAnonymous' DWord 1 $cat

# Large cached-logon count (offline cracking of cached domain creds)
Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount' String '50' $cat

# ── AutoLogon: password in cleartext in the registry ─────────────────────
#    LOCKOUT SAFETY (finding F1). The teaching artifact -- a readable plaintext
#    DefaultPassword -- is unchanged. What changed is the three ways this used to
#    lock the operator out:
#
#      1. SET the account's password to the configured value first, so the real
#         credential and the registry value can never diverge.
#      2. VALIDATE that credential; only enable autologon if it authenticates.
#      3. NEVER write ForceAutoLogon (and remove it if an earlier run left it).
#         With AutoAdminLogon alone, a failed autologon drops you at the logon
#         screen instead of retrying forever.
#
#    NOTE: this script is re-run by the orchestrator AFTER DC promotion, because
#    DefaultDomainName differs once the local SAM is gone.
$wl      = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$alUser  = $Config.LocalAdminAutoLogonUser
$alPass  = $Config.LocalAdminAutoLogonPass
$onDC    = Test-IsDomainController
$alDomain = if ($onDC) { $Config.DC.NetbiosName } else { '.' }

# 1. Make the credential real. This SET is the authoritative action -- if it
#    succeeds, the account's password IS $alPass, full stop.
Write-RangeLog "Setting '$alUser' password to LocalAdminAutoLogonPass so autologon cannot diverge (F1)." 'WARN'
$secure = ConvertTo-SecureString $alPass -AsPlainText -Force
$pwSet  = $false
try {
    if ($onDC) {
        Import-Module ActiveDirectory -ErrorAction Stop
        Set-ADAccountPassword -Identity $alUser -Reset -NewPassword $secure -ErrorAction Stop
        Set-ADUser -Identity $alUser -Enabled $true -PasswordNeverExpires $true -ErrorAction SilentlyContinue
    } else {
        Set-LocalUser -Name $alUser -Password $secure -PasswordNeverExpires $true -ErrorAction Stop
        Enable-LocalUser -Name $alUser -ErrorAction SilentlyContinue
    }
    $pwSet = $true
    Write-RangeManifest $cat 'set-password' $alUser 'set to LocalAdminAutoLogonPass (autologon consistency)'
} catch {
    Write-RangeLog "Could not set password for '$alUser': $($_.Exception.Message)" 'ERROR'
}

# 2. Validate -- INFORMATIONAL ONLY. ValidateCredentials(Machine) performs a
#    NETWORK logon, which a hardened/UAC box routinely denies for a LOCAL account
#    even when the password is correct (a false negative; interactive login is
#    unaffected). We just set the password ourselves, so we do not gate on this.
$authOk = $null
try {
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
    $ctx = [System.DirectoryServices.AccountManagement.PrincipalContext]::new($(if ($onDC) { 'Domain' } else { 'Machine' }))
    $authOk = $ctx.ValidateCredentials($alUser, $alPass)
} catch {
    Write-RangeLog "Could not validate '$alUser' credential (informational): $($_.Exception.Message)" 'WARN'
}

Set-RegValue $wl 'DefaultUserName'   String $alUser   $cat
Set-RegValue $wl 'DefaultDomainName' String $alDomain $cat   # F1: was never set -> autologon failed post-promotion
Set-RegValue $wl 'DefaultPassword'   String $alPass   $cat   # the teaching artifact: cleartext in the registry

# 3. Enable autologon when the password was SET (authoritative) or it validated.
#    Safe because ForceAutoLogon is never written (below): a wrong autologon
#    password can only drop to the logon screen, never loop. Only withhold if the
#    SET itself failed AND validation did not pass.
if ($pwSet -or $authOk -eq $true) {
    Set-RegValue $wl 'AutoAdminLogon' String '1' $cat
    $note = if ($authOk -eq $true) { 'credential validated' }
            elseif ($authOk -eq $false) { 'password set; network-logon validate returned false, which is a known false negative for local accounts -- interactive login is unaffected' }
            else { 'password set; validation unavailable' }
    Write-RangeLog "Autologon ENABLED for $alDomain\$alUser ($note)." 'WARN'
} else {
    Set-RegValue $wl 'AutoAdminLogon' String '0' $cat
    Write-RangeLog "Autologon NOT enabled: could not SET '$alUser' password and it did not validate. DefaultPassword is still exposed for the exercise; log in as analyst, or via the logon-screen accessibility shell." 'ERROR'
    Write-RangeManifest $cat 'autologon-withheld' $alUser 'password set failed AND validation failed; AutoAdminLogon=0'
}

# 3. ForceAutoLogon is never set, and is stripped if a previous run left it.
try {
    Remove-ItemProperty -Path $wl -Name 'ForceAutoLogon' -Force -ErrorAction Stop
    Write-RangeManifest $cat 'remove-reg' "$wl\ForceAutoLogon" 'lockout safety (F1)'
    Write-RangeLog 'Removed ForceAutoLogon left behind by an earlier run.' 'WARN'
} catch { }   # not present is the normal, desired case

# ── Weak Kerberos: ALLOW RC4 in addition to AES ──────────────────────────
#    This is "Network security: Configure encryption types allowed for Kerberos".
#    It is an ALLOW-LIST, not a preference, and it applies to this machine.
#
#    DO NOT set this to 4. 0x4 is RC4-HMAC *only*, with AES128 (0x8) and AES256
#    (0x10) cleared. On a standalone box that is survivable, but this script is
#    deliberately re-run after DC promotion -- and a domain controller that
#    supports only RC4 cannot complete Kerberos AS/TGS exchanges on Server 2025,
#    where RC4 is deprecated and disabled by default. Every domain logon then
#    fails, including Administrator and the operator account, with no local SAM
#    left to fall back on. That is the "locked out of everything after the second
#    reboot" failure: it cannot appear before promotion, because local accounts
#    authenticate over NTLM rather than Kerberos.
#
#    0x1C = RC4 (0x4) + AES128 (0x8) + AES256 (0x10). RC4 stays available, so the
#    Kerberoast downgrade still works -- dc\10 stamps msDS-SupportedEncryptionTypes
#    = 4 on the svc_* accounts individually, which is what forces an RC4 (etype 23,
#    hashcat -m 13100) service ticket for exactly those principals. The weakness is
#    scoped to the target accounts instead of breaking the whole KDC.
$RC4_PLUS_AES = 0x1C
Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes' DWord $RC4_PLUS_AES $cat

Write-RangeLog 'Credential-exposure category complete.' 'OK'
