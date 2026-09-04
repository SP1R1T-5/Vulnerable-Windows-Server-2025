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

# 1. Make the credential real.
Write-RangeLog "Setting '$alUser' password to LocalAdminAutoLogonPass so autologon cannot diverge (F1)." 'WARN'
$secure = ConvertTo-SecureString $alPass -AsPlainText -Force
try {
    if ($onDC) {
        Import-Module ActiveDirectory -ErrorAction Stop
        Set-ADAccountPassword -Identity $alUser -Reset -NewPassword $secure -ErrorAction Stop
        Set-ADUser -Identity $alUser -PasswordNeverExpires $true -ErrorAction SilentlyContinue
    } else {
        Set-LocalUser -Name $alUser -Password $secure -PasswordNeverExpires $true -ErrorAction Stop
        Enable-LocalUser -Name $alUser -ErrorAction SilentlyContinue
    }
    Write-RangeManifest $cat 'set-password' $alUser 'set to LocalAdminAutoLogonPass (autologon consistency)'
} catch {
    Write-RangeLog "Could not set password for '$alUser': $($_.Exception.Message)" 'ERROR'
}

# 2. Prove it authenticates before trusting it.
$authOk = $null
try {
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
    $ctx = [System.DirectoryServices.AccountManagement.PrincipalContext]::new($(if ($onDC) { 'Domain' } else { 'Machine' }))
    $authOk = $ctx.ValidateCredentials($alUser, $alPass)
} catch {
    Write-RangeLog "Could not validate '$alUser' credential: $($_.Exception.Message)" 'WARN'
}

Set-RegValue $wl 'DefaultUserName'   String $alUser   $cat
Set-RegValue $wl 'DefaultDomainName' String $alDomain $cat   # F1: was never set -> autologon failed post-promotion
Set-RegValue $wl 'DefaultPassword'   String $alPass   $cat   # the teaching artifact: cleartext in the registry

if ($authOk -eq $true) {
    Set-RegValue $wl 'AutoAdminLogon' String '1' $cat
    Write-RangeLog "Autologon ENABLED for $alDomain\$alUser (credential validated)." 'WARN'
} else {
    Set-RegValue $wl 'AutoAdminLogon' String '0' $cat
    Write-RangeLog "Autologon NOT enabled: '$alUser' did not validate. DefaultPassword is still exposed in the registry for the exercise, but the box will show a normal logon screen." 'ERROR'
    Write-RangeManifest $cat 'autologon-withheld' $alUser 'credential validation failed; AutoAdminLogon=0 to avoid lockout'
}

# 3. ForceAutoLogon is never set, and is stripped if a previous run left it.
try {
    Remove-ItemProperty -Path $wl -Name 'ForceAutoLogon' -Force -ErrorAction Stop
    Write-RangeManifest $cat 'remove-reg' "$wl\ForceAutoLogon" 'lockout safety (F1)'
    Write-RangeLog 'Removed ForceAutoLogon left behind by an earlier run.' 'WARN'
} catch { }   # not present is the normal, desired case

# Weak Kerberos on the local machine: allow RC4 (0x4). NOTE: DES (0x1/0x2) is
# effectively removed on 2025 — the original "/d 4 = DES" comment was wrong;
# 0x4 is RC4-HMAC, which is the realistic downgrade for Kerberoast practice.
Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes' DWord 4 $cat

Write-RangeLog 'Credential-exposure category complete.' 'OK'
