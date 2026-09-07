#requires -Version 5.1
<#  SETUP step: weaponise the existing directory accounts.

    Stage-CyberRange.ps1 (scripts\directory.ps1) already created these users as
    ORDINARY accounts. This step gives a named subset of them the attributes that
    make them attackable. Nothing here creates a user -- if an account is missing,
    Stage did not complete and this says so rather than inventing one.

    Splitting it this way means the vulnerable accounts are drawn FROM the normal
    population instead of being a separate, obviously-planted set. Finding them is
    then an exercise (enumerate SPNs, check UAC flags) rather than reading a list
    of accounts that all look alike.

      * Kerberoastable service accounts -> SPN set + RC4 forced
        (Rubeus kerberoast / GetUserSPNs.py, crack with hashcat -m 13100)
      * AS-REP roastable users          -> "Do not require Kerberos preauth"
        (Rubeus asreproast / GetNPUsers.py, crack with hashcat -m 18200)
      * Reversible encryption           -> password recoverable as cleartext
      * Password in the description     -> the timeless AD hygiene miss

    Gated by DC.SeedUsers.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'ad-users'
if (-not (Test-IsDomainController)) { Write-RangeLog 'Not a DC; skipping AD user weaponisation.' 'WARN'; return }
if (-not $Config.DC.SeedUsers)      { Write-RangeLog 'DC.SeedUsers=$false; skipping.' 'INFO'; return }
Import-Module ActiveDirectory -Force

$dns    = (Get-ADDomain).DNSRoot
$RC4    = 4   # msDS-SupportedEncryptionTypes = RC4-HMAC (etype 23), the crackable one

function Get-RangeUser {
    param([string]$Sam)
    $u = Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue
    if (-not $u) { Write-RangeLog "account '$Sam' not found -- Stage did not complete. Re-run Stage-CyberRange.ps1." 'ERROR' }
    $u
}

# ── Kerberoastable: SPN + RC4 ────────────────────────────────────────────
#    The RC4 stamp is per-ACCOUNT on purpose. The machine-wide KDC etype list
#    stays RC4+AES (0x1C) -- pinning the whole KDC to RC4-only breaks every
#    domain logon on Server 2025 (F26). Scoping the downgrade to these principals
#    keeps the Kerberoast lesson intact without bricking authentication.
foreach ($svc in @(
    @{ Sam='svc_mssql';  Spn="MSSQLSvc/sql01.${dns}:1433" },
    @{ Sam='svc_web';    Spn="HTTP/web01.$dns" },
    @{ Sam='svc_backup'; Spn="CIFS/backup01.$dns" }
)) {
    if (-not (Get-RangeUser $svc.Sam)) { continue }
    try {
        Set-ADUser -Identity $svc.Sam -ServicePrincipalNames @{ Replace = @($svc.Spn) } -ErrorAction Stop
        Set-ADUser -Identity $svc.Sam -Replace @{ 'msDS-SupportedEncryptionTypes' = $RC4 } -ErrorAction Stop
        Write-RangeManifest $cat 'kerberoastable' $svc.Sam "spn=$($svc.Spn); etype=RC4"
        Write-RangeLog "kerberoastable: $($svc.Sam)  spn=$($svc.Spn)" 'WARN'
    } catch { Write-RangeLog "$($svc.Sam) SPN/etype: $($_.Exception.Message)" 'WARN' }
}

# ── AS-REP roastable: no Kerberos pre-authentication ─────────────────────
foreach ($sam in 'jsmith','agarcia') {
    if (-not (Get-RangeUser $sam)) { continue }
    try {
        Set-ADAccountControl -Identity $sam -DoesNotRequirePreAuth $true -ErrorAction Stop
        Write-RangeManifest $cat 'asrep-roastable' $sam 'DoesNotRequirePreAuth=$true'
        Write-RangeLog "AS-REP roastable: $sam" 'WARN'
    } catch { Write-RangeLog "$sam preauth: $($_.Exception.Message)" 'WARN' }
}

# ── Reversible encryption: password recoverable as cleartext ─────────────
#    The password must be RE-SET after enabling the flag -- AD only stores the
#    reversible copy on the next password write, so flipping the bit alone leaves
#    nothing to recover.
if (Get-RangeUser 'legacyapp') {
    try {
        Set-ADUser -Identity 'legacyapp' -AllowReversiblePasswordEncryption $true -ErrorAction Stop
        Set-ADAccountPassword -Identity 'legacyapp' -Reset `
            -NewPassword (ConvertTo-SecureString 'Legacy!2020' -AsPlainText -Force) -ErrorAction Stop
        Set-ADUser -Identity 'legacyapp' -Description 'Legacy app - reversible encryption required' -ErrorAction SilentlyContinue
        Write-RangeManifest $cat 'reversible-encryption' 'legacyapp' 'pw=Legacy!2020 recoverable as cleartext'
        Write-RangeLog 'reversible encryption: legacyapp' 'WARN'
    } catch { Write-RangeLog "legacyapp reversible: $($_.Exception.Message)" 'WARN' }
}

# ── Password sitting in the description field ────────────────────────────
if (Get-RangeUser 'tmpadmin') {
    try {
        Set-ADUser -Identity 'tmpadmin' -Description 'temp account - pw Spring2025! - remove after migration' -ErrorAction Stop
        Write-RangeManifest $cat 'password-in-description' 'tmpadmin' 'pw=Spring2025! in the description attribute'
        Write-RangeLog 'password-in-description: tmpadmin' 'WARN'
    } catch { Write-RangeLog "tmpadmin description: $($_.Exception.Message)" 'WARN' }
}

Write-RangeLog 'AD user weaponisation complete.' 'OK'
