#requires -Version 5.1
<#  DC step 1: Seed AD with Kerberoast / AS-REP-roast fodder and weak accounts.

    Creates an OU tree, a few groups, and users that model the classic AD
    credential-attack paths students should learn to find and defenders should
    learn to spot:

      * Kerberoastable service accounts  -> SPN set + weak password + RC4 forced
        (Rubeus kerberoast / GetUserSPNs.py, crack with hashcat -m 13100).
      * AS-REP roastable users           -> "Do not require Kerberos preauth"
        (Rubeus asreproast / GetNPUsers.py, crack with hashcat -m 18200).
      * Reversible-encryption user        -> password recoverable as cleartext.
      * Password-in-description user       -> the timeless SYSVOL/AD hygiene miss.
      * An over-privileged "helpdesk" user in a sensitive group.

    All passwords are intentionally weak and are LOGGED to the manifest so
    instructors have an answer key. Gated by DC.SeedUsers.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'dc-users'
if (-not (Test-IsDomainController)) { Write-RangeLog 'Not a DC; skipping dc-users.' 'WARN'; return }
if (-not $Config.DC.SeedUsers)      { Write-RangeLog 'DC.SeedUsers=$false; skipping.' 'INFO'; return }
Import-Module ActiveDirectory -Force

# F31: the seeded accounts below use intentionally weak passwords, several of which
# the DEFAULT domain policy rejects (complexity, min length, and "must not contain
# the account name" -- e.g. helpdesk / 'Helpdesk@1'). Relax the policy first so the
# weak seeds take, whether this script runs via Setup or by hand. dc\40 re-asserts.
try {
    Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot `
        -ComplexityEnabled $false -MinPasswordLength 4 -MinPasswordAge '0.00:00:00' `
        -PasswordHistoryCount 0 -ErrorAction Stop
    Write-RangeLog 'Relaxed domain password policy so weak seeded passwords are accepted (F31).' 'WARN'
} catch { Write-RangeLog "Could not relax password policy: $($_.Exception.Message)" 'WARN' }

$dn     = (Get-ADDomain).DistinguishedName
$domRC4 = 4   # msDS-SupportedEncryptionTypes = RC4-HMAC (etype 23) for easy cracking

# ── OU tree ──────────────────────────────────────────────────────────────
$ouRange = "OU=Range,$dn"
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouRange'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name 'Range' -Path $dn -ProtectedFromAccidentalDeletion $false
    Write-RangeManifest $cat 'new-ou' $ouRange
}
foreach ($sub in 'Service Accounts','Staff') {
    $p = "OU=$sub,$ouRange"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$p'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $sub -Path $ouRange -ProtectedFromAccidentalDeletion $false
        Write-RangeManifest $cat 'new-ou' $p
    }
}
$ouSvc   = "OU=Service Accounts,$ouRange"
$ouStaff = "OU=Staff,$ouRange"

function New-RangeUser {
    param([string]$Sam,[string]$Name,[string]$Pass,[string]$Path,[string]$Desc='',[string[]]$Spn,[switch]$AsRep,[switch]$Reversible,[switch]$Rc4)
    $sec = ConvertTo-SecureString $Pass -AsPlainText -Force
    if (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue) {
        Set-ADAccountPassword -Identity $Sam -Reset -NewPassword $sec -ErrorAction SilentlyContinue
    } else {
        $p = @{ SamAccountName=$Sam; Name=$Name; AccountPassword=$sec; Path=$Path; Enabled=$true
                PasswordNeverExpires=$true; UserPrincipalName="$Sam@$((Get-ADDomain).DNSRoot)" }
        if ($Desc) { $p.Description = $Desc }
        if ($Spn)  { $p.ServicePrincipalNames = $Spn }
        New-ADUser @p
    }
    if ($AsRep)      { Set-ADAccountControl -Identity $Sam -DoesNotRequirePreAuth $true }
    if ($Reversible) { Set-ADUser -Identity $Sam -AllowReversiblePasswordEncryption $true
                       Set-ADAccountPassword -Identity $Sam -Reset -NewPassword $sec }  # re-set so cleartext is stored
    if ($Rc4)        { Set-ADUser -Identity $Sam -Replace @{ 'msDS-SupportedEncryptionTypes' = $domRC4 } }
    Write-RangeManifest $cat 'ad-user' "$Sam" ("pw=$Pass" + $(if($Spn){"; spn=$($Spn -join ',')"}) + $(if($AsRep){'; ASREP'}) + $(if($Reversible){'; REVERSIBLE'}))
    Write-RangeLog "user $Sam  (pw: $Pass)" 'WARN'
}

# ── Kerberoastable service accounts (SPN + weak pw + RC4) ─────────────────
New-RangeUser -Sam 'svc_mssql'  -Name 'svc_mssql'  -Pass 'Summer2024'      -Path $ouSvc -Desc 'SQL Server service account' -Spn @("MSSQLSvc/sql01.$((Get-ADDomain).DNSRoot):1433") -Rc4
New-RangeUser -Sam 'svc_web'    -Name 'svc_web'    -Pass 'Password123!'    -Path $ouSvc -Desc 'IIS app pool identity'      -Spn @("HTTP/web01.$((Get-ADDomain).DNSRoot)") -Rc4
New-RangeUser -Sam 'svc_backup' -Name 'svc_backup' -Pass 'Backup2023'      -Path $ouSvc -Desc 'Backup service'             -Spn @("CIFS/backup01.$((Get-ADDomain).DNSRoot)") -Rc4

# ── AS-REP roastable users (no Kerberos pre-auth) ────────────────────────
New-RangeUser -Sam 'jsmith'  -Name 'Jane Smith'  -Pass 'Autumn2024!' -Path $ouStaff -AsRep -Desc 'Marketing'
New-RangeUser -Sam 'agarcia' -Name 'Ana Garcia'  -Pass 'Welcome1'    -Path $ouStaff -AsRep -Desc 'Finance'

# ── Reversible encryption (cleartext recoverable) ────────────────────────
New-RangeUser -Sam 'legacyapp' -Name 'legacyapp' -Pass 'Legacy!2020' -Path $ouSvc -Reversible -Desc 'Legacy app - reversible encryption required'

# ── Password sitting in the description field ────────────────────────────
New-RangeUser -Sam 'tmpadmin' -Name 'tmpadmin' -Pass 'Spring2025!' -Path $ouStaff -Desc 'temp account - pw Spring2025! - remove after migration'

# ── Over-privileged helpdesk user (lateral/priv-esc target) ──────────────
New-RangeUser -Sam 'helpdesk' -Name 'Help Desk' -Pass 'Helpdesk@1' -Path $ouStaff -Desc 'IT helpdesk'
foreach ($grp in 'Account Operators','Server Operators') {
    try { Add-ADGroupMember -Identity $grp -Members 'helpdesk' -ErrorAction Stop
          Write-RangeManifest $cat 'group-add' "$grp += helpdesk" } catch { Write-RangeLog "group ${grp}: $($_.Exception.Message)" 'WARN' }
}

Write-RangeLog 'DC user-seeding (roast fodder + weak accounts) complete.' 'OK'
