#requires -Version 5.1
<#  STAGE step: the directory population -- OUs, groups, staff and service accounts.

    Called by Stage-CyberRange.ps1 once the DC is up. Everything created here is
    an ORDINARY account in an ORDINARY OU tree. Nothing is weakened:

      * no SPNs (Kerberoast)          -- Setup stamps those
      * no "no pre-auth" flag (AS-REP) -- Setup sets that
      * no reversible encryption       -- Setup enables that
      * no password in the description -- Setup writes that

    Setup-CyberRange.ps1 weaponises a named subset of these SAME accounts. That
    is the point of the split: the vulnerable users are drawn FROM the normal
    population rather than standing out as a separate obvious set, so finding
    them is an exercise rather than a formality.

    The passwords ARE weak, deliberately -- they are the crackable material the
    range is built on, and they are logged to the manifest as the answer key.
    Stage relaxes the domain password policy first so they are accepted (F31).

    Gated by DC.SeedUsers.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext
}
$cat = 'directory'
if (-not (Test-IsDomainController)) { Write-RangeLog 'Not a DC; skipping the directory population.' 'WARN'; return }
Import-Module ActiveDirectory -Force

$dn   = (Get-ADDomain).DistinguishedName
$dns  = (Get-ADDomain).DNSRoot

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
    <# Idempotent: an existing account has its password re-set rather than being
       recreated, so re-running Stage does not disturb SIDs or group membership. #>
    param([string]$Sam, [string]$Name, [string]$Pass, [string]$Path, [string]$Desc = '')
    $sec = ConvertTo-SecureString $Pass -AsPlainText -Force
    if (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue) {
        Set-ADAccountPassword -Identity $Sam -Reset -NewPassword $sec -ErrorAction SilentlyContinue
    } else {
        $p = @{ SamAccountName=$Sam; Name=$Name; AccountPassword=$sec; Path=$Path; Enabled=$true
                PasswordNeverExpires=$true; UserPrincipalName="$Sam@$dns" }
        if ($Desc) { $p.Description = $Desc }
        try { New-ADUser @p } catch { Write-RangeLog "user ${Sam}: $($_.Exception.Message)" 'WARN'; return }
    }
    Write-RangeManifest $cat 'ad-user' $Sam "pw=$Pass"
    Write-RangeLog "user $Sam  (pw: $Pass)" 'WARN'
}

# ── Service accounts ─────────────────────────────────────────────────────
#    Setup gives svc_* their SPNs and RC4 stamp (Kerberoast), and turns on
#    reversible encryption for legacyapp.
New-RangeUser -Sam 'svc_mssql'  -Name 'svc_mssql'  -Pass 'Summer2024'   -Path $ouSvc -Desc 'SQL Server service account'
New-RangeUser -Sam 'svc_web'    -Name 'svc_web'    -Pass 'Password123!' -Path $ouSvc -Desc 'IIS app pool identity'
New-RangeUser -Sam 'svc_backup' -Name 'svc_backup' -Pass 'Backup2023'   -Path $ouSvc -Desc 'Backup service'
New-RangeUser -Sam 'legacyapp'  -Name 'legacyapp'  -Pass 'Legacy!2020'  -Path $ouSvc -Desc 'Legacy line-of-business application'

# ── Staff ────────────────────────────────────────────────────────────────
#    Setup disables Kerberos pre-auth on jsmith and agarcia (AS-REP roast) and
#    writes the password into tmpadmin's description.
New-RangeUser -Sam 'jsmith'   -Name 'Jane Smith' -Pass 'Autumn2024!' -Path $ouStaff -Desc 'Marketing'
New-RangeUser -Sam 'agarcia'  -Name 'Ana Garcia' -Pass 'Welcome1'    -Path $ouStaff -Desc 'Finance'
New-RangeUser -Sam 'tmpadmin' -Name 'tmpadmin'   -Pass 'Spring2025!' -Path $ouStaff -Desc 'Temporary account - remove after migration'
New-RangeUser -Sam 'helpdesk' -Name 'Help Desk'  -Pass 'Helpdesk@1'  -Path $ouStaff -Desc 'IT helpdesk'

# ── Group membership ─────────────────────────────────────────────────────
#    'helpdesk' in Account Operators / Server Operators is over-privileged, and
#    is a lateral-movement and priv-esc target. It is created here because it is
#    an ordinary (if badly governed) directory decision -- exactly the kind of
#    thing a real environment accumulates.
foreach ($grp in 'Account Operators','Server Operators') {
    try {
        if (-not (Get-ADGroupMember -Identity $grp -ErrorAction SilentlyContinue | Where-Object { $_.SamAccountName -eq 'helpdesk' })) {
            Add-ADGroupMember -Identity $grp -Members 'helpdesk' -ErrorAction Stop
        }
        Write-RangeManifest $cat 'group-add' "$grp += helpdesk"
    } catch { Write-RangeLog "group ${grp}: $($_.Exception.Message)" 'WARN' }
}

Write-RangeLog 'Directory population complete (OUs, groups, staff and service accounts).' 'OK'
