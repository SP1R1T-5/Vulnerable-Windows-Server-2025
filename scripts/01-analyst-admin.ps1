#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    Provision the stable operator admin account ("analyst") for the cyber range.

.DESCRIPTION
    Creates (or repairs) a standing administrator the build NEVER rewrites, so the
    operator always has a known working login even though the build sets the
    built-in Administrator's password to LocalAdminAutoLogonPass for the
    exposed-credential lesson.

    Role-aware, exactly like the break-glass account:
      * Standalone / member server -> LOCAL user in Administrators (+ Remote
        Desktop Users so it can RDP in).
      * Domain Controller -> DOMAIN user in Domain Admins (local users do not
        survive promotion, so the engine calls this again in Phase 3).

    Sets the password, marks it never-expiring, ensures it is NOT hidden from the
    sign-in screen, and VALIDATES that it authenticates before returning. Runs
    standalone too, so you can create the account on an already-built box:

        .\scripts\01-analyst-admin.ps1

    This script does not weaken the host and is not part of the misconfiguration
    set. It is standalone (no RangeCommon dependency) so it runs on a damaged box.

.PARAMETER User
    Account name. Defaults to Config.Analyst.User, else 'analyst'.

.PARAMETER Password
    SecureString. Omit to use Config.Analyst.Password.

.PARAMETER FromBuild
    Set by Setup-CyberRange.ps1 for unattended calls: no prompts, returns instead
    of calling exit, so a failure surfaces to the orchestrator.
#>
[CmdletBinding()]
param(
    [string]$User,
    [System.Security.SecureString]$Password,
    [switch]$FromBuild
)

$ErrorActionPreference = 'Continue'
$RepoRoot   = Split-Path $PSScriptRoot -Parent
$ConfigPath = Join-Path $RepoRoot 'config\range.config.psd1'
$WinlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$UserListKey = "$WinlogonKey\SpecialAccounts\UserList"

$cfg = $null
try { $cfg = Import-PowerShellDataFile $ConfigPath -ErrorAction Stop } catch {}

if (-not $User) {
    $User = if ($cfg -and $cfg.Analyst -and $cfg.Analyst.User) { $cfg.Analyst.User } else { 'analyst' }
}
if (-not $Password) {
    if ($cfg -and $cfg.Analyst -and $cfg.Analyst.Password) {
        $Password = ConvertTo-SecureString ([string]$cfg.Analyst.Password) -AsPlainText -Force
    } elseif ($FromBuild) {
        Write-Host "analyst: no Config.Analyst.Password and cannot prompt unattended." -ForegroundColor Red
        return
    } else {
        $Password = Read-Host "Password for '$User'" -AsSecureString
    }
}

function ConvertFrom-Secure {
    param([System.Security.SecureString]$S)
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($S)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

$isDC  = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
$plain = ConvertFrom-Secure $Password
$ok    = $true

Write-Host ""
Write-Host "ANALYST ADMIN  --  $env:COMPUTERNAME  --  $(Get-Date -Format s)  --  $(if($isDC){'DOMAIN'}else{'LOCAL'})" -ForegroundColor Cyan

if ($isDC) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $dom = Get-ADDomain -ErrorAction Stop
        if (Get-ADUser -Filter "SamAccountName -eq '$User'" -ErrorAction SilentlyContinue) {
            Set-ADAccountPassword -Identity $User -Reset -NewPassword $Password -ErrorAction Stop
            Set-ADUser -Identity $User -Enabled $true -PasswordNeverExpires $true -ErrorAction Stop
            Write-Host "  domain user '$User' updated" -ForegroundColor Green
        } else {
            New-ADUser -SamAccountName $User -Name $User -UserPrincipalName "$User@$($dom.DNSRoot)" `
                -AccountPassword $Password -Enabled $true -PasswordNeverExpires $true `
                -Path $dom.UsersContainer -Description 'RANGE operator admin (analyst)' `
                -ErrorAction Stop
            Write-Host "  domain user '$User' created" -ForegroundColor Green
        }
        try { Add-ADGroupMember -Identity 'Domain Admins' -Members $User -ErrorAction Stop; Write-Host "  added to Domain Admins" -ForegroundColor Green }
        catch { Write-Host "  Domain Admins: $($_.Exception.Message)" -ForegroundColor Yellow; $ok = $false }
    } catch {
        Write-Host "  domain provisioning FAILED: $($_.Exception.Message)" -ForegroundColor Red; $ok = $false
    }
} else {
    try {
        if (Get-LocalUser -Name $User -ErrorAction SilentlyContinue) {
            Set-LocalUser -Name $User -Password $Password -PasswordNeverExpires $true -ErrorAction Stop
            Enable-LocalUser -Name $User -ErrorAction SilentlyContinue
            Write-Host "  local user '$User' updated" -ForegroundColor Green
        } else {
            New-LocalUser -Name $User -Password $Password -PasswordNeverExpires -AccountNeverExpires `
                -Description 'RANGE operator admin (analyst)' `
                -ErrorAction Stop | Out-Null
            Write-Host "  local user '$User' created" -ForegroundColor Green
        }
        foreach ($g in 'Administrators','Remote Desktop Users') {
            try {
                if (-not (Get-LocalGroupMember -Group $g -Member $User -ErrorAction SilentlyContinue)) {
                    Add-LocalGroupMember -Group $g -Member $User -ErrorAction Stop
                }
                Write-Host "  member of $g" -ForegroundColor Green
            } catch { Write-Host "  $g : $($_.Exception.Message)" -ForegroundColor Yellow; if ($g -eq 'Administrators') { $ok = $false } }
        }
    } catch {
        Write-Host "  local provisioning FAILED: $($_.Exception.Message)" -ForegroundColor Red; $ok = $false
    }
}

# Ensure it is NOT hidden from the sign-in screen (the build hides other accounts).
try {
    if (Test-Path $UserListKey) { Remove-ItemProperty -Path $UserListKey -Name $User -Force -ErrorAction SilentlyContinue }
} catch {}

# Validate that it actually authenticates.
try {
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
    $ctxType = if ($isDC) { 'Domain' } else { 'Machine' }
    $ctx = [System.DirectoryServices.AccountManagement.PrincipalContext]::new($ctxType)
    if ($ctx.ValidateCredentials($User, $plain)) {
        Write-Host "  AUTH VALIDATION: PASS -- '$User' can log in with the configured password." -ForegroundColor Green
    } else {
        Write-Host "  AUTH VALIDATION: FAIL -- '$User' does NOT authenticate. Check password policy." -ForegroundColor Red; $ok = $false
    }
} catch {
    Write-Host "  AUTH VALIDATION: could not test (no directory context); verify by logging in." -ForegroundColor Yellow
}
$plain = $null

Write-Host ""
if ($ok) { Write-Host "analyst admin ready." -ForegroundColor Green }
else     { Write-Host "analyst admin had problems (see above)." -ForegroundColor Red }

if ($FromBuild) { return }
exit ($(if ($ok) { 0 } else { 1 }))
