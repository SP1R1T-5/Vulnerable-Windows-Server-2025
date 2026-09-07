#requires -Version 5.1
<#
.SYNOPSIS
    Recover any clone's identity and operator secrets from the master secret.

.DESCRIPTION
    Instructor / range-administrator tool (WP2, closes F16). Every participant VM
    is personalized by Initialize-RangeClone.ps1, which derives its secrets as
    HMAC-SHA256(MasterSecret, "<cloneId>/<purpose>"). Because that derivation is
    deterministic, you never have to record thirty sets of passwords -- you keep
    ONE master secret and recompute any clone on demand.

    Run this on the range-administrator box, NOT on a participant VM: it needs the
    master secret, and the whole point of the scheme is that the master secret
    never touches a student machine.

    This calls the same Get-RangeCloneIdentity in modules\RangeCommon.psm1 that
    Initialize-RangeClone.ps1 used to set the values, so the two cannot drift.

.PARAMETER CloneId
    1-2 digits, 01-99. Omit to list a range of clones with -All.

.PARAMETER MasterSecret
    The range master secret. Prompted for (hidden) if not supplied.

.PARAMETER All
    Emit a table for clones 1..N instead of one clone.

.PARAMETER AsCsv
    Emit CSV, e.g. to build a sealed instructor handout. Treat the output as the
    answer key: it opens every VM in the range.

.EXAMPLE
    .\Get-RangeCloneSecret.ps1 -CloneId 07
    Show clone 07's name, domain and four operator secrets.

.EXAMPLE
    .\Get-RangeCloneSecret.ps1 -All 30 -AsCsv | Set-Content C:\secure\range-keys.csv
    Produce the full instructor key sheet.
#>
[CmdletBinding(DefaultParameterSetName = 'One')]
param(
    [Parameter(ParameterSetName='One', Position=0)][string]$CloneId,
    [Parameter(ParameterSetName='Many')][int]$All,
    [System.Security.SecureString]$MasterSecret,
    [string]$BaseDomain = 'range.lab',
    [switch]$AsCsv
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'modules\RangeCommon.psm1') -Force

if (-not $MasterSecret) { $MasterSecret = Read-Host 'Range master secret' -AsSecureString }
$b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($MasterSecret)
try { $plainMaster = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }

$ids = if ($PSCmdlet.ParameterSetName -eq 'Many') { 1..$All } elseif ($CloneId) { @($CloneId) } else { @(Read-Host 'CloneId (01-99)') }

$out = foreach ($id in $ids) { Get-RangeCloneIdentity -CloneId $id -MasterSecret $plainMaster -BaseDomain $BaseDomain }
$plainMaster = $null

if ($AsCsv) { $out | ConvertTo-Csv -NoTypeInformation; return }

foreach ($o in $out) {
    Write-Host ""
    Write-Host "CLONE $($o.CloneId)" -ForegroundColor Cyan
    Write-Host "  Computer name        : $($o.ComputerName)"
    Write-Host "  Domain (DNS/NetBIOS) : $($o.DomainName) / $($o.NetbiosName)"
    Write-Host "  Administrator        : $($o.AdminPassword)" -ForegroundColor Yellow
    Write-Host "  DSRM                 : $($o.DsrmPassword)" -ForegroundColor Yellow
    Write-Host "  Break-glass          : $($o.BreakGlassPassword)" -ForegroundColor Yellow
    Write-Host "  Analyst (Domain Admin): $($o.AnalystPassword)" -ForegroundColor Yellow
    Write-Host "  Hidden admins        : $($o.HiddenAdminPassword)" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "These open the VM. Handle as answer-key material; do not leave them on a participant box." -ForegroundColor Red
