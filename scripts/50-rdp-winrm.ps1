#requires -Version 5.1
<#  Category: RDP + WinRM / PowerShell Remoting

    Opens remote access wide: RDP with NLA off and no password prompt, WinRM
    with unencrypted + Basic + CredSSP. All still valid on Server 2025.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'rdp-winrm'

# ── RDP: enabled, NLA off, low security layer, no password prompt ────────
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' DWord 0 $cat
$rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
Set-RegValue $rdp 'UserAuthentication' DWord 0 $cat   # NLA off
Set-RegValue $rdp 'SecurityLayer'      DWord 0 $cat   # RDP security layer (not TLS)
Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fPromptForPassword' DWord 0 $cat
try { Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction Stop }
catch { Invoke-Native 'netsh.exe' @('advfirewall','firewall','set','rule','group=remote desktop','new','enable=Yes') $cat }

# ── WinRM / PowerShell Remoting: weak transport + auth ───────────────────
try {
    Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop
    Set-Item WSMan:\localhost\Service\AllowUnencrypted   $true  -Force
    Set-Item WSMan:\localhost\Service\Auth\Basic         $true  -Force
    Set-Item WSMan:\localhost\Service\Auth\CredSSP        $true  -Force
    Set-Item WSMan:\localhost\Client\AllowUnencrypted    $true  -Force
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*'    -Force
    Write-RangeManifest $cat 'winrm' 'AllowUnencrypted+Basic+CredSSP+TrustedHosts=*'
} catch { Write-RangeLog "WinRM config: $($_.Exception.Message)" 'WARN' }

# Unrestricted execution policy (machine scope)
try { Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force -ErrorAction Stop } catch {}
Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' 'ExecutionPolicy' String 'Unrestricted' $cat

Write-RangeLog 'RDP + WinRM category complete.' 'OK'
