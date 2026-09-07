#requires -Version 5.1
<#  Category: Legacy / vulnerable services + shares

    2025 notes vs 2019 baseline:
      * TELNET SERVER (TlntSvr) no longer ships as a Windows feature — the old
        `Install-WindowsFeature Telnet-Server` fails. Left as a documented,
        commented manual option (bring your own daemon). Telnet CLIENT is still
        an optional feature.
      * SNMP moved to Features-on-Demand; `Install-WindowsFeature SNMP-Service`
        may fail, so we try Add-WindowsCapability first and fall back.
      * WMIC is deprecated / a FoD and may be absent — this build never uses it.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'legacy-services'

# ── SNMP with default community string (recon practice) ──────────────────
$snmpInstalled = $false
try {
    $cap = Get-WindowsCapability -Online -Name 'SNMP.Server*' -ErrorAction Stop | Select-Object -First 1
    if ($cap -and $cap.State -ne 'Installed') { Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop | Out-Null }
    $snmpInstalled = $true; Write-RangeManifest $cat 'install-capability' $cap.Name
} catch {
    try { Install-WindowsFeature SNMP-Service -IncludeManagementTools -ErrorAction Stop | Out-Null; $snmpInstalled = $true }
    catch { Write-RangeLog "SNMP unavailable on this build: $($_.Exception.Message)" 'WARN' }
}
if ($snmpInstalled) {
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities' 'public' DWord 4 $cat  # 4 = READ ONLY
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers' '1' String '0.0.0.0' $cat
    try { Set-Service SNMP -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service SNMP -ErrorAction SilentlyContinue } catch {}
}

# ── TFTP client (file-staging practice) ──────────────────────────────────
try { Install-WindowsFeature TFTP-Client -ErrorAction Stop | Out-Null; Write-RangeManifest $cat 'install-feature' 'TFTP-Client' }
catch { Write-RangeLog "TFTP-Client feature not installed: $($_.Exception.Message)" 'WARN' }

# ── Windows PowerShell v2 engine (downgrade / logging-bypass practice) ────
try {
    Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop | Out-Null
    Write-RangeManifest $cat 'enable-feature' 'PowerShell v2 engine'
} catch { Write-RangeLog "PSv2 engine not enabled: $($_.Exception.Message)" 'WARN' }

# ── Telnet SERVER: removed from modern Windows Server. Manual option only ──
Write-RangeLog 'Telnet Server feature is not available on Server 2025; skipping. Supply a 3rd-party telnetd manually if a plaintext service is required.' 'WARN'

# ── Over-shared folders incl. a deceptively named share ──────────────────
New-Item -ItemType Directory -Path 'C:\Public' -Force | Out-Null
'Range public share - drop files here.' | Set-Content 'C:\Public\README.txt'
Invoke-Native 'icacls.exe' @('C:\Public','/grant','Everyone:(OI)(CI)F') $cat
foreach ($share in @(@{N='Public';P='C:\Public'}, @{N='SYSVOL$';P='C:\Public'})) {
    if (-not (Get-SmbShare -Name $share.N -ErrorAction SilentlyContinue)) {
        try { New-SmbShare -Name $share.N -Path $share.P -FullAccess 'Everyone' -ErrorAction Stop | Out-Null
              Write-RangeManifest $cat 'smb-share' "$($share.N) -> $($share.P) (Everyone:Full)" }
        catch { Write-RangeLog "share $($share.N): $($_.Exception.Message)" 'WARN' }
    }
}

# F35: the SNMP capability / TFTP + PSv2 feature installs above go through the
# servicing stack, which re-enables wuauserv.
Disable-RangeUpdateServices -Because 'legacy feature/capability installs'

Write-RangeLog 'Legacy-services category complete.' 'OK'
