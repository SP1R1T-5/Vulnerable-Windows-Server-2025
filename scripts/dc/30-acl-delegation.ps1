#requires -Version 5.1
<#  DC step 3: Weak AD ACLs + Kerberos delegation misconfigurations.

    Plants the object-security and delegation mistakes that BloodHound lights up
    and that map to real escalation paths:

      * DCSync         -> a low-priv user granted the two replication extended
                          rights on the domain head (secretsdump.py -just-dc).
      * GenericAll     -> a low-priv user with full control over a privileged
                          group (can add itself -> instant Domain Admin).
      * Unconstrained  -> a service account flagged TrustedForDelegation
        delegation     (printerbug/coerce -> TGT capture).
      * Constrained    -> a service account with msDS-AllowedToDelegateTo +
        delegation       protocol transition (S4U2Self/Proxy abuse).

    Requires the seed users from dc\10. Gated by DC.WeakAcls.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'dc-acl'
if (-not (Test-IsDomainController)) { Write-RangeLog 'Not a DC; skipping ACL/delegation.' 'WARN'; return }
if (-not $Config.DC.WeakAcls)       { Write-RangeLog 'DC.WeakAcls=$false; skipping.' 'INFO'; return }
Import-Module ActiveDirectory -Force

$dom  = Get-ADDomain
$dn   = $dom.DistinguishedName
$nb   = $dom.NetBIOSName

function Test-RangeUser { param($s) [bool](Get-ADUser -Filter "SamAccountName -eq '$s'" -ErrorAction SilentlyContinue) }

# ── DCSync: grant replication extended rights to a low-priv user ─────────
if (Test-RangeUser 'jsmith') {
    foreach ($right in 'Replicating Directory Changes','Replicating Directory Changes All','Replicating Directory Changes In Filtered Set') {
        Invoke-Native 'dsacls.exe' @("$dn", '/G', "$nb\jsmith:CA;$right") $cat
    }
    Write-RangeManifest $cat 'dcsync' "jsmith granted DS-Replication rights on $dn"
    Write-RangeLog 'DCSync rights granted to jsmith.' 'WARN'
} else { Write-RangeLog 'jsmith missing (run dc\10 first) - skipping DCSync grant.' 'WARN' }

# ── GenericAll over a privileged group (self-add to Domain Admins path) ──
if (Test-RangeUser 'agarcia') {
    $grpDN = (Get-ADGroup 'Domain Admins').DistinguishedName
    Invoke-Native 'dsacls.exe' @("$grpDN", '/G', "$nb\agarcia:GA") $cat
    Write-RangeManifest $cat 'genericall' "agarcia -> GenericAll on Domain Admins"
    Write-RangeLog 'GenericAll on Domain Admins granted to agarcia.' 'WARN'
}

# ── Unconstrained delegation on a service account ────────────────────────
if (Test-RangeUser 'svc_web') {
    try { Set-ADAccountControl -Identity 'svc_web' -TrustedForDelegation $true -ErrorAction Stop
          Write-RangeManifest $cat 'unconstrained' 'svc_web TrustedForDelegation=$true'
          Write-RangeLog 'Unconstrained delegation set on svc_web.' 'WARN' } catch { Write-RangeLog "svc_web delegation: $($_.Exception.Message)" 'WARN' }
}

# ── Constrained delegation w/ protocol transition ────────────────────────
if (Test-RangeUser 'svc_mssql') {
    try {
        Set-ADUser -Identity 'svc_mssql' -Add @{ 'msDS-AllowedToDelegateTo' = @("CIFS/dc01.$($dom.DNSRoot)") } -ErrorAction SilentlyContinue
        Set-ADAccountControl -Identity 'svc_mssql' -TrustedToAuthForDelegation $true -ErrorAction SilentlyContinue
        Write-RangeManifest $cat 'constrained' 'svc_mssql -> CIFS/dc01 + protocol transition'
        Write-RangeLog 'Constrained delegation (protocol transition) set on svc_mssql.' 'WARN'
    } catch { Write-RangeLog "svc_mssql constrained delegation: $($_.Exception.Message)" 'WARN' }
}

# ── Machine Account Quota note (default 10 enables RBCD) ──────────────────
$maq = (Get-ADObject -Identity $dn -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
Write-RangeLog "ms-DS-MachineAccountQuota = $maq (default 10 lets any user join computers -> RBCD attack surface). Left as-is." 'WARN'
Write-RangeManifest $cat 'note' "ms-DS-MachineAccountQuota=$maq (RBCD enabler)"

Write-RangeLog 'DC ACL / delegation category complete.' 'OK'
