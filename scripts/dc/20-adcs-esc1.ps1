#requires -Version 5.1
<#  DC step 2: Install an Enterprise CA and publish an ESC1-vulnerable template.

    ESC1 = a certificate template that (a) allows the enrollee to supply the
    subject/SAN, (b) has a client-authentication EKU, (c) needs no manager
    approval and no authorized signatures, and (d) lets low-privileged users
    enroll. A student can then request a cert "as" a Domain Admin and use it to
    authenticate (Certipy/Certify + Rubeus). This is one of the most-taught AD
    escalation paths in current red-vs-blue play.

    Approach: install AD CS (Enterprise Root CA), then CLONE the built-in "User"
    template (which already carries the Client Authentication EKU), flip on
    ENROLLEE_SUPPLIES_SUBJECT, strip manager-approval/authorized-signature
    requirements, grant "Domain Users" Enroll, and publish it to the CA.

    Gated by DC.InstallAdcs. Validate afterwards with:
        certipy find -u <user>@<domain> -p <pw> -dc-ip <dc>   (look for ESC1)
        Certify.exe find /vulnerable
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'dc-adcs'
if (-not (Test-IsDomainController)) { Write-RangeLog 'Not a DC; skipping AD CS.' 'WARN'; return }
if (-not $Config.DC.InstallAdcs)    { Write-RangeLog 'DC.InstallAdcs=$false; skipping.' 'INFO'; return }
Import-Module ActiveDirectory -Force

# ── Install + configure Enterprise Root CA ───────────────────────────────
Install-WindowsFeature ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools | Out-Null
Write-RangeManifest $cat 'install-feature' 'ADCS-Cert-Authority;ADCS-Web-Enrollment'
Import-Module ADCSDeployment -Force
try {
    if (-not (Get-Service CertSvc -ErrorAction SilentlyContinue).Status -or (Get-Service CertSvc).Status -ne 'Running') {
        Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName "$($Config.DC.NetbiosName)-RootCA" -Force -ErrorAction Stop | Out-Null
        Write-RangeManifest $cat 'install-ca' "$($Config.DC.NetbiosName)-RootCA (EnterpriseRoot)"
    }
} catch { Write-RangeLog "CA install (may already exist): $($_.Exception.Message)" 'WARN' }
try { Install-AdcsWebEnrollment -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

# ── Build the ESC1 template by cloning "User" ────────────────────────────
$tplName = 'RangeUserESC1'
$rootDSE = [ADSI]'LDAP://RootDSE'
$confNC  = $rootDSE.configurationNamingContext
$tplCont = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$confNC"
$container = [ADSI]$tplCont

$existing = $container.psbase.Children | Where-Object { $_.Name -eq $tplName }
if ($existing) {
    Write-RangeLog "Template $tplName already exists; re-applying settings." 'INFO'
    $new = [ADSI]"LDAP://CN=$tplName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$confNC"
} else {
    $src = [ADSI]"LDAP://CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,$confNC"
    $new = $container.Create('pKICertificateTemplate', "CN=$tplName")
    # Copy the attributes that make a template valid, from the User template.
    $copy = 'flags','pKIDefaultKeySpec','pKIKeyUsage','pKIMaxIssuingDepth',
            'pKICriticalExtensions','pKIExpirationPeriod','pKIOverlapPeriod',
            'pKIExtendedKeyUsage','pKIDefaultCSPs','msPKI-RA-Signature',
            'msPKI-Minimal-Key-Size','msPKI-Template-Schema-Version',
            'msPKI-Template-Minor-Revision','msPKI-Cert-Template-OID',
            'msPKI-Certificate-Application-Policy','revision'
    foreach ($a in $copy) {
        try { $v = $src.psbase.Properties[$a]; if ($v -and $v.Count) { $new.psbase.Properties[$a].Value = $v.Value } } catch {}
    }
    $new.Put('displayName','Range User ESC1')
    $new.Put('revision', 100)
    $new.CommitChanges()
    Write-RangeManifest $cat 'clone-template' "$tplName (from User)"
}

# ── The ESC1 flips ───────────────────────────────────────────────────────
#  msPKI-Certificate-Name-Flag: 0x1 = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
$ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
$new.Put('msPKI-Certificate-Name-Flag', $ENROLLEE_SUPPLIES_SUBJECT)
#  msPKI-Enrollment-Flag: 0 = no manager approval, no auto-enroll requirement
$new.Put('msPKI-Enrollment-Flag', 0)
#  msPKI-RA-Signature: 0 = no authorized signatures required
$new.Put('msPKI-RA-Signature', 0)
#  Ensure Client Authentication EKU (1.3.6.1.5.5.7.3.2) is present
$clientAuth = '1.3.6.1.5.5.7.3.2'
$ekus = @($new.psbase.Properties['pKIExtendedKeyUsage'].Value) | Where-Object { $_ }
if ($ekus -notcontains $clientAuth) { $new.psbase.Properties['pKIExtendedKeyUsage'].Value = @($clientAuth) }
$new.CommitChanges()

# ── Grant "Domain Users" Enroll on the template ──────────────────────────
$domainSid = (Get-ADDomain).DomainSID.Value
$duSid = New-Object System.Security.Principal.SecurityIdentifier("$domainSid-513")  # Domain Users
$enrollGuid = [GUID]'0e10c968-78fb-11d2-90d4-00c04f79dc55'  # Certificate-Enrollment extended right
try {
    $sd = $new.psbase.ObjectSecurity
    $rule = New-Object System.DirectoryServices.ExtendedRightAccessRule($duSid,'Allow',$enrollGuid)
    $sd.AddAccessRule($rule)
    # Also grant generic Read+Enroll so enumeration tools see it.
    $readRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($duSid,'GenericRead','Allow')
    $sd.AddAccessRule($readRule)
    $new.psbase.ObjectSecurity = $sd
    $new.psbase.CommitChanges()
    Write-RangeManifest $cat 'template-acl' "$tplName Enroll -> Domain Users"
} catch { Write-RangeLog "Template ACL grant failed: $($_.Exception.Message)" 'WARN' }

# ── Publish the template on the CA ───────────────────────────────────────
Start-Sleep -Seconds 3
$published = $false
try { Add-CATemplate -Name $tplName -Force -ErrorAction Stop; $published = $true } catch {}
if (-not $published) {
    Invoke-Native 'certutil.exe' @('-SetCATemplates', "+$tplName") $cat
}
Write-RangeManifest $cat 'publish-template' $tplName
Write-RangeLog "ESC1 template '$tplName' created and published. Verify with certipy/Certify 'find'." 'WARN'
Write-RangeLog 'DC AD CS / ESC1 category complete.' 'OK'
