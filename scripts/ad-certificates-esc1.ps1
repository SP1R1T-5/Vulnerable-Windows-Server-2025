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
# F41: CAPTURE the feature-install result. Install-WindowsFeature returns
# Success=$false WITHOUT throwing, so piping it to Out-Null hid the real failure --
# and then ADCSDeployment/Install-AdcsCertificationAuthority did not exist, no CA
# was configured, and every downstream step (CA, enrollment-service object,
# published template) silently had nothing to build on.
$feat = $null
try { $feat = Install-WindowsFeature ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools -ErrorAction Stop }
catch { Write-RangeLog "AD CS feature install threw: $($_.Exception.Message)" 'ERROR' }
if ($feat) {
    Write-RangeLog ("AD CS feature install: Success=$($feat.Success) ExitCode=$($feat.ExitCode) RestartNeeded=$($feat.RestartNeeded)") $(if ($feat.Success) { 'OK' } else { 'ERROR' })
}
Write-RangeManifest $cat 'install-feature' "ADCS-Cert-Authority;ADCS-Web-Enrollment (Success=$($feat.Success);Restart=$($feat.RestartNeeded))"

# The ADCSDeployment module ships WITH the role's management tools. If it is not
# importable, the role did not actually land -- almost always a pending reboot from
# promotion, or the role payload was removed from this image (ExitCode above says
# which). Configuring the CA is impossible until that is fixed, so say so clearly
# and skip the CA steps -- but still apply the CA-independent downgrades below.
Import-Module ADCSDeployment -Force -ErrorAction SilentlyContinue
$adcsReady = [bool](Get-Module ADCSDeployment)
if (-not $adcsReady) {
    Write-RangeLog 'AD CS role is NOT installed (ADCSDeployment module missing) -- the feature install did not complete.' 'ERROR'
    Write-RangeLog '  Recover on the box:  Install-WindowsFeature ADCS-Cert-Authority,ADCS-Web-Enrollment -IncludeManagementTools' 'WARN'
    Write-RangeLog '  If RestartNeeded=Yes, reboot; if ExitCode is 0x800f081f the payload is absent (needs -Source).' 'WARN'
    Write-RangeLog '  Then re-run:  .\scripts\ad-certificates-esc1.ps1' 'WARN'
} else {
    try {
        $svc = Get-Service CertSvc -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -ne 'Running') {
            Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName "$($Config.DC.NetbiosName)-RootCA" -Force -ErrorAction Stop | Out-Null
            Write-RangeManifest $cat 'install-ca' "$($Config.DC.NetbiosName)-RootCA (EnterpriseRoot)"
        }
    } catch { Write-RangeLog "CA configuration failed: $($_.Exception.Message)" 'WARN' }
    try { Install-AdcsWebEnrollment -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
}

# ── DC auth downgrades that make the cert/LDAP attacks actually work ──────
# F8a: Server 2025 defaults Kdc\StrongCertificateBindingEnforcement to 2 (Full
# Enforcement) -- a cert with no SID extension is REJECTED for PKINIT, so ESC1
# certs do not authenticate. 1 = Compatibility, which allows the classic ESC1.
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'StrongCertificateBindingEnforcement' DWord 1 $cat
# F11: LDAP channel binding is enforced by default on 2025, which blocks LDAPS
# relay. Turn it off (0) so relay is exercisable. (LDAP signing lives in dc\40.)
Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding' DWord 0 $cat

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
    # F8b: msPKI-Cert-Template-OID is deliberately NOT copied -- every template
    # needs its OWN unique OID, or the CA cannot resolve which template an OID
    # refers to and enrollment breaks. A fresh OID is minted below.
    # msPKI-Private-Key-Flag was missing here, and it is mandatory for a V2+
    # template. Without it certutil rejects the object -- which is exactly the
    # "RangeUserESC1: Invalid Template / ERROR_NOT_FOUND (0x80070490)" seen from
    # `certutil -SetCATemplates +RangeUserESC1` in the field.
    $copy = 'flags','pKIDefaultKeySpec','pKIKeyUsage','pKIMaxIssuingDepth',
            'pKICriticalExtensions','pKIExpirationPeriod','pKIOverlapPeriod',
            'pKIExtendedKeyUsage','pKIDefaultCSPs','msPKI-RA-Signature',
            'msPKI-Minimal-Key-Size','msPKI-Template-Schema-Version',
            'msPKI-Template-Minor-Revision','msPKI-Private-Key-Flag',
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

# ── Make this a coherent V2 template, not a V1/V2 hybrid ─────────────────
#    The built-in "User" template is schema version 1. Cloning it and then
#    setting msPKI-Certificate-Name-Flag / msPKI-Enrollment-Flag /
#    msPKI-RA-Signature -- all V2 concepts -- produces an object that declares V1
#    while carrying V2 attributes. certutil validates the template against its
#    declared schema version and rejects the mismatch as "Invalid Template",
#    which is why publication failed with ERROR_NOT_FOUND even though the object
#    existed in AD and every individual ESC1 attribute checked out.
#    Declare V2 and guarantee the attributes V2 requires.
$schemaV2 = 2
$new.Put('msPKI-Template-Schema-Version', $schemaV2)
# Logged so the build log PROVES this version of the script ran. A stale staged
# copy at C:\CyberRange silently re-running the old logic is otherwise impossible
# to tell apart from the fix not working.
Write-RangeLog "Declaring $tplName as schema version $schemaV2 (V2) with the V2 attribute set (F34)." 'WARN'
if (-not $new.psbase.Properties['msPKI-Private-Key-Flag'].Value) {
    $new.Put('msPKI-Private-Key-Flag', 0x10)          # CT_FLAG_EXPORTABLE_KEY
}
if (-not $new.psbase.Properties['msPKI-Minimal-Key-Size'].Value) {
    $new.Put('msPKI-Minimal-Key-Size', 2048)
}
if (-not $new.psbase.Properties['msPKI-Template-Minor-Revision'].Value) {
    $new.Put('msPKI-Template-Minor-Revision', 1)
}
$new.CommitChanges()

# ── F8b: give the template its OWN unique OID (mint an msPKI-Enterprise-Oid) ──
# Sharing the User template's OID breaks CA template resolution. Mint a new OID
# under the forest OID container and point the template at it.
try {
    $oidCont = [ADSI]"LDAP://CN=OID,CN=Public Key Services,CN=Services,$confNC"

    # F8b-2: mint ONLY IF the template does not already own a unique OID.
    # This block used to mint unconditionally, so every re-run changed the
    # template's identity out from under the CA (the field runs showed a
    # different OID each time) and littered the OID container with orphaned
    # msPKI-Enterprise-Oid objects. A CA that has cached the previous OID can
    # then refuse to publish. Reuse is the correct behaviour; the only OID we
    # must never keep is the one inherited from the User template.
    $userOid = $null
    try {
        $userTpl = [ADSI]"LDAP://CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,$confNC"
        $userOid = [string]$userTpl.psbase.Properties['msPKI-Cert-Template-OID'].Value
    } catch {}
    # An ADSI object bound by path loads its property cache lazily; reading a
    # property before the cache is populated returns $null, which would look like
    # "no OID yet" and mint a fresh one on every run. Force the read.
    try { $new.psbase.RefreshCache() } catch {}
    $currentOid = [string]$new.psbase.Properties['msPKI-Cert-Template-OID'].Value
    if ($currentOid -and ($currentOid -ne $userOid)) {
        Write-RangeLog "Template $tplName already has its own OID ($currentOid); keeping it." 'INFO'
        Write-RangeManifest $cat 'template-oid' "$tplName -> $currentOid (existing, reused)"
        $skipMint = $true
    } else { $skipMint = $false }

    $forestBase = $oidCont.psbase.Properties['msPKI-Cert-Template-OID'].Value
    if (-not $forestBase) { $forestBase = '1.3.6.1.4.1.311.21.8' }   # generic fallback base
    $a1 = Get-Random -Minimum 10000000 -Maximum 99999999
    $a2 = Get-Random -Minimum 10000000 -Maximum 99999999
    $newOid = "$forestBase.$a1.$a2"
    if (-not $skipMint) {
        $oidObj = $oidCont.Create('msPKI-Enterprise-Oid', "CN=$a1.$a2")
        $oidObj.Put('msPKI-Cert-Template-OID', $newOid)
        $oidObj.Put('flags', 1)                       # 1 = this OID names a certificate template
        $oidObj.Put('displayName', 'Range User ESC1')
        $oidObj.CommitChanges()
        $new.Put('msPKI-Cert-Template-OID', $newOid)
        $new.CommitChanges()
        Write-RangeManifest $cat 'template-oid' "$tplName -> $newOid (newly minted)"
        Write-RangeLog "Minted unique template OID $newOid for $tplName." 'WARN'
    }
} catch { Write-RangeLog "Unique-OID mint failed (template may share User's OID): $($_.Exception.Message)" 'WARN' }

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

# ── Publish the template on the CA, then VERIFY (F8) ─────────────────────
# "Created in AD" is NOT the same as "enrollable on the CA". Publishing means the
# template CN is listed in the pKIEnrollmentService object's certificateTemplates
# attribute -- that AD write is the authoritative act, and it is the most reliable
# path (certutil/Add-CATemplate can silently no-op if the CA has not yet cached
# the template). We write it directly via ADSI, then also drive the certutil path,
# then restart CertSvc so its in-memory template list re-reads, then verify.
for ($i = 0; $i -lt 12 -and (Get-Service CertSvc -ErrorAction SilentlyContinue).Status -ne 'Running'; $i++) { Start-Sleep 5 }

# 1. Authoritative: append the template CN to every CA's enrollment-service object.
try {
    $esCont = [ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$confNC"
    $published = $false
    foreach ($ca in $esCont.psbase.Children) {
        $tpls = @($ca.psbase.Properties['certificateTemplates'].Value) | Where-Object { $_ }
        if ($tpls -notcontains $tplName) {
            $ca.psbase.Properties['certificateTemplates'].Add($tplName) | Out-Null
            $ca.psbase.CommitChanges()
        }
        $published = $true
        Write-RangeLog "Published $tplName on CA '$($ca.Name)' via pKIEnrollmentService.certificateTemplates." 'WARN'
    }
    if (-not $published) { Write-RangeLog 'No pKIEnrollmentService object found under Enrollment Services -- is CertSvc configured?' 'ERROR' }
} catch { Write-RangeLog "ADSI publish to enrollment service failed: $($_.Exception.Message)" 'WARN' }

# 2. Also drive the certutil/PS path (harmless if step 1 already did it).
try { Add-CATemplate -Name $tplName -Force -ErrorAction Stop } catch {}
Invoke-Native 'certutil.exe' @('-SetCATemplates', "+$tplName") $cat

# 3. Restart the CA so its cached template list re-reads AD, then verify.
try { Restart-Service CertSvc -ErrorAction SilentlyContinue } catch {}
for ($i = 0; $i -lt 12 -and (Get-Service CertSvc -ErrorAction SilentlyContinue).Status -ne 'Running'; $i++) { Start-Sleep 5 }
Start-Sleep -Seconds 5
$catOut = (& certutil.exe -CATemplates 2>&1) -join "`n"
if ($catOut -match [regex]::Escape($tplName)) {
    Write-RangeManifest $cat 'publish-template' "$tplName (published + verified)"
    Write-RangeLog "ESC1 template '$tplName' is published on the CA (verified via certutil -CATemplates)." 'OK'
} else {
    Write-RangeManifest $cat 'publish-template-FAILED' $tplName 'not listed by certutil -CATemplates'
    Write-RangeLog "ESC1 template '$tplName' did NOT publish. Retry: certutil -SetCATemplates +$tplName ; Restart-Service CertSvc. Then confirm with 'certipy find -vulnerable'." 'ERROR'
}
# F35: Install-WindowsFeature above re-enables wuauserv via the servicing
# stack. Put the update lockdown back before we leave.
Disable-RangeUpdateServices -Because 'AD CS role install'

Write-RangeLog 'DC AD CS / ESC1 category complete.' 'OK'
