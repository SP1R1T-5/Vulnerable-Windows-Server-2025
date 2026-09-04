#requires -Version 5.1
<#  DC step 4: Legacy Group Policy artifacts + weak domain policy.

    Two classic teaching artifacts plus a weakened password policy:

      * GPP cpassword: a Group Policy Preferences Groups.xml dropped in SYSVOL
        with an AES-encrypted "cpassword". Microsoft published the AES key in
        2014 (MS14-025), so ANY authenticated user who can read SYSVOL can
        decrypt it (gpp-decrypt / Get-GPPPassword / Certipy). This models the
        single most common "creds in SYSVOL" finding.
      * Weak domain password policy: complexity off, short minimum length, no
        lockout -> makes password spraying viable for the red team and gives the
        blue team a concrete hardening task.

    Gated by DC.LegacyGpo.

    NOTE on the cpassword value below: it is a well-known public example. Decrypt
    it in class with `gpp-decrypt <cpassword>` (Kali) or PowerSploit's
    Get-GPPPassword to reveal the plaintext -- that reveal *is* the exercise.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat = 'dc-gpo'
if (-not (Test-IsDomainController)) { Write-RangeLog 'Not a DC; skipping legacy GPO.' 'WARN'; return }
if (-not $Config.DC.LegacyGpo)      { Write-RangeLog 'DC.LegacyGpo=$false; skipping.' 'INFO'; return }
Import-Module ActiveDirectory -Force
Import-Module GroupPolicy -Force

$dom     = Get-ADDomain
$dnsRoot = $dom.DNSRoot

# ── Weak domain password policy ──────────────────────────────────────────
try {
    Set-ADDefaultDomainPasswordPolicy -Identity $dnsRoot -ComplexityEnabled $false `
        -MinPasswordLength 5 -MinPasswordAge '0.00:00:00' -MaxPasswordAge '0.00:00:00' `
        -LockoutThreshold 0 -PasswordHistoryCount 0 -ReversibleEncryptionEnabled $false -ErrorAction Stop
    Write-RangeManifest $cat 'pw-policy' 'complexity off; minlen 5; no lockout; no expiry'
    Write-RangeLog 'Domain password policy weakened (spray-friendly).' 'WARN'
} catch { Write-RangeLog "password policy: $($_.Exception.Message)" 'WARN' }

# ── GPP cpassword artifact in SYSVOL ─────────────────────────────────────
$gpoName = 'Legacy Local Admin Provisioning'
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if (-not $gpo) { $gpo = New-GPO -Name $gpoName; Write-RangeManifest $cat 'new-gpo' $gpoName }
$guid = '{' + $gpo.Id.ToString().ToUpper() + '}'

$prefDir = "\\$dnsRoot\SYSVOL\$dnsRoot\Policies\$guid\Machine\Preferences\Groups"
New-Item -ItemType Directory -Path $prefDir -Force | Out-Null

# Public example cpassword (MS14-025 AES key is public -> decrypts with gpp-decrypt)
$cpassword = 'j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw'
$uid = '{' + ([guid]::NewGuid().ToString().ToUpper()) + '}'
$groupsXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LocalAdmin" image="2" changed="2024-01-01 00:00:00" uid="$uid">
    <Properties action="U" newName="" fullName="Local Administrator" description="Provisioned local admin"
      cpassword="$cpassword" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="LocalAdmin"/>
  </User>
</Groups>
"@
Set-Content -Path (Join-Path $prefDir 'Groups.xml') -Value $groupsXml -Encoding UTF8
Write-RangeManifest $cat 'gpp-cpassword' "SYSVOL Groups.xml (cpassword public example) under $guid"
Write-RangeLog "GPP cpassword artifact written to SYSVOL under $gpoName. Decrypt in class with gpp-decrypt." 'WARN'

# Register the Groups client-side extension so the GPO is recognizable, and link it.
$cse = '[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]'
try {
    $gpoDN = "CN=$guid,CN=Policies,CN=System,$($dom.DistinguishedName)"
    Set-ADObject -Identity $gpoDN -Replace @{ gPCMachineExtensionNames = $cse; versionNumber = 1 } -ErrorAction SilentlyContinue
    New-GPLink -Name $gpoName -Target $dom.DistinguishedName -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
    Write-RangeManifest $cat 'gpo-link' "$gpoName linked to $($dom.DistinguishedName)"
} catch { Write-RangeLog "GPO CSE/link: $($_.Exception.Message)" 'WARN' }

Write-RangeLog 'DC legacy-GPO category complete.' 'OK'
