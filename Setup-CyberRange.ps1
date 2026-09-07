#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    STEP 2 of 3 -- apply every intentional misconfiguration. This is the range.

.DESCRIPTION
    Takes the healthy domain that Stage-CyberRange.ps1 built and breaks it, on
    purpose, in the specific ways a red-vs-blue exercise needs. Run this second.

        Stage-CyberRange.ps1     Structure: DC, OUs, users. Nothing weakened.
        Setup-CyberRange.ps1     <- you are here.  The misconfigurations.
        Test-RangeConfig.ps1     Verify (-Repair to fix drift). Optional.
        Reset-CyberRange.ps1     Teardown, when you want the VM back.

    WHAT IT APPLIES, IN ORDER
      1. MACHINE CONTROLS -- every entry in the control table
         (modules\RangeControls.psm1): frozen updates, Defender neutered, UAC and
         LSA protections off, SMB1 with signing off, RDP without NLA, WinRM
         unencrypted, logging blinded, legacy services, CVE artifacts,
         persistence beacons. The table is the single definition of each control;
         this script supplies only the imperative prerequisites a table cannot
         express (a feature install that must precede a control, the autologon
         block, the beacon payloads).
      2. AD ATTACK PATHS (on a DC) -- weaponises the accounts Stage created,
         publishes the ESC1 certificate template, grants the weak ACLs and
         delegation, plants the GPP cpassword in SYSVOL, seeds hidden domain
         admins, and finally pushes the SMB-signing / NoLMHash / log-size
         downgrades into the Default Domain Controllers Policy so they survive
         gpupdate (F33). That GPO step runs LAST for exactly that reason.
      3. FINALIZE -- locks the answer key and writes READY.txt.

    Then it reboots, because UAC, LSA PPL and VBS only take effect on restart.

    Safe to re-run: every step is idempotent. Re-running is the supported way to
    re-apply a category after you have been experimenting on the box.

    FOR ISOLATED, AUTHORIZED EDUCATIONAL USE ONLY. Requires Confirmed = $true.

.PARAMETER Force
    Continue past a step that failed instead of stopping, and allow the shipped
    placeholder credentials (for an off-network dry run).

.PARAMETER NoReboot
    Apply everything but do not reboot at the end. UAC / LSA PPL / VBS will not
    be in effect until you do restart, and Test-RangeConfig will say so.

.PARAMETER Only
    Apply only these control-table categories, e.g.
    -Only smb-network,logging-visibility
    Skips the AD attack paths and the finalize step. For targeted re-application.

.PARAMETER Auto
    Do not prompt. Run Test-RangeConfig.ps1 at the end and reboot without asking.

.EXAMPLE
    .\Setup-CyberRange.ps1
    Apply everything, then offer to verify and reboot.

.EXAMPLE
    .\Setup-CyberRange.ps1 -Only smb-network
    Re-apply just the SMB category on an already-built box.
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$NoReboot,
    [string[]]$Only,
    [switch]$Auto
)

$ErrorActionPreference = 'Stop'
$LocalRoot  = 'C:\CyberRange'
$StateDir   = Join-Path $env:ProgramData 'CyberRange'
$StateFile  = Join-Path $StateDir 'setup-state.json'
$ReadyFile  = Join-Path $StateDir 'READY.txt'
$StagedFile = Join-Path $StateDir 'STAGED.txt'

# ── Run from the staged local copy ────────────────────────────────────────
if ($PSScriptRoot.TrimEnd('\') -ine $LocalRoot.TrimEnd('\')) {
    $local = Join-Path $LocalRoot 'Setup-CyberRange.ps1'
    if (-not (Test-Path $local)) {
        throw ("Setup must run from $LocalRoot, and the staged copy is not there. " +
               "Run Stage-CyberRange.ps1 first -- it stages the repo and builds the domain.")
    }
    $fwd = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$local)
    foreach ($s in 'Force','NoReboot','Auto') { if ($PSBoundParameters[$s]) { $fwd += "-$s" } }
    if ($Only) { $fwd += @('-Only', ($Only -join ',')) }
    & powershell.exe @fwd
    exit $LASTEXITCODE
}

Import-Module (Join-Path $LocalRoot 'modules\RangeCommon.psm1')   -Force
Import-Module (Join-Path $LocalRoot 'modules\RangeControls.psm1') -Force
$Config = Import-PowerShellDataFile (Join-Path $LocalRoot 'config\range.config.psd1')

New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
$state = if (Test-Path $StateFile) { try { Get-Content $StateFile -Raw | ConvertFrom-Json } catch { $null } } else { $null }
if (-not $state) { $state = [pscustomobject]@{ Stage = 0; Setup = 0; LogFile = $null; Manifest = $null } }
foreach ($p in 'Setup','LogFile','Manifest') {
    if ($state.PSObject.Properties.Name -notcontains $p) { $state | Add-Member -NotePropertyName $p -NotePropertyValue $null -Force }
}

if ($state.LogFile) { $env:RANGE_LOGFILE = $state.LogFile; $env:RANGE_MANIFEST = $state.Manifest }
Initialize-RangeContext
if (-not $state.LogFile) { $state.LogFile = $env:RANGE_LOGFILE; $state.Manifest = $env:RANGE_MANIFEST }
function Save-State { ($state | ConvertTo-Json) | Set-Content -Path $StateFile -Encoding UTF8 }
Save-State

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " STEP 2/3  SETUP -- applying the intentional misconfigurations" -ForegroundColor Cyan
Write-Host ("   $env:COMPUTERNAME    $(Get-Date -Format s)") -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

Assert-RangeSafety -Config $Config -AllowPlaceholderCredentials:$Force

# ── Did Stage actually run? ───────────────────────────────────────────────
#    Not fatal -- a non-DC build is legitimate -- but running Setup on a box with
#    no operator account and no domain is how people lock themselves out.
if (-not (Test-Path $StagedFile)) {
    Write-RangeLog 'No STAGED.txt marker: Stage-CyberRange.ps1 has not completed on this host.' 'WARN'
    if ($Config.DC.Enabled -and -not (Test-IsDomainController)) {
        throw ("DC.Enabled = `$true but this host is NOT a domain controller, and Stage has not " +
               "completed.`nRun  .\Stage-CyberRange.ps1  first -- it builds the domain and " +
               "provisions the operator account you need to get back in.`n" +
               "To weaken a standalone box deliberately, set DC.Enabled = `$false in the config.")
    }
}

$script:Failures = 0
function Invoke-Part {
    <# Runs one named part. A failure is recorded, not fatal -- the run continues
       so a single broken technique does not cost you the whole range. #>
    param([string]$Name, [scriptblock]$Body)
    Write-RangeLog "---- $Name ----" 'WARN'
    try { & $Body }
    catch { Write-RangeLog "$Name FAILED: $($_.Exception.Message)" 'ERROR'; $script:Failures++ }
}
function Invoke-Script {
    param([string]$Rel)
    $p = Join-Path $LocalRoot $Rel
    if (-not (Test-Path $p)) { Write-RangeLog "missing: $Rel" 'ERROR'; $script:Failures++; return }
    Invoke-Part $Rel { & $p -Config $Config }
}

# ══════════════════════════════════════════════════════════════════════════
#  PART 1 -- MACHINE CONTROLS (the control table)
# ══════════════════════════════════════════════════════════════════════════
#  Each category below is one call into modules\RangeControls.psm1, which holds
#  the intended value, the control mapping, the check and the revert for every
#  control. What lives here is ONLY what a declarative table cannot express.

$categories = [ordered]@{
    'updates-defender'   = 'UpdatesDefender'
    'credential-exposure'= 'CredentialExposure'
    'uac-lsa-vbs'        = 'UacLsaVbs'
    'smb-network'        = 'SmbNetwork'
    'rdp-winrm'          = 'RdpWinrm'
    'logging-visibility' = 'LoggingVisibility'
    'legacy-services'    = 'LegacyServices'
    'cve-repro'          = $null      # always on; no config toggle
    'persistence'        = 'Persistence'
}

foreach ($cat in $categories.Keys) {
    if ($Only -and ($Only -notcontains $cat)) { continue }
    $toggle = $categories[$cat]
    if ($toggle -and -not $Config.Categories[$toggle]) {
        Write-RangeLog "skip $cat (Categories.$toggle = `$false)" ; continue
    }

    # ── imperative prerequisites, per category ────────────────────────────
    switch ($cat) {
        'smb-network' {
            # SMB1 is an OPTIONAL FEATURE on 2025. The control cannot be
            # satisfied at all until the feature is present.
            Invoke-Part 'FS-SMB1 feature' {
                $f = Get-WindowsFeature -Name FS-SMB1 -ErrorAction Stop
                if ($f -and -not $f.Installed) { Install-WindowsFeature FS-SMB1 -ErrorAction Stop | Out-Null }
                Write-RangeManifest $cat 'install-feature' 'FS-SMB1'
                Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -ErrorAction SilentlyContinue
            }
        }
        'rdp-winrm' {
            # WinRM has to EXIST before any WSMan:\ path can be written to.
            Invoke-Part 'Enable-PSRemoting' {
                Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop
                Write-RangeManifest $cat 'winrm' 'PSRemoting enabled (weak transport/auth applied as controls)'
            }
        }
        'persistence' {
            # The beacon payloads are generated from the config, so they cannot
            # be a static table value. TCP connect only, no payload -- the point
            # is that the blue team can FIND and kill the persistence.
            Invoke-Part 'beacon payloads + implants' {
                $dir = 'C:\ProgramData\SysTasks'
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                $bh = $Config.BeaconHost; $bp = $Config.BeaconPort; $bi = $Config.BeaconIntervalSeconds
@"
# Range check-in beacon (educational). TCP connect only, no payload.
while (`$true) {
    try { Test-NetConnection -ComputerName '$bh' -Port $bp -WarningAction SilentlyContinue | Out-Null } catch {}
    Start-Sleep -Seconds $bi
}
"@ | Set-Content "$dir\svc.ps1" -Encoding UTF8
@"
try { Test-NetConnection -ComputerName '$bh' -Port $bp -WarningAction SilentlyContinue | Out-Null } catch {}
"@ | Set-Content "$dir\health.ps1" -Encoding UTF8
                Write-RangeManifest $cat 'drop-script' "$dir\svc.ps1;$dir\health.ps1 -> ${bh}:$bp"

                # The "service" is powershell.exe running a script, which is NOT a
                # service binary -- it never answers the SCM, so `sc start` fails
                # with 1053. That is expected: the artifact is its EXISTENCE and
                # its Automatic start type, which is what the control checks.
                Invoke-Native 'sc.exe' @('create','WinTelemetryHelper','binPath=',"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File $dir\svc.ps1",'start=','auto','DisplayName=','Windows Telemetry Helper') $cat
                Invoke-Native 'sc.exe' @('description','WinTelemetryHelper','System telemetry collection service') $cat
                Invoke-Native 'sc.exe' @('start','WinTelemetryHelper') $cat
                Invoke-Native 'schtasks.exe' @('/create','/tn','System Update Check','/tr',"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File $dir\health.ps1",'/sc','minute','/mo','5','/ru','SYSTEM','/f') $cat
                Invoke-Native 'schtasks.exe' @('/create','/tn','Windows Health Monitor','/tr',"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File $dir\health.ps1",'/sc','onlogon','/ru','SYSTEM','/f') $cat
                Copy-Item "$dir\health.ps1" "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\SysHealth.ps1" -Force
                Write-RangeManifest $cat 'startup-folder' 'SysHealth.ps1 in the all-users Startup folder'
            }
        }
    }

    Invoke-Part "controls: $cat" { Invoke-RangeControlCategory -Category $cat -Config $Config -ExcludeId `
        'cred.autologon.enabled','cred.autologon.user','cred.autologon.password',
        'cred.autologon.domain','cred.autologon.noforce' }

    # ── post-category imperative work ─────────────────────────────────────
    switch ($cat) {
        'smb-network' {
            # netsh is the fallback for a box where the NetSecurity module is broken.
            if (@(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }).Count) {
                Invoke-Native 'netsh.exe' @('advfirewall','set','allprofiles','state','off') $cat
            }
            # F35: the feature install above went through the servicing stack,
            # which quietly re-enables wuauserv.
            Disable-RangeUpdateServices -Because 'FS-SMB1 feature install'
        }
        'rdp-winrm' {
            Invoke-Part 'RDP firewall rule' {
                try { Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction Stop }
                catch { Invoke-Native 'netsh.exe' @('advfirewall','firewall','set','rule','group=remote desktop','new','enable=Yes') $cat }
            }
        }
        'legacy-services' {
            Write-RangeLog 'Telnet Server is not available on Server 2025; skipping. Supply a 3rd-party telnetd if a plaintext service is required.' 'WARN'
            Disable-RangeUpdateServices -Because 'legacy feature/capability installs'
        }
        'cve-repro' { Write-RangeManifest 'cve-repro' 'vss-shadow' 'C: (enables HiveNightmare read)' }
        'credential-exposure' {
            # ── AUTOLOGON: not declarative, so the table leaves it to us ──
            #    F1, the lockout that started all of this. Three rules:
            #      1. SET the account's password to the configured value FIRST, so
            #         the real credential and the registry value cannot diverge.
            #      2. Validate it -- informational only (see below).
            #      3. NEVER write ForceAutoLogon, and strip it if an earlier run
            #         left it. With AutoAdminLogon alone a failed autologon drops
            #         to the logon screen instead of retrying forever.
            Invoke-Part 'autologon (F1)' {
                $wl       = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                $alUser   = $Config.LocalAdminAutoLogonUser
                $alPass   = $Config.LocalAdminAutoLogonPass
                $onDC     = Test-IsDomainController
                $alDomain = if ($onDC) { $Config.DC.NetbiosName } else { '.' }

                Write-RangeLog "Setting '$alUser' password to LocalAdminAutoLogonPass so autologon cannot diverge (F1)." 'WARN'
                $secure = ConvertTo-SecureString $alPass -AsPlainText -Force
                $pwSet  = $false
                try {
                    if ($onDC) {
                        Import-Module ActiveDirectory -ErrorAction Stop
                        Set-ADAccountPassword -Identity $alUser -Reset -NewPassword $secure -ErrorAction Stop
                        Set-ADUser -Identity $alUser -Enabled $true -PasswordNeverExpires $true -ErrorAction SilentlyContinue
                    } else {
                        Set-LocalUser -Name $alUser -Password $secure -PasswordNeverExpires $true -ErrorAction Stop
                        Enable-LocalUser -Name $alUser -ErrorAction SilentlyContinue
                    }
                    $pwSet = $true
                    Write-RangeManifest 'credential-exposure' 'set-password' $alUser 'set to LocalAdminAutoLogonPass (autologon consistency)'
                } catch { Write-RangeLog "Could not set password for '$alUser': $($_.Exception.Message)" 'ERROR' }

                # INFORMATIONAL ONLY. ValidateCredentials(Machine) performs a
                # NETWORK logon, which a hardened box routinely denies for a LOCAL
                # account even when the password is correct -- a false negative;
                # interactive login is unaffected. We just set the password
                # ourselves, so we do not gate on this.
                $authOk = $null
                try {
                    Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
                    $ctx = [System.DirectoryServices.AccountManagement.PrincipalContext]::new($(if ($onDC) { 'Domain' } else { 'Machine' }))
                    $authOk = $ctx.ValidateCredentials($alUser, $alPass)
                } catch { Write-RangeLog "Could not validate '$alUser' (informational): $($_.Exception.Message)" 'WARN' }

                Set-RegValue $wl 'DefaultUserName'   String $alUser   'credential-exposure'
                Set-RegValue $wl 'DefaultDomainName' String $alDomain 'credential-exposure'
                Set-RegValue $wl 'DefaultPassword'   String $alPass   'credential-exposure'   # the teaching artifact

                if ($pwSet -or $authOk -eq $true) {
                    Set-RegValue $wl 'AutoAdminLogon' String '1' 'credential-exposure'
                    $note = if ($authOk -eq $true) { 'credential validated' }
                            elseif ($authOk -eq $false) { 'password set; network-logon validate returned false, a known false negative for local accounts' }
                            else { 'password set; validation unavailable' }
                    Write-RangeLog "Autologon ENABLED for $alDomain\$alUser ($note)." 'WARN'
                } else {
                    Set-RegValue $wl 'AutoAdminLogon' String '0' 'credential-exposure'
                    Write-RangeLog "Autologon NOT enabled: could not set '$alUser' password and it did not validate. DefaultPassword is still exposed for the exercise; log in as the operator account." 'ERROR'
                }

                try {
                    Remove-ItemProperty -Path $wl -Name 'ForceAutoLogon' -Force -ErrorAction Stop
                    Write-RangeLog 'Removed ForceAutoLogon left behind by an earlier run.' 'WARN'
                } catch { }   # not present is the normal, desired case
            }
        }
    }
}

# ── Accessibility SYSTEM shell (operator break-glass + T1546 artifact) ────
#    Dual purpose and both are intended: a guaranteed no-password SYSTEM prompt
#    at the logon screen means you can never be fully locked out, AND it is the
#    textbook IFEO accessibility backdoor the blue team is expected to find.
#    HKLM-only, so it survives promotion.
if (-not $Only -and $Config.AccessibilityShell) {
    Invoke-Part 'accessibility shell' {
        $ifeo  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        $shell = "$env:SystemRoot\System32\cmd.exe"
        foreach ($exe in 'utilman.exe','sethc.exe') { Set-RegValue "$ifeo\$exe" 'Debugger' String $shell 'accessibility-shell' }
        Write-RangeManifest 'accessibility-shell' 'ifeo-debugger' 'utilman.exe;sethc.exe -> cmd.exe (SYSTEM shell at logon)' 'MITRE T1546.008 / T1546.012'
        Write-RangeLog 'Accessibility SYSTEM shell ARMED. At the logon screen: Win+U, or Shift x5, opens cmd.exe as SYSTEM.' 'WARN'
        Write-RangeLog 'To remove (blue-team remediation): Remove-ItemProperty on the two Debugger values above.' 'INFO'
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  PART 2 -- AD ATTACK PATHS  (or hidden LOCAL admins on a non-DC)
# ══════════════════════════════════════════════════════════════════════════
if (-not $Only) {
    if (Test-IsDomainController) {
        # F39: guarantee the directory services are ENABLED before anything tries to
        # use them. A promoted DC needs ADWS for every Get-AD*/New-AD* call, and a
        # Disabled service cannot be started -- on the field DC a Disabled ADWS
        # silently sank the whole AD phase (no analyst, no hidden admins, no
        # autologon). Force NTDS/DNS/ADWS/Netlogon to Automatic + start them once,
        # up front and unconditionally, so a fresh build never hits that trap.
        foreach ($svc in 'NTDS','DNS','ADWS','Netlogon') {
            $s = Get-Service $svc -ErrorAction SilentlyContinue
            if ($s -and $s.StartType -eq 'Disabled') {
                Set-Service $svc -StartupType Automatic -ErrorAction SilentlyContinue
                Write-RangeLog "Re-enabled $svc (was Disabled) before the AD phase (F39)." 'WARN'
            }
        }
        try { Start-Service NTDS,ADWS,DNS,Netlogon -ErrorAction SilentlyContinue } catch {}

        # Everything here needs AD to answer. If it does not, all six steps fail
        # for the same underlying reason -- say that once instead of six times.
        $adUp = $false
        for ($i = 0; $i -lt 30 -and -not $adUp; $i++) {
            # A Disabled service cannot be started -- re-enable before starting, or
            # a Disabled ADWS silently sinks every AD step below (see operator-keeper).
            foreach ($svc in 'NTDS','DNS','ADWS','Netlogon') { $s = Get-Service $svc -ErrorAction SilentlyContinue; if ($s -and $s.StartType -eq 'Disabled') { Set-Service $svc -StartupType Automatic -ErrorAction SilentlyContinue } }
            try { Start-Service NTDS,ADWS,DNS,Netlogon -ErrorAction SilentlyContinue } catch {}
            try { Import-Module ActiveDirectory -ErrorAction Stop; Get-ADDomain -ErrorAction Stop | Out-Null; $adUp = $true } catch { Start-Sleep -Seconds 10 }
        }
        if (-not $adUp) {
            Write-RangeLog 'ACTIVE DIRECTORY IS NOT ANSWERING (ADWS down / no DC located). Skipping every AD attack path -- they would all fail for this one reason.' 'ERROR'
            Write-RangeLog '   Get-Service ADWS,NTDS,DNS,Netlogon | Select Name,Status,StartType' 'WARN'
            Write-RangeLog '   Get-DnsClientServerAddress -AddressFamily IPv4   # a DC must point at 127.0.0.1' 'WARN'
            $script:Failures++
        } else {
            # dc-security-gpo.ps1 runs LAST: it pushes the SMB-signing / NoLMHash /
            # log-size downgrades into the Default Domain Controllers Policy and
            # ends with gpupdate /force. Anything after it that writes those same
            # values locally would just be reverted by the next refresh (F33).
            Invoke-Script 'scripts\ad-users-weaponise.ps1'
            if ($Config.DC.InstallAdcs)          { Invoke-Script 'scripts\ad-certificates-esc1.ps1' }
            if ($Config.DC.WeakAcls)             { Invoke-Script 'scripts\ad-acl-delegation.ps1' }
            if ($Config.DC.LegacyGpo)            { Invoke-Script 'scripts\ad-gpo-legacy.ps1' }
            Invoke-Script 'scripts\ad-hidden-admins.ps1'
            if ($Config.DC.SecurityGpoDowngrade) { Invoke-Script 'scripts\dc-security-gpo.ps1' }
        }
    }
    elseif ($Config.Categories.HiddenAccounts) {
        # Hidden LOCAL admins are only meaningful off a DC -- a DC has no local SAM.
        Invoke-Part 'hidden local admins' {
            $pass = ConvertTo-SecureString $Config.HiddenAdminPassword -AsPlainText -Force
            $ul   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
            foreach ($n in $Config.HiddenAdminAccounts) {
                try {
                    if (Get-LocalUser -Name $n -ErrorAction SilentlyContinue) {
                        Set-LocalUser -Name $n -Password $pass -PasswordNeverExpires $true -ErrorAction Stop
                    } else {
                        New-LocalUser -Name $n -Password $pass -PasswordNeverExpires -AccountNeverExpires `
                            -Description 'Backup service account' -ErrorAction Stop | Out-Null
                    }
                    Add-LocalGroupMember -Group 'Administrators' -Member $n -ErrorAction SilentlyContinue
                    # Hidden from the sign-in screen -- that is the point.
                    Set-RegValue $ul $n DWord 0 'hidden-accounts'
                    Write-RangeManifest 'hidden-accounts' 'hidden-local-admin' $n "pw=$($Config.HiddenAdminPassword); Administrators; hidden from sign-in"
                    Write-RangeLog "hidden local admin $n  (pw: $($Config.HiddenAdminPassword))" 'WARN'
                } catch { Write-RangeLog "hidden admin ${n}: $($_.Exception.Message)" 'WARN' }
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  PART 3 -- FINALIZE
# ══════════════════════════════════════════════════════════════════════════
if ($Only) {
    Write-RangeLog "==== -Only run complete ($($Only -join ', ')). Skipped the AD paths and finalize. ====" 'OK'
    Write-Host ""
    Write-Host " Targeted run complete. Verify with:  .\Test-RangeConfig.ps1" -ForegroundColor Cyan
    return
}

# F35 catch-all: any step above may have run a servicing operation (AD CS role,
# SNMP capability, TFTP/PSv2 features) and the servicing stack re-enables
# wuauserv behind us. Re-assert before the range is declared ready.
Disable-RangeUpdateServices -Because 'Setup finalize'

$hadFailures = $script:Failures -gt 0
$statusLine = if ($hadFailures) {
    "STATUS: *** $($script:Failures) STEP(S) FAILED -- NOT READY TO HAND OUT. *** Run Test-RangeConfig.ps1 and fix the FAIL rows first."
} else { 'STATUS: setup completed cleanly.' }

@"
Cyber range setup COMPLETE  -  $(Get-Date -Format s)  -  $env:COMPUTERNAME
Build log: $($env:RANGE_LOGFILE)
$statusLine

This machine is INTENTIONALLY VULNERABLE for authorized red-vs-blue training.

OPERATOR NOTES (not for participants)
  Log in as:        $(if ($Config.Analyst -and $Config.Analyst.Enabled) { "$($Config.Analyst.User)  ($(if($Config.DC.Enabled){'Domain Admins'}else{'local Administrators'}))" } else { '(NO OPERATOR ACCOUNT -- Analyst disabled in config)' })
  A permanent SYSTEM task (CyberRangeOperatorKeeper) re-asserts that account on
  every boot, so a GPO or a lockout cannot take it away from you.
  If that fails:    Win+U (or Shift x5) at the logon screen = SYSTEM prompt,
                    then run  C:\range-fix.cmd
  NOTE: the built-in Administrator password is now LocalAdminAutoLogonPass -- the
  build overwrote it for the exposed-credential lesson. Use the operator account.
  Recovery runbook: docs\BREAK-GLASS.md

  The change manifest and the staged config hold every seeded password in
  cleartext. They are the ANSWER KEY, not an after-action handout. They live
  under ACL-locked paths (SYSTEM + Administrators). Do NOT relax those ACLs and
  do NOT give the manifest to a participant; collect it off-box for review.
"@ | Set-Content -Path $ReadyFile -Encoding UTF8

$state.Setup = 1; Save-State

# Lock the ANSWER-KEY directory only now that every write is done. Doing it
# earlier locked the build out of its own state file (F27).
Protect-RangePath -Path $StateDir

Write-Host ""
if ($hadFailures) {
    Write-RangeLog "==== SETUP FINISHED WITH $($script:Failures) FAILURE(S). Marker: $ReadyFile ====" 'ERROR'
    Write-Host "======================================================================" -ForegroundColor Red
    Write-Host " STEP 2/3 FINISHED WITH FAILURES -- do not hand this VM out yet." -ForegroundColor Red
    Write-Host "======================================================================" -ForegroundColor Red
} else {
    Write-RangeLog "==== RANGE READY. Marker: $ReadyFile ====" 'OK'
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host " STEP 2/3 COMPLETE -- the range is built." -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Green
}
Write-Host ""
Write-Host " UAC, LSA PPL and VBS only take effect after a REBOOT." -ForegroundColor Yellow
Write-Host ""

# ── STEP 3: verify ────────────────────────────────────────────────────────
$tester = Join-Path $LocalRoot 'Test-RangeConfig.ps1'
$runTest = $Auto
if (-not $Auto) {
    $isSystem = try { [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem } catch { $false }
    if (-not $isSystem) {
        try {
            $ans = Read-Host " Run STEP 3 (Test -- verify every control) now? [Y/n]"
            $runTest = ($ans -eq '' -or $ans -match '^(y|yes)$')
        } catch { }
    }
}
if ($runTest -and (Test-Path $tester)) {
    Write-Host ""
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tester
}

Write-Host ""
Write-Host " Verify any time :  $tester" -ForegroundColor Cyan
Write-Host " Fix drift       :  $tester -Repair" -ForegroundColor Cyan
Write-Host ""

if ($NoReboot) {
    Write-Host " -NoReboot given. Restart before handing the VM over -- UAC/PPL/VBS are" -ForegroundColor Yellow
    Write-Host " not in effect until you do." -ForegroundColor Yellow
    return
}
$doReboot = $Auto
if (-not $Auto) {
    try {
        $ans = Read-Host " Reboot now to settle UAC / LSA PPL / VBS? [Y/n]"
        $doReboot = ($ans -eq '' -or $ans -match '^(y|yes)$')
    } catch { $doReboot = $false }
}
if ($doReboot) {
    Write-Host " Rebooting in 5 seconds ..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Restart-Computer -Force
} else {
    Write-Host " Not rebooting. Remember to restart before the exercise." -ForegroundColor Yellow
}
