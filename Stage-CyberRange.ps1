#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    STEP 1 of 3 -- build the structure of the range. Nothing is weakened here.

.DESCRIPTION
    Takes a fresh, standalone Windows Server 2025 VM and turns it into a working
    domain: a promoted DC, an OU tree, staff and service accounts, and the
    operator account you will log in as. Everything it builds is CORRECT --
    a small, ordinary, functioning domain.

    The misconfigurations come afterwards, in Setup-CyberRange.ps1. Building a
    healthy domain first and breaking it second is deliberate: promotion on an
    already-weakened box (no firewall, no UAC, downgraded LSA) is fragile and was
    the source of the field lockouts.

        Stage-CyberRange.ps1     <- you are here.  Structure. Safe to re-run.
        Setup-CyberRange.ps1     Misconfigurations. This is what makes it a range.
        Test-RangeConfig.ps1     Verify (-Repair to fix drift). Optional.
        Reset-CyberRange.ps1     Teardown, when you want the VM back.

    WHAT IT DOES, IN ORDER
      1. Copies the repo to C:\CyberRange and runs from there. Required: the
         SYSTEM resume task that carries the build across the promotion reboot
         runs before any user logs on, and cannot see a mapped drive or USB stick.
      2. Pre-flight gates -- refuses to continue if the config is unsafe, the host
         is domain-joined, the beacon target is routable, or the answer key is
         world-readable.
      3. Provisions the OPERATOR ACCOUNT and proves it authenticates, before
         anything else happens. This is your way back in.
      4. Installs AD DS + DNS and promotes this host into its own new forest.
         REBOOTS, and resumes itself.
      5. Creates the OU tree, staff and service accounts, and groups.

    Progress lives in C:\ProgramData\CyberRange\setup-state.json. Re-running is
    safe -- every step is idempotent and skips work already done.

    FOR ISOLATED, AUTHORIZED EDUCATIONAL USE ONLY.

.PARAMETER Resume
    Used by the auto-resume scheduled task after the promotion reboot. You do not
    normally pass this by hand; just re-run the script with no arguments.

.PARAMETER Fresh
    Clear the recorded progress and start from the beginning. This does NOT undo
    anything already done to the machine -- it only resets the bookkeeping. On a
    box that has already been built, reverting the snapshot is the clean restart.

.PARAMETER Force
    Continue past a step that failed instead of stopping. Also allows the shipped
    placeholder credentials, for an off-network dry run.

.PARAMETER SkipPreflight
    Skip the safety gates and the operator-account provisioning. You are then
    building a box with no verified way back in. Only use this if you have just
    run the gates by hand and they passed.

.PARAMETER Auto
    Do not prompt. Chain straight into Setup-CyberRange.ps1 when this finishes.

.EXAMPLE
    .\Stage-CyberRange.ps1
    Build the domain. Prompts before handing off to Setup.

.EXAMPLE
    .\Stage-CyberRange.ps1 -Auto
    Build the domain and run Setup immediately afterwards, unattended.
#>
[CmdletBinding()]
param(
    [switch]$Resume,
    [switch]$Fresh,
    [switch]$Force,
    [switch]$SkipPreflight,
    [switch]$Auto
)

$ErrorActionPreference = 'Stop'
$LocalRoot = 'C:\CyberRange'
$TaskName  = 'CyberRangeStage'
$StateDir  = Join-Path $env:ProgramData 'CyberRange'
$StateFile = Join-Path $StateDir 'setup-state.json'
$StagedFile = Join-Path $StateDir 'STAGED.txt'

# ══════════════════════════════════════════════════════════════════════════
#  PART 0 -- stage the repo to local disk, then re-enter from there
# ══════════════════════════════════════════════════════════════════════════
if ($PSScriptRoot.TrimEnd('\') -ine $LocalRoot.TrimEnd('\')) {
    Write-Host "Staging range files to $LocalRoot ..." -ForegroundColor Yellow
    if (Test-Path $LocalRoot) {
        # Heal a mangled ACL from an earlier run (a manual Everyone:F, or a lock a
        # previous build applied) so the copy and the engine can read the tree.
        & takeown.exe /F $LocalRoot /R /D Y 2>&1 | Out-Null
        & icacls.exe $LocalRoot /reset /T /C 2>&1 | Out-Null
    }
    New-Item -ItemType Directory -Path $LocalRoot -Force | Out-Null
    Copy-Item -Path (Join-Path $PSScriptRoot '*') -Destination $LocalRoot -Recurse -Force `
        -Exclude '.attic' -ErrorAction SilentlyContinue
    Get-ChildItem $LocalRoot -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
    Write-Host ("Staged " + (Get-ChildItem $LocalRoot -Recurse -File).Count + " files.") -ForegroundColor Green

    $local = Join-Path $LocalRoot 'Stage-CyberRange.ps1'
    if (-not (Test-Path $local)) { throw "Stage-CyberRange.ps1 missing at '$local' after staging. Is the repo layout intact?" }

    Write-Host "Re-entering from the local copy ..." -ForegroundColor Yellow
    $fwd = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$local)
    foreach ($s in 'Resume','Fresh','Force','SkipPreflight','Auto') {
        if ($PSBoundParameters[$s]) { $fwd += "-$s" }
    }
    & powershell.exe @fwd
    exit $LASTEXITCODE
}

Import-Module (Join-Path $LocalRoot 'modules\RangeCommon.psm1')   -Force
Import-Module (Join-Path $LocalRoot 'modules\RangeControls.psm1') -Force
$Config = Import-PowerShellDataFile (Join-Path $LocalRoot 'config\range.config.psd1')

New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

function Get-State {
    if (Test-Path $StateFile) { try { return (Get-Content $StateFile -Raw | ConvertFrom-Json) } catch {} }
    [pscustomobject]@{ Stage = 1; Setup = 0; LogFile = $null; Manifest = $null; PromoteTries = 0 }
}
function Save-State { param($s) ($s | ConvertTo-Json) | Set-Content -Path $StateFile -Encoding UTF8 }

if ($Fresh) {
    Write-Host "-Fresh: clearing recorded progress. Nothing already applied to this" -ForegroundColor Red
    Write-Host "machine is being undone. Reverting the VM snapshot is the clean restart." -ForegroundColor Red
    Remove-Item $StateFile, $StagedFile -Force -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

$state = Get-State
if ($state.PSObject.Properties.Name -notcontains 'Stage') {
    $state | Add-Member -NotePropertyName Stage -NotePropertyValue 1 -Force
}

# One continuous log + change manifest across the promotion reboot.
if ($state.LogFile) { $env:RANGE_LOGFILE = $state.LogFile; $env:RANGE_MANIFEST = $state.Manifest }
Initialize-RangeContext
if (-not $state.LogFile) {
    $state.LogFile = $env:RANGE_LOGFILE; $state.Manifest = $env:RANGE_MANIFEST; Save-State $state
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " STEP 1/3  STAGE -- building the domain structure" -ForegroundColor Cyan
Write-Host ("   $env:COMPUTERNAME    stage $($state.Stage)    $(Get-Date -Format s)" +
            $(if ($Resume) { '    [resumed after reboot]' } else { '' })) -ForegroundColor Cyan
Write-Host " Nothing is weakened in this step. Misconfigurations are Setup." -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

Assert-RangeSafety -Config $Config -AllowPlaceholderCredentials:$Force

$script:Failures = 0
function Step-Failed { param([string]$What, [string]$Why) Write-RangeLog "$What FAILED: $Why" 'ERROR'; $script:Failures++ }
function Test-StageClean {
    param([int]$N)
    if ($script:Failures -eq 0) { return $true }
    if ($Force) { Write-RangeLog "Stage $N had $($script:Failures) failure(s); -Force given, continuing." 'WARN'; return $true }
    Write-RangeLog "Stage $N had $($script:Failures) failure(s). NOT advancing." 'ERROR'
    Write-RangeLog 'Fix the cause and re-run (steps are idempotent), or pass -Force.' 'WARN'
    return $false
}
function Test-AdReady {
    try { Import-Module ActiveDirectory -ErrorAction Stop; Get-ADDomain -ErrorAction Stop | Out-Null; $true } catch { $false }
}

function Register-ResumeTask {
    # SYSTEM at STARTUP. Essential: promotion destroys the local SAM, so the
    # domain account you would log in with does not exist until this script
    # finishes. A login-gated resume deadlocks -- you cannot log in to trigger
    # the step that creates the account you would log in with.
    $a = New-ScheduledTaskAction -Execute 'powershell.exe' `
         -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$LocalRoot\Stage-CyberRange.ps1`" -Resume$(if($Auto){' -Auto'})"
    $t = New-ScheduledTaskTrigger -AtStartup
    $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # A FINITE limit. With no limit a wedged instance ran forever and, being
    # -MultipleInstances IgnoreNew, suppressed every later trigger -- the build
    # could never retry itself.
    $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
         -ExecutionTimeLimit (New-TimeSpan -Hours 3) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
    Write-RangeLog "Resume task '$TaskName' registered (SYSTEM at startup -- no login needed)."
}
function Unregister-ResumeTask {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

# ══════════════════════════════════════════════════════════════════════════
#  STAGE 1 -- pre-flight, operator account, AD DS role
# ══════════════════════════════════════════════════════════════════════════
if ([int]$state.Stage -le 1) {
    Write-RangeLog '==== STAGE 1: pre-flight, operator account, AD DS role ====' 'WARN'

    # ── F29: refuse on a domain MEMBER before touching anything ───────────
    #    A DC build promotes a STANDALONE server into its OWN new forest. A box
    #    already joined to a domain as a member cannot do that -- promotion fails
    #    prereqs. Catch it now, not after the role install.
    if ($Config.DC.Enabled) {
        $cs = Get-CimInstance Win32_ComputerSystem
        if ($cs.PartOfDomain -and $cs.DomainRole -lt 4) {
            throw ("This host is a MEMBER of domain '$($cs.Domain)' (DomainRole $($cs.DomainRole)). A DC build " +
                   "promotes a STANDALONE server into its OWN new forest and cannot run on a domain member. " +
                   "Nothing has been changed.`n" +
                   "Fix:  Add-Computer -WorkgroupName WORKGROUP -Force -Restart`n" +
                   "...or start from a clean standalone snapshot that was never domain-joined.")
        }
    }

    # ── Pre-flight gates + the operator account ───────────────────────────
    if ($SkipPreflight) {
        Write-RangeLog '-SkipPreflight: NOT verifying the operator recovery account. If this build locks you out, the snapshot is your only way back.' 'ERROR'
    } else {
        $pf = Join-Path $LocalRoot 'scripts\preflight.ps1'
        if (-not (Test-Path $pf)) { throw "Pre-flight script not found at '$pf'." }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $pf -Apply
        if ($LASTEXITCODE -ne 0) {
            throw ("PRE-FLIGHT FAILED (see the BLOCKED/FAIL gates above). Nothing has been weakened " +
                   "and no domain has been created.`n`n" +
                   "Fix the cause, then re-run  .\Stage-CyberRange.ps1`n" +
                   "Recovery procedure:  docs\BREAK-GLASS.md`n`n" +
                   "To build anyway, with no verified way back in:  -SkipPreflight")
        }
        Write-RangeLog 'Pre-flight PASSED; operator account provisioned and authenticated.' 'OK'
    }

    # ── Operator keeper: re-asserts the operator account on EVERY boot ────
    if ($Config.OperatorKeeper) {
        try {
            & (Join-Path $LocalRoot 'scripts\operator-keeper.ps1')
            $a = New-ScheduledTaskAction -Execute 'powershell.exe' `
                 -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$LocalRoot\scripts\operator-keeper.ps1`" -FromBoot"
            $t = New-ScheduledTaskTrigger -AtStartup
            $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
            Register-ScheduledTask -TaskName 'CyberRangeOperatorKeeper' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
            Write-RangeLog "Operator keeper registered (SYSTEM at startup, PERMANENT) -- the operator account self-heals every boot." 'OK'
        } catch { Step-Failed 'operator keeper' $_.Exception.Message }
    }

    if (-not $Config.DC.Enabled) {
        Write-RangeLog 'DC.Enabled = $false -- no domain will be created. Skipping to the end of Stage.' 'WARN'
        $state.Stage = 4; Save-State $state
    }
    else {
        # ── AD DS + DNS role ──────────────────────────────────────────────
        if (Test-IsDomainController) {
            Write-RangeLog 'Host is already a domain controller; role install not needed.' 'OK'
            $state.Stage = 3; Save-State $state
        } else {
            Write-RangeLog "Installing AD-Domain-Services + DNS for forest '$($Config.DC.DomainName)'." 'WARN'
            try {
                $feat = Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools -ErrorAction Stop
                Write-RangeLog "Feature install: Success=$($feat.Success) ExitCode=$($feat.ExitCode) RestartNeeded=$($feat.RestartNeeded)"
                Write-RangeManifest 'dc-promote' 'install-feature' 'AD-Domain-Services;DNS' "Success=$($feat.Success);Restart=$($feat.RestartNeeded)"
            } catch { Step-Failed 'AD DS role install' $_.Exception.Message }

            # The ADDSDeployment module ships with the AD DS management tools. On
            # some trimmed images -IncludeManagementTools reports success without
            # placing them, so verify and install explicitly if missing.
            if (-not (Get-Module -ListAvailable -Name ADDSDeployment)) {
                Write-RangeLog 'ADDSDeployment module not present; installing RSAT-ADDS explicitly.' 'WARN'
                try { Install-WindowsFeature -Name RSAT-ADDS -IncludeAllSubFeature -ErrorAction Stop | Out-Null }
                catch { Write-RangeLog "RSAT-ADDS install: $($_.Exception.Message)" 'WARN' }
            }

            # F41: pre-install the optional features Setup will only CONFIGURE
            # later, so their pending-reboot completes on THIS stage's reboot below.
            # Installing the AD CS role leaves it InstallPending until a reboot; Setup
            # then configures the CA in the SAME session, which on a clean build fails
            # ("ADCSDeployment module not found", CertSvc never starts, ESC1 cannot
            # publish) because the box has not rebooted yet. Installing the binaries
            # here -- the CA is still CONFIGURED in Setup after promotion -- means the
            # box is settled by then. Same for FS-SMB1: the SMB1 server protocol is
            # not live until a reboot finishes the feature install.
            if ($Config.DC.InstallAdcs) {
                try {
                    $fca = Install-WindowsFeature -Name ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools -ErrorAction Stop
                    Write-RangeLog "AD CS feature pre-install: Success=$($fca.Success) RestartNeeded=$($fca.RestartNeeded)"
                    Write-RangeManifest 'dc-adcs' 'install-feature' 'ADCS-Cert-Authority;ADCS-Web-Enrollment' "Success=$($fca.Success);Restart=$($fca.RestartNeeded)"
                } catch { Write-RangeLog "AD CS feature pre-install: $($_.Exception.Message)" 'WARN' }
            }
            if ($Config.Categories.SmbNetwork) {
                try {
                    $fsmb = Install-WindowsFeature -Name FS-SMB1 -ErrorAction Stop
                    Write-RangeLog "FS-SMB1 feature pre-install: Success=$($fsmb.Success) RestartNeeded=$($fsmb.RestartNeeded)"
                    Write-RangeManifest 'smb-network' 'install-feature' 'FS-SMB1' "Success=$($fsmb.Success);Restart=$($fsmb.RestartNeeded)"
                } catch { Write-RangeLog "FS-SMB1 feature pre-install: $($_.Exception.Message)" 'WARN' }
            }

            if (-not (Test-StageClean 1)) { return }
            $state.Stage = 2; Save-State $state
            Register-ResumeTask
            Write-RangeLog '==== STAGE 1 done. Rebooting so the AD DS tools load; will auto-resume. ====' 'OK'
            Write-Host ""
            Write-Host "  REBOOTING. This resumes by itself (SYSTEM task at startup)." -ForegroundColor Yellow
            Write-Host "  If it does not, run:  C:\CyberRange\Stage-CyberRange.ps1" -ForegroundColor Green
            Write-Host "  Watch: Get-Content C:\ProgramData\CyberRange\logs\rangebuild-*.log -Tail 40 -Wait" -ForegroundColor Green
            Write-Host ""
            Start-Sleep -Seconds 3
            Restart-Computer -Force
            return
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  STAGE 2 -- promote to domain controller
# ══════════════════════════════════════════════════════════════════════════
if ([int]$state.Stage -eq 2) {
    if (Test-IsDomainController) {
        Write-RangeLog 'Host is now a Domain Controller; promotion complete.' 'OK'
        $state.Stage = 3; Save-State $state
    }
    else {
        Write-RangeLog '==== STAGE 2: promoting to Domain Controller ====' 'WARN'
        if (-not (Get-Module -ListAvailable -Name ADDSDeployment)) {
            Write-RangeLog 'AD DS tools still missing after reboot; cannot promote unattended.' 'ERROR'
            Write-RangeLog 'Fix Windows servicing, reboot to retry, or install RSAT-ADDS by hand.' 'WARN'
            return
        }
        $state.PromoteTries = [int]$state.PromoteTries + 1; Save-State $state
        if ([int]$state.PromoteTries -gt 3) {
            Write-RangeLog 'Promotion attempted 3x without success; stopping to avoid a reboot loop.' 'ERROR'
            Unregister-ResumeTask; return
        }
        Register-ResumeTask

        # Install-ADDSForest only throws a generic "Verification of prerequisites
        # failed", which hides the real cause. Log the DETAILED prereq result and
        # the two most common blockers first.
        $dc   = $Config.DC
        $safe = ConvertTo-SecureString $dc.SafeModePassword -AsPlainText -Force
        try {
            $tp = @{ DomainName=$dc.DomainName; DomainNetbiosName=$dc.NetbiosName
                     ForestMode='WinThreshold'; DomainMode='WinThreshold'; InstallDns=$true
                     SafeModeAdministratorPassword=$safe; Force=$true }
            $pre = Test-ADDSForestInstallation @tp -WarningAction SilentlyContinue -ErrorAction Stop
            Write-RangeLog ("Prereq check: " + ((($pre | Format-List * | Out-String).Trim()) -replace '\s*\r?\n\s*','  |  ')) 'WARN'
        } catch { Write-RangeLog "Prereq test could not run: $($_.Exception.Message)" 'WARN' }

        $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
                   (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        if ($pending) { Write-RangeLog 'A REBOOT IS PENDING -- that alone fails the promotion prereq. Reboot, then re-run.' 'ERROR' }

        Write-RangeManifest 'dc-promote' 'promote-forest' "$($dc.DomainName) / $($dc.NetbiosName) (FL=WinThreshold)"
        Write-RangeLog "Promoting into forest '$($dc.DomainName)'. The machine WILL REBOOT if prerequisites pass." 'WARN'
        Write-RangeLog 'Functional level is pinned to WinThreshold (2016): nearly every red-team AD tool is validated against 2016-2022 FLs, and a brand-new 2025 FL trips older parsers.' 'INFO'
        Write-Host ""
        Write-Host "  REBOOTING into the new domain. Resumes by itself." -ForegroundColor Yellow
        Write-Host "  If it does not: C:\CyberRange\Stage-CyberRange.ps1" -ForegroundColor Green
        Write-Host ""
        try {
            Import-Module ADDSDeployment -Force
            Install-ADDSForest -DomainName $dc.DomainName -DomainNetbiosName $dc.NetbiosName `
                -ForestMode 'WinThreshold' -DomainMode 'WinThreshold' -InstallDns `
                -SafeModeAdministratorPassword $safe -NoRebootOnCompletion:$false -Force -ErrorAction Stop
        } catch {
            # A PREREQUISITE failure is not fixed by rebooting -- do not loop.
            Write-RangeLog "Promotion FAILED: $($_.Exception.Message)" 'ERROR'
            Write-RangeLog 'See the prerequisite detail logged above. NOT rebooting -- a reboot does not clear a prereq failure. Fix the cause, then re-run Stage-CyberRange.ps1.' 'ERROR'
            Write-RangeLog 'If the only blocker was a PENDING REBOOT, reboot once by hand -- the resume task retries promotion automatically.' 'WARN'
            return
        }
        # Only reached if Install-ADDSForest returned without rebooting (unusual).
        Write-RangeLog 'Promotion returned without an automatic reboot; forcing one.' 'WARN'
        Start-Sleep -Seconds 5
        Restart-Computer -Force
        return
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  STAGE 3 -- the directory: OUs, groups, staff and service accounts
# ══════════════════════════════════════════════════════════════════════════
if ([int]$state.Stage -eq 3) {
    Write-RangeLog '==== STAGE 3: directory population (OUs, groups, users) ====' 'WARN'
    $script:Failures = 0

    if (-not (Test-IsDomainController)) {
        Write-RangeLog 'Not a domain controller; skipping the directory population.' 'WARN'
        $state.Stage = 4; Save-State $state
    }
    else {
        # ── A DC must resolve DNS via ITSELF or ADWS never answers ────────
        #    F28: the #1 cause of "Unable to find a default server with Active
        #    Directory Web Services running" is a DC pointing at an upstream/NAT
        #    resolver -- it then cannot resolve its own SRV records. Repair once,
        #    up front, before waiting on anything.
        try {
            $ipv4 = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count }
            if (-not ($ipv4 | Where-Object { $_.ServerAddresses -contains '127.0.0.1' })) {
                $idx = (Get-NetIPConfiguration -ErrorAction SilentlyContinue |
                        Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up' } |
                        Select-Object -First 1).InterfaceIndex
                if ($idx) {
                    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses '127.0.0.1' -ErrorAction SilentlyContinue
                    & ipconfig /flushdns | Out-Null
                    Write-RangeLog 'Repaired DC DNS client -> 127.0.0.1 (a DC must resolve via itself).' 'WARN'
                }
            }
        } catch {}

        Write-RangeLog 'Waiting for AD DS (ADWS) to come up...'
        $adUp = $false
        for ($i = 0; $i -lt 60 -and -not $adUp; $i++) {
            # A Disabled service cannot be started -- re-enable before starting, or
            # a Disabled ADWS silently sinks the wait (Start-Service is a no-op on it).
            foreach ($svc in 'NTDS','DNS','ADWS','Netlogon') { $s = Get-Service $svc -ErrorAction SilentlyContinue; if ($s -and $s.StartType -eq 'Disabled') { Set-Service $svc -StartupType Automatic -ErrorAction SilentlyContinue } }
            try { Start-Service NTDS,ADWS,DNS,Netlogon -ErrorAction SilentlyContinue } catch {}
            if (Test-AdReady) { $adUp = $true; break }
            Start-Sleep -Seconds 10
        }
        if (-not $adUp) {
            Write-RangeLog 'AD DID NOT COME UP in ~10 min. ADWS is not answering, so every directory step would fail for the same reason.' 'ERROR'
            Write-RangeLog '   Get-Service ADWS,NTDS,DNS,Netlogon | Select Name,Status,StartType' 'WARN'
            Write-RangeLog ("   nltest /dsgetdc:" + $Config.DC.DomainName) 'WARN'
            Write-RangeLog '   Get-DnsClientServerAddress -AddressFamily IPv4   # must point at 127.0.0.1' 'WARN'
            Step-Failed 'AD DS availability' 'ADWS did not answer'
            if (-not (Test-StageClean 3)) { return }
        }
        Write-RangeLog 'AD is ready.' 'OK'
        Import-Module ActiveDirectory -Force

        # Promotion destroyed the local SAM, so re-create the operator account as
        # a DOMAIN account before anything else. This is the way back in.
        if (-not $SkipPreflight) {
            try {
                & (Join-Path $LocalRoot 'scripts\operator-account.ps1') -FromBuild
                $u = $Config.Analyst.User
                if (-not (Get-ADUser -Filter "SamAccountName -eq '$u'" -ErrorAction SilentlyContinue)) {
                    Step-Failed "operator account '$u'" 'does not exist after provisioning'
                } else { Write-RangeLog "Operator account '$u' re-created as a DOMAIN admin." 'OK' }
            } catch { Step-Failed 'operator account (domain)' $_.Exception.Message }
        }

        # ── Password policy: allow the weak account passwords below ───────
        #    NOT the graded misconfiguration -- Setup re-asserts a weak policy as
        #    a control. This is a PREREQUISITE: the DEFAULT policy (complexity on,
        #    min length 7, "must not contain the account name") rejects several of
        #    the accounts this step creates, e.g. helpdesk / 'Helpdesk@1' (F31).
        try {
            Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot `
                -ComplexityEnabled $false -MinPasswordLength 4 -MinPasswordAge '0.00:00:00' `
                -PasswordHistoryCount 0 -ErrorAction Stop
            Write-RangeLog 'Relaxed the domain password policy so the seeded account passwords are accepted (F31).' 'WARN'
        } catch { Write-RangeLog "Could not relax the password policy: $($_.Exception.Message)" 'WARN' }

        if ($Config.DC.SeedUsers) {
            try { & (Join-Path $LocalRoot 'scripts\directory.ps1') -Config $Config }
            catch { Step-Failed 'directory population' $_.Exception.Message }
        } else {
            Write-RangeLog 'DC.SeedUsers = $false; skipping the directory population.' 'INFO'
        }

        if (-not (Test-StageClean 3)) { return }
        $state.Stage = 4; Save-State $state
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  STAGE 4 -- done
# ══════════════════════════════════════════════════════════════════════════
Unregister-ResumeTask
$state.Stage = 4; Save-State $state

@"
STAGE COMPLETE  -  $(Get-Date -Format s)  -  $env:COMPUTERNAME
Build log: $($env:RANGE_LOGFILE)

The domain structure exists and is HEALTHY. Nothing has been weakened yet.

  Domain      : $(if ($Config.DC.Enabled) { "$($Config.DC.DomainName) / $($Config.DC.NetbiosName)" } else { '(none -- DC.Enabled = $false)' })
  Log in as   : $(if ($Config.Analyst -and $Config.Analyst.Enabled) { $Config.Analyst.User } else { '(NO OPERATOR ACCOUNT -- Analyst disabled)' })

NEXT STEP -- this VM is not a range until you run:

    C:\CyberRange\Setup-CyberRange.ps1

That applies every intentional misconfiguration. After it, verify with:

    C:\CyberRange\Test-RangeConfig.ps1
"@ | Set-Content -Path $StagedFile -Encoding UTF8

Write-RangeLog "==== STAGE COMPLETE. Marker: $StagedFile ====" 'OK'
Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " STEP 1/3 COMPLETE -- the domain is built and healthy." -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " Nothing is weakened yet. This VM is not a range until Setup runs." -ForegroundColor Yellow
Write-Host ""

$setup = Join-Path $LocalRoot 'Setup-CyberRange.ps1'
$runSetup = $Auto
if (-not $Auto) {
    $isSystem = try { [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem } catch { $false }
    if ($isSystem) {
        Write-Host " Running as SYSTEM (auto-resume) -- not prompting. Run Setup yourself:" -ForegroundColor Yellow
        Write-Host "     $setup" -ForegroundColor Green
    } else {
        try {
            $ans = Read-Host " Run STEP 2 (Setup -- apply the misconfigurations) now? [Y/n]"
            $runSetup = ($ans -eq '' -or $ans -match '^(y|yes)$')
        } catch {
            Write-Host " No console to prompt on. Run Setup yourself:  $setup" -ForegroundColor Yellow
        }
    }
}

if ($runSetup) {
    Write-Host ""
    Write-Host " Handing off to STEP 2 (Setup) ..." -ForegroundColor Yellow
    $fwd = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$setup)
    if ($Force) { $fwd += '-Force' }
    if ($Auto)  { $fwd += '-Auto' }
    & powershell.exe @fwd
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host " When you are ready:" -ForegroundColor Cyan
Write-Host "     $setup" -ForegroundColor Green
Write-Host ""
