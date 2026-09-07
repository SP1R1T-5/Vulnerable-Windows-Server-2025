#requires -Version 5.1
<#
    RangeCommon.psm1
    Shared helpers for the Windows Server 2025 cyber-range builder.

    Provides: run-scoped logging, an applied-changes manifest (CSV), a safety
    guard, and idempotent registry / native-command helpers so each category
    script stays short and auditable.

    FOR ISOLATED, AUTHORIZED EDUCATIONAL LAB USE ONLY.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LogFile      = $null
$script:ManifestFile = $null

function Initialize-RangeContext {
    <#
        Establishes (or re-attaches to) the per-run log + manifest. The
        orchestrator initializes once and exports the paths via environment
        variables; child scripts run standalone re-attach to the same files
        so a single build produces a single log.
    #>
    [CmdletBinding()]
    param(
        [string]$LogDir = (Join-Path $env:ProgramData 'CyberRange\logs')
    )

    if ($env:RANGE_LOGFILE -and (Test-Path $env:RANGE_LOGFILE)) {
        $script:LogFile      = $env:RANGE_LOGFILE
        $script:ManifestFile = $env:RANGE_MANIFEST
        return
    }

    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

    # The manifest is the instructor ANSWER KEY -- it records every seeded
    # password in plaintext. C:\ProgramData grants BUILTIN\Users ReadAndExecute
    # by inheritance, so without this the red team simply reads the answers off
    # the box (and the build also weakens anonymous access on top of that).
    # Lock the whole CyberRange tree, not just logs: setup-state.json, READY.txt
    # and the break-glass card live one level up.
    Protect-RangePath -Path (Split-Path $LogDir -Parent)

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:LogFile      = Join-Path $LogDir "rangebuild-$stamp.log"
    $script:ManifestFile = Join-Path $LogDir "manifest-$stamp.csv"
    'Timestamp,Category,Action,Target,Detail' | Set-Content -Path $script:ManifestFile -Encoding UTF8

    $env:RANGE_LOGFILE  = $script:LogFile
    $env:RANGE_MANIFEST = $script:ManifestFile
    Write-RangeLog "Range context initialized. Log: $($script:LogFile)"
}

function Write-RangeLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Message,
        [Parameter(Position = 1)][ValidateSet('INFO','WARN','ERROR','OK')][string]$Level = 'INFO'
    )
    $line  = "{0}  [{1,-5}] {2}" -f (Get-Date -Format 's'), $Level, $Message
    $color = switch ($Level) { 'WARN' {'Yellow'} 'ERROR' {'Red'} 'OK' {'Green'} default {'Gray'} }
    Write-Host $line -ForegroundColor $color
    if ($script:LogFile) { Add-RangeFileLine -Path $script:LogFile -Line $line }
}

function Add-RangeFileLine {
    <# Append one line, tolerating transient file locks (AV/indexer/rapid calls).
       Logging must NEVER throw and abort the build. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Line)
    for ($i = 0; $i -lt 5; $i++) {
        try { Add-Content -Path $Path -Value $Line -Encoding UTF8 -ErrorAction Stop; return }
        catch { Start-Sleep -Milliseconds 100 }
    }
    # Last-resort: give up silently rather than break the run.
}

function Protect-RangePath {
    <#
        Strips inheritance from a path and grants only SYSTEM + Administrators.
        Used on the log/manifest directory and the staged build tree, both of
        which contain plaintext range credentials and would otherwise inherit
        BUILTIN\Users:ReadAndExecute from C:\ or C:\ProgramData.

        Best-effort by design: this must never abort a build.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return }
    try {
        # F25: take ownership to Administrators, strip inheritance, grant ONLY
        # SYSTEM + Administrators, and explicitly remove any world-readable ACE
        # (Everyone / Authenticated Users / Users) that a manual
        # `icacls /grant Everyone:F` workaround may have left behind. This makes
        # a re-run REPAIR a directory someone loosened to get unstuck, instead of
        # silently leaving the answer key world-readable. SIDs, not names, so it
        # is locale-independent: Everyone=S-1-1-0, Auth Users=S-1-5-11,
        # Users=S-1-5-32-545.
        & icacls.exe $Path /setowner 'Administrators' /T /C 2>&1 | Out-Null

        # F27: apply the inheritable ACE to the CONTAINER ONLY -- never with /T.
        #
        # `/inheritance:r /grant:r ... /T /C` is a destructive, non-atomic rewrite:
        # /inheritance:r strips each child's inherited ACEs and /grant:r REPLACES
        # its explicit ones, while /C silently continues past any child that fails.
        # A child that loses its inherited ACEs but does not receive the new grant
        # is left with an effectively empty DACL and becomes unopenable -- which is
        # how the build locked itself out of its own setup-state.json and could no
        # longer record Phase 99.
        #
        # Granting on the container and letting children inherit is not destructive:
        # nothing is ever removed from a child, so a partial failure cannot strand
        # one. The write self-test at the end is the real guarantee either way.
        & icacls.exe $Path /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' /C 2>&1 | Out-Null

        # Children re-inherit the container ACL. /reset on the children (not the
        # container -- that would undo the line above) is what actually propagates.
        if (Test-Path $Path -PathType Container) {
            & icacls.exe (Join-Path $Path '*') /reset /T /C 2>&1 | Out-Null
        }

        & icacls.exe $Path /remove:g '*S-1-1-0' '*S-1-5-11' '*S-1-5-32-545' /T /C 2>&1 | Out-Null

        # Prove it: an administrator must still be able to write here afterwards.
        if (Test-Path $Path -PathType Container) {
            $probe = Join-Path $Path '.acl-probe.tmp'
            try {
                Set-Content -Path $probe -Value 'probe' -ErrorAction Stop
                Remove-Item $probe -Force -ErrorAction SilentlyContinue
            } catch {
                Write-RangeLog "ACL SELF-TEST FAILED for $Path -- this session can no longer write there. Reverting to inherited permissions to avoid locking the build out." 'ERROR'
                & icacls.exe $Path /reset /T /C 2>&1 | Out-Null
                & icacls.exe $Path /inheritance:e /C 2>&1 | Out-Null
                Write-RangeManifest -Category 'safety' -Action 'protect-path-REVERTED' -Target $Path -Detail $_.Exception.Message
                return
            }
        }
        if ($script:LogFile) { Write-RangeLog "ACL locked to SYSTEM+Administrators (owner+inheritance+world ACEs enforced): $Path" }
        Write-RangeManifest -Category 'safety' -Action 'protect-path' -Target $Path -Detail 'owner=Administrators; inheritance removed; SYSTEM+Administrators only; Everyone/Users/AuthUsers removed'
    }
    catch {
        if ($script:LogFile) { Write-RangeLog "Could not protect $Path : $($_.Exception.Message)" 'WARN' }
    }
}

function Write-RangeManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [string]$Detail = ''
    )
    if (-not $script:ManifestFile) { return }
    $esc = { param($s) '"' + ($s -replace '"','""') + '"' }
    $row = @(
        (& $esc (Get-Date -Format 's')),
        (& $esc $Category),
        (& $esc $Action),
        (& $esc $Target),
        (& $esc $Detail)
    ) -join ','
    Add-RangeFileLine -Path $script:ManifestFile -Line $row
}

function Set-RegValue {
    <# Idempotent registry write using the PS registry provider (HKLM:\ / HKCU:\ paths). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('String','ExpandString','Binary','DWord','MultiString','QWord')][string]$Type,
        [Parameter(Mandatory)]$Value,
        [string]$Category = 'registry'
    )
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction Stop | Out-Null
        Write-RangeManifest -Category $Category -Action 'set-reg' -Target "$Path\$Name" -Detail "$Type=$Value"
        Write-RangeLog "reg  $Path\$Name = $Value ($Type)"
    }
    catch {
        # Some keys are ACL-/Tamper-Protection-locked on 2025 (e.g. the Defender
        # 'Features'/'Real-Time Protection' hives). A blocked write is expected;
        # log it and keep going rather than aborting the whole category.
        Write-RangeManifest -Category $Category -Action 'set-reg-BLOCKED' -Target "$Path\$Name" -Detail $_.Exception.Message
        Write-RangeLog "reg BLOCKED $Path\$Name  ($($_.Exception.Message))" 'WARN'
    }
}

function Invoke-Native {
    <# Runs an external command, logs it, and does not throw on non-zero exit
       (many range steps touch features that may be absent on a given build). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$File,
        [string[]]$Arguments = @(),
        [string]$Category = 'native'
    )
    Write-RangeLog "exec $File $($Arguments -join ' ')"
    try {
        $out = & $File @Arguments 2>&1
        Write-RangeManifest -Category $Category -Action 'exec' -Target $File -Detail ($Arguments -join ' ')
        if ($out) { $out | ForEach-Object { Write-RangeLog "     $_" } }
    }
    catch {
        Write-RangeLog "exec failed: $($_.Exception.Message)" 'WARN'
    }
}

function Assert-RangeSafety {
    <# Refuses to run unless the operator has acknowledged the isolation guard
       (Confirmed) and has replaced the shipped placeholder credentials (F20). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [switch]$AllowPlaceholderCredentials
    )
    if (-not $Config.Confirmed) {
        throw @'
SAFETY GUARD TRIPPED. This build intentionally weakens the host.
Only run it on an ISOLATED, authorized lab VM with no production data and no
unrestricted internet path. Set  Confirmed = $true  in config\range.config.psd1
after you have confirmed that, then re-run.
'@
    }

    # F20: refuse to build while any shipped placeholder credential is present.
    # The list lives HERE, not in the config, so editing the config cannot
    # disable the check. Since the F1 fix, LocalAdminAutoLogonPass BECOMES the
    # Administrator password on every clone -- a documentation-only gate on a
    # value with that blast radius is the wrong control.
    if (-not $AllowPlaceholderCredentials) {
        # Only genuine shipped "change me" example values. NOT the intentionally
        # weak seeded loot (e.g. HiddenAdminPassword = 'CrazySnow2024*'), which is
        # MEANT to stay a known, crackable value and is deliberately identical
        # across clones -- blocking on it would be wrong.
        # These must match what the repo actually SHIPS in config\range.config.psd1.
        # The list drifted once before: it named values ('Password!',
        # 'ChangeMe-BreakGlass!2026') that were no longer the shipped defaults, so
        # the gate passed on a completely untouched config and protected nothing.
        # If you change a shipped default, change it here in the same commit.
        $placeholders = @('Password123!','bb123#123','Password!','S@feM0de-ChangeMe!','ChangeMe-BreakGlass!2026')
        $vals = @{}
        if ($Config.ContainsKey('LocalAdminAutoLogonPass')) { $vals['LocalAdminAutoLogonPass'] = [string]$Config.LocalAdminAutoLogonPass }
        if ($Config.ContainsKey('HiddenAdminPassword'))     { $vals['HiddenAdminPassword']     = [string]$Config.HiddenAdminPassword }
        if ($Config.DC -and $Config.DC.ContainsKey('SafeModePassword'))  { $vals['DC.SafeModePassword'] = [string]$Config.DC.SafeModePassword }
        if ($Config.Analyst -and $Config.Analyst.ContainsKey('Password')) { $vals['Analyst.Password'] = [string]$Config.Analyst.Password }
        $bad = @()
        foreach ($k in $vals.Keys) {
            $v = $vals[$k]
            if ($v -and (($placeholders -contains $v) -or ($v -match 'ChangeMe'))) { $bad += $k }
        }
        if ($bad.Count) {
            throw ("PLACEHOLDER CREDENTIALS PRESENT: " + ($bad -join ', ') + ".`n" +
                   "These ship as examples and BECOME real credentials on every clone. Set them to your own`n" +
                   "values in config\range.config.psd1, record them off-box, then re-run.`n" +
                   "For a deliberate off-network dry run only: -AllowPlaceholderCredentials (Setup: -Force).")
        }
    }

    Write-RangeLog 'Safety guard acknowledged (Confirmed = $true). Applying intentional weaknesses.' 'WARN'
}

function Test-IsDomainController {
    # 4 or 5 == DC (per Win32_ComputerSystem.DomainRole)
    (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
}

function Disable-RangeUpdateServices {
    <#
        Re-assert the Windows Update lockdown.

        F35: any SERVICING operation -- Install-WindowsFeature,
        Add-WindowsCapability, DISM -- re-enables `wuauserv`, because the
        component store may need to pull payload from Windows Update. The field
        run showed this exactly: `wuauserv` was Disabled/Stopped, then running
        dc\20-adcs-esc1.ps1 (which calls Install-WindowsFeature for the AD CS
        role) flipped it back and two update-defender controls regressed.
        WaaSMedicSvc and UsoSvc were untouched, which is the signature of the
        servicing stack specifically re-enabling the update client.

        So: call this AFTER anything that installs a feature or capability.
        Idempotent and safe to call repeatedly.
    #>
    [CmdletBinding()]
    param([string]$Because = 'post-servicing re-assert')
    $changed = @()
    foreach ($svc in 'wuauserv','WaaSMedicSvc','UsoSvc') {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
        $cur  = $null
        try { $cur = (Get-ItemProperty -Path $path -Name Start -ErrorAction Stop).Start } catch {}
        if ($cur -ne 4) {
            Set-RegValue $path 'Start' DWord 4 'updates-defender'
            try { Stop-Service $svc -Force -ErrorAction SilentlyContinue } catch {}
            $changed += "$svc (was Start=$cur)"
        }
    }
    if ($changed.Count) {
        Write-RangeLog ("Re-disabled update service(s) after servicing [$Because]: " + ($changed -join ', ')) 'WARN'
        Write-RangeManifest -Category 'updates-defender' -Action 'reassert-update-lockdown' -Target ($changed -join ';') -Detail $Because
    }
}

Export-ModuleMember -Function Initialize-RangeContext, Write-RangeLog, Write-RangeManifest,
    Set-RegValue, Invoke-Native, Assert-RangeSafety, Test-IsDomainController, Protect-RangePath,
    Disable-RangeUpdateServices
