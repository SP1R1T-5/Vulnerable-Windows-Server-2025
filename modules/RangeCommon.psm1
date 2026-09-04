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
        & icacls.exe $Path /inheritance:r /grant 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' /T /C 2>&1 | Out-Null
        if ($script:LogFile) { Write-RangeLog "ACL locked to SYSTEM+Administrators: $Path" }
        Write-RangeManifest -Category 'safety' -Action 'protect-path' -Target $Path -Detail 'inheritance removed; SYSTEM+Administrators only'
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
    <# Refuses to run unless the operator has acknowledged the isolation guard. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)
    if (-not $Config.Confirmed) {
        throw @'
SAFETY GUARD TRIPPED. This build intentionally weakens the host.
Only run it on an ISOLATED, authorized lab VM with no production data and no
unrestricted internet path. Set  Confirmed = $true  in config\range.config.psd1
after you have confirmed that, then re-run.
'@
    }
    Write-RangeLog 'Safety guard acknowledged (Confirmed = $true). Applying intentional weaknesses.' 'WARN'
}

function Test-IsDomainController {
    # 4 or 5 == DC (per Win32_ComputerSystem.DomainRole)
    (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
}

Export-ModuleMember -Function Initialize-RangeContext, Write-RangeLog, Write-RangeManifest,
    Set-RegValue, Invoke-Native, Assert-RangeSafety, Test-IsDomainController, Protect-RangePath
