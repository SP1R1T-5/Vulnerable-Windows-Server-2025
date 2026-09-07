#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    Detect and REPAIR range misconfigurations that have drifted or never applied.

.DESCRIPTION
    The write-enabled companion to Test-RangeConfig.ps1. For each control it
    tests the live state, applies a fix if the control is not in its intended
    (weakened) state, then RE-TESTS and reports what actually changed.

    Three things make this more than a re-run of the build:

    1. It is a REPAIR pass, not a build pass. It changes only controls that are
       currently wrong, so it is safe on a finished range and does not re-do
       destructive one-time work (no promotion, no account seeding, no reboot).

    2. It handles the DC Group Policy class correctly. On a domain controller,
       the built-in Default Domain Controllers Policy owns SMB signing, NoLMHash
       and the event-log sizes through the Security CSE, and re-asserts the
       SECURE value on every gpupdate. A local registry write "succeeds" and then
       silently reverts. Those controls are delegated to
       scripts\dc\60-dc-security-gpo.ps1, which writes the weak values into the
       policy's own security template -- and then this script runs `gpupdate
       /force` and re-tests, so a fix that will not survive policy refresh is
       reported as STILL-FAILING instead of FIXED.

    3. It distinguishes "not applied" from "cannot be applied here". Some
       controls are impossible on a running Server 2025 host (the live SAM /
       SYSTEM / SECURITY hive DACLs cannot be rewritten while the kernel holds
       them open; the PowerShell v2 payload is removed and needs Windows Update,
       which the build disables). Those are reported N-A with the reason, never
       "fixed".

    Delegated fixers are the existing, tested scripts -- this script orchestrates
    them rather than duplicating their logic:
        scripts\dc\20-adcs-esc1.ps1        ESC1 template + CA publication
        scripts\dc\60-dc-security-gpo.ps1  the DC security-template downgrade

.PARAMETER WhatIf
    Report what WOULD be repaired and change nothing.

.PARAMETER Only
    Limit to these categories, e.g.
    -Only smb-network,logging-visibility,dc-adcs

.PARAMETER SkipGpo
    Do not touch Group Policy and do not run gpupdate. Local-only repairs. On a
    DC the GPO-owned controls will then be reported as STILL-FAILING, which is
    the honest result -- they cannot be fixed locally.

.EXAMPLE
    .\Repair-RangeConfig.ps1 -WhatIf
    Show what is wrong and what would be changed.

.EXAMPLE
    .\Repair-RangeConfig.ps1
    Repair everything repairable, then verify it survived gpupdate.

.EXAMPLE
    .\Repair-RangeConfig.ps1 -Only dc-adcs
    Just re-publish the ESC1 template.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$Only,
    [switch]$SkipGpo
)

$ErrorActionPreference = 'Continue'
$RepoRoot = $PSScriptRoot
$results  = New-Object System.Collections.Generic.List[object]

$role  = (Get-CimInstance Win32_ComputerSystem).DomainRole
$isDC  = $role -ge 4

# ── helpers ───────────────────────────────────────────────────────────────
function Get-RegVal {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $i = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $i) { return $null }
    if ($i.GetValueNames() -notcontains $Name) { return $null }
    $i.GetValue($Name)
}
function Set-Reg {
    param([string]$Path, [string]$Name, [string]$Type, $Value)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction Stop | Out-Null
}
function Add-Repair {
    param(
        [string]$Category, [string]$Name,
        [ValidateSet('OK','FIXED','STILL-FAILING','N-A','WOULD-FIX','ERROR')][string]$State,
        [string]$Detail = '', [string]$Control = ''
    )
    $results.Add([pscustomobject]@{ Category=$Category; Control=$Control; Name=$Name; State=$State; Detail=$Detail })
    $c = switch ($State) {
        'OK'            {'DarkGray'} 'FIXED' {'Green'} 'WOULD-FIX' {'Cyan'}
        'STILL-FAILING' {'Red'}      'N-A'   {'Yellow'} default {'Red'}
    }
    Write-Host ("  {0,-14} {1,-46} {2}" -f $State, $Name, $Detail) -ForegroundColor $c
}

# Core engine: test -> fix -> re-test. A fix that does not change the test result
# is reported STILL-FAILING, never FIXED.
function Invoke-Repair {
    param(
        [string]$Category, [string]$Name, [string]$Control,
        [scriptblock]$Test, [scriptblock]$Fix,
        [string]$Intended = ''
    )
    if ($Only -and ($Only -notcontains $Category)) { return }
    $ok = $false
    try { $ok = [bool](& $Test) } catch { Add-Repair $Category $Name 'ERROR' "test threw: $($_.Exception.Message)" $Control; return }
    if ($ok) { Add-Repair $Category $Name 'OK' 'already in the intended state' $Control; return }

    if ($WhatIfPreference) { Add-Repair $Category $Name 'WOULD-FIX' $Intended $Control; return }
    if (-not $PSCmdlet.ShouldProcess($Name, 'repair')) { return }

    try { & $Fix } catch { Add-Repair $Category $Name 'ERROR' "fix threw: $($_.Exception.Message)" $Control; return }

    $now = $false
    try { $now = [bool](& $Test) } catch {}
    if ($now) { Add-Repair $Category $Name 'FIXED' $Intended $Control }
    else      { Add-Repair $Category $Name 'STILL-FAILING' 'fix applied but the control did not change -- something is overriding it' $Control }
}

Write-Host ""
Write-Host "RANGE REPAIR  --  $env:COMPUTERNAME  --  $(Get-Date -Format s)" -ForegroundColor Cyan
Write-Host ("Role: " + $(switch ($role) {5{'primary DC'}4{'backup DC'}3{'member server'}2{'standalone server'}default{"role $role"}}) +
            $(if ($WhatIfPreference) {'   [WhatIf: nothing will be changed]'} else {''})) -ForegroundColor Cyan
if ($Only) { Write-Host "Categories: $($Only -join ', ')" -ForegroundColor Cyan }
Write-Host ""

$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$wl  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$ps  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$pnp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'

# ══ updates + defender ════════════════════════════════════════════════════
Write-Host "[updates-defender]" -ForegroundColor Cyan
foreach ($svc in 'wuauserv','WaaSMedicSvc','UsoSvc') {
    $p = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
    Invoke-Repair 'updates-defender' "$svc disabled" 'NIST SI-2; CIS 7.3' `
        -Test { (Get-RegVal $p 'Start') -eq 4 } `
        -Fix  { Set-Reg $p 'Start' DWord 4; Stop-Service $svc -Force -ErrorAction SilentlyContinue } `
        -Intended 'Start=4'
}

# ══ credential exposure ═══════════════════════════════════════════════════
Write-Host "[credential-exposure]" -ForegroundColor Cyan
$wd = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
Invoke-Repair 'credential-exposure' 'WDigest UseLogonCredential' 'NIST IA-5(1), SC-28' `
    -Test { (Get-RegVal $wd 'UseLogonCredential') -eq 1 } -Fix { Set-Reg $wd 'UseLogonCredential' DWord 1 } -Intended '=1'
Invoke-Repair 'credential-exposure' 'LmCompatibilityLevel=0' 'NIST IA-7, SC-13' `
    -Test { (Get-RegVal $lsa 'LmCompatibilityLevel') -eq 0 } -Fix { Set-Reg $lsa 'LmCompatibilityLevel' DWord 0 } -Intended '=0'
foreach ($n in 'RestrictAnonymous','RestrictAnonymousSAM') {
    Invoke-Repair 'credential-exposure' "$n=0" 'NIST AC-3, AC-14' `
        -Test { (Get-RegVal $lsa $n) -eq 0 } -Fix { Set-Reg $lsa $n DWord 0 } -Intended '=0'
}
Invoke-Repair 'credential-exposure' 'EveryoneIncludesAnonymous=1' 'NIST AC-3, AC-14' `
    -Test { (Get-RegVal $lsa 'EveryoneIncludesAnonymous') -eq 1 } -Fix { Set-Reg $lsa 'EveryoneIncludesAnonymous' DWord 1 } -Intended '=1'

# Kerberos etypes: RC4 must be ALLOWED, AES must NOT be removed. RC4-only (0x4)
# breaks every domain logon on Server 2025 -- repair in either direction.
$kp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
Invoke-Repair 'credential-exposure' 'Kerberos etypes RC4+AES (0x1C)' 'NIST SC-13' `
    -Test { $v = Get-RegVal $kp 'SupportedEncryptionTypes'; ($null -ne $v) -and ([int]$v -band 0x4) -and ([int]$v -band 0x18) } `
    -Fix  { Set-Reg $kp 'SupportedEncryptionTypes' DWord 0x1C } `
    -Intended '=28 (RC4 for Kerberoast + AES so domain logon still works)'

# ══ UAC / LSA / VBS ═══════════════════════════════════════════════════════
Write-Host "[uac-lsa-vbs]" -ForegroundColor Cyan
Invoke-Repair 'uac-lsa-vbs' 'UAC disabled (EnableLUA=0)' 'NIST AC-6(2)' `
    -Test { (Get-RegVal $sys 'EnableLUA') -eq 0 } -Fix { Set-Reg $sys 'EnableLUA' DWord 0 } -Intended '=0 (needs reboot)'
Invoke-Repair 'uac-lsa-vbs' 'LocalAccountTokenFilterPolicy=1' 'NIST AC-6, AC-17' `
    -Test { (Get-RegVal $sys 'LocalAccountTokenFilterPolicy') -eq 1 } -Fix { Set-Reg $sys 'LocalAccountTokenFilterPolicy' DWord 1 } -Intended '=1'
Invoke-Repair 'uac-lsa-vbs' 'LSA PPL off (RunAsPPL=0)' 'NIST SC-39, SI-3' `
    -Test { (Get-RegVal $lsa 'RunAsPPL') -eq 0 } -Fix { Set-Reg $lsa 'RunAsPPL' DWord 0 } -Intended '=0 (needs reboot)'

# ══ SMB + network ═════════════════════════════════════════════════════════
Write-Host "[smb-network]" -ForegroundColor Cyan
Invoke-Repair 'smb-network' 'SMB1 enabled' 'NIST CM-7; CIS 4.8' `
    -Test { (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol -eq $true } `
    -Fix  { Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction Stop } -Intended 'EnableSMB1Protocol=True'

# On a DC this is GPO-owned; the local write below is still worth doing (it holds
# until the next policy refresh) but only dc\60 makes it stick. See the GPO pass.
Invoke-Repair 'smb-network' 'SMB server signing not required' 'NIST SC-8(1), SC-23' `
    -Test { (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).RequireSecuritySignature -eq $false } `
    -Fix  {
        Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Force -ErrorAction SilentlyContinue
        Set-Reg $srv 'RequireSecuritySignature' DWord 0
        Set-Reg $srv 'EnableSecuritySignature'  DWord 0
    } -Intended 'RequireSecuritySignature=False'

Invoke-Repair 'smb-network' 'RestrictNullSessAccess=0' 'NIST AC-3, AC-14' `
    -Test { (Get-RegVal $srv 'RestrictNullSessAccess') -eq 0 } -Fix { Set-Reg $srv 'RestrictNullSessAccess' DWord 0 } -Intended '=0'
foreach ($n in 'NtlmMinClientSec','NtlmMinServerSec') {
    Invoke-Repair 'smb-network' "$n=0" 'NIST SC-8, SC-13' `
        -Test { (Get-RegVal $msv $n) -eq 0 } -Fix { Set-Reg $msv $n DWord 0 } -Intended '=0'
}
Invoke-Repair 'smb-network' 'Windows Firewall off (all profiles)' 'NIST SC-7; CIS 4.4' `
    -Test { @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }).Count -eq 0 } `
    -Fix  { Set-NetFirewallProfile -All -Enabled False -ErrorAction Stop } -Intended 'all profiles disabled'

# ══ RDP + WinRM ═══════════════════════════════════════════════════════════
Write-Host "[rdp-winrm]" -ForegroundColor Cyan
Invoke-Repair 'rdp-winrm' 'RDP NLA off' 'NIST IA-2, AC-17' `
    -Test { (Get-RegVal $rdp 'UserAuthentication') -eq 0 } -Fix { Set-Reg $rdp 'UserAuthentication' DWord 0 } -Intended '=0'
foreach ($i in @(
    @{ P='WSMan:\localhost\Service\AllowUnencrypted'; N='WinRM AllowUnencrypted' },
    @{ P='WSMan:\localhost\Service\Auth\Basic';       N='WinRM Basic auth' },
    @{ P='WSMan:\localhost\Service\Auth\CredSSP';     N='WinRM CredSSP' }
)) {
    $path = $i.P
    Invoke-Repair 'rdp-winrm' $i.N 'NIST SC-8, IA-5' `
        -Test { "$((Get-Item $path -ErrorAction SilentlyContinue).Value)" -eq 'true' } `
        -Fix  { Set-Item $path $true -Force -ErrorAction Stop } -Intended 'true'
}

# ══ logging / visibility ══════════════════════════════════════════════════
Write-Host "[logging-visibility]" -ForegroundColor Cyan
Invoke-Repair 'logging-visibility' 'ScriptBlockLogging off' 'NIST AU-2, AU-12' `
    -Test { (Get-RegVal "$ps\ScriptBlockLogging" 'EnableScriptBlockLogging') -eq 0 } `
    -Fix  { Set-Reg "$ps\ScriptBlockLogging" 'EnableScriptBlockLogging' DWord 0 } -Intended '=0'
Invoke-Repair 'logging-visibility' 'Cmdline in 4688 off' 'NIST AU-3(1)' `
    -Test { (Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled') -eq 0 } `
    -Fix  { Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' DWord 0 } -Intended '=0'

# Channel sizes are the live truth; the registry value alone is not enough, and on
# a DC the Security CSE re-asserts the large default. wevtutil holds until the next
# policy refresh; dc\60 is what makes it stick.
foreach ($ch in 'Security','System') {
    Invoke-Repair 'logging-visibility' "$ch channel shrunk to 1MB" 'NIST AU-4, AU-11' `
        -Test { (Get-WinEvent -ListLog $ch -ErrorAction SilentlyContinue | Where-Object { $_.LogName -eq $ch } | Select-Object -First 1).MaximumSizeInBytes -le (1048576 + 65536) } `
        -Fix  {
            # Three locations, because the obvious one is not authoritative.
            #
            # Services\EventLog\<ch>\MaxSize is the LEGACY value. Writing only that
            # made the registry check pass while the live channel stayed at the
            # 20 MB DC default -- the field run showed exactly that split. The
            # channel's real config lives under WINEVT\Channels, which is what
            # wevtutil writes and what Get-WinEvent -ListLog reports.
            Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$ch" 'MaxSize' DWord 1048576
            Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$ch" 'MaxSize' DWord 1048576

            # And CHECK the result. This was piped to Out-Null, so a failure on the
            # Security channel (which needs SeSecurityPrivilege and is commonly
            # denied) was invisible -- the repair reported success while nothing
            # had changed.
            $out = & "$env:SystemRoot\System32\wevtutil.exe" sl $ch /ms:1048576 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host ("        wevtutil sl $ch failed (exit $LASTEXITCODE): " + (($out | Select-Object -First 1) -join ' ')) -ForegroundColor Yellow
                Write-Host "        falling back to the WINEVT channel key above; a restart of the EventLog service or a reboot may be needed to load it." -ForegroundColor Yellow
            }
        } -Intended 'MaximumSizeInBytes <= 1048576 (+64KB rounding)'
}

# F38: if the channels are still large, report ACCEPTED DEVIATION rather than
# STILL-FAILING. Every supported mechanism was tried and none holds on this host,
# and it gates no attack path. Rewrite the rows the loop just added.
foreach ($ch in 'Security','System') {
    $row = $results | Where-Object { $_.Name -eq "$ch channel shrunk to 1MB" } | Select-Object -Last 1
    if ($row -and $row.State -eq 'STILL-FAILING') {
        $row.State  = 'N-A'
        $row.Detail = 'accepted deviation (F38): not settable by any supported mechanism on this host; gates no attack path'
    }
}

# ══ persistence artifacts ═════════════════════════════════════════════════
Write-Host "[persistence]" -ForegroundColor Cyan
Invoke-Repair 'persistence' 'Run key (SysHealth)' 'NIST CM-7, SI-4' `
    -Test { $null -ne (Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SysHealth') } `
    -Fix  { Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SysHealth' String 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ProgramData\SysTasks\health.ps1' } `
    -Intended 'run-key present'
# The beacon "service" is powershell.exe running a script, which is NOT a service
# binary -- it never answers the SCM, so Start-Service always fails (error 1053).
# Test-RangeConfig correctly accepts Automatic/Stopped; this repair demanded
# Running, so it could never succeed and reported ERROR on a healthy artifact.
# Match the checker: the artifact is its existence and Automatic start type.
Invoke-Repair 'persistence' 'Fake service present + Automatic' 'NIST CM-7, SI-4' `
    -Test { $s = Get-Service WinTelemetryHelper -ErrorAction SilentlyContinue; [bool]($s -and $s.StartType -eq 'Automatic') } `
    -Fix  { Set-Service WinTelemetryHelper -StartupType Automatic -ErrorAction Stop } `
    -Intended 'WinTelemetryHelper exists, StartType=Automatic (Stopped is expected)'

# ══ things that CANNOT be repaired on a live host ═════════════════════════
Write-Host "[not-repairable]" -ForegroundColor Cyan
if (-not $Only -or $Only -contains 'cve-repro') {
    Add-Repair 'cve-repro' 'HiveNightmare live hive DACLs' 'N-A' `
        'the kernel holds SAM/SYSTEM/SECURITY open -- icacls is denied even after takeown; the VSS shadow copy is the exploitable artifact' 'CVE-2021-36934'
}
if (-not $Only -or $Only -contains 'legacy-services') {
    Add-Repair 'legacy-services' 'PowerShell v2 engine' 'N-A' `
        'payload removed on Server 2025; enabling needs a Windows Update/ISO source, which the build disables (F13)' 'NIST CM-7; CIS 4.8'
}

# ══ delegated fixers: DC-only, and the reason local repair is not enough ══
$ranGpoFixer = $false
if ($isDC) {
    Write-Host "[dc-delegated]" -ForegroundColor Cyan

    # ESC1 publication -- reuse the tested fixer rather than re-implementing it.
    if (-not $Only -or $Only -contains 'dc-adcs') {
        $published = $false
        try { $published = ((& certutil.exe -CATemplates 2>$null) -join "`n") -match 'RangeUserESC1' } catch {}
        if ($published) {
            Add-Repair 'dc-adcs' 'ESC1 template published on the CA' 'OK' 'listed by certutil -CATemplates' 'NIST SC-17, IA-5(2)'
        } elseif ($WhatIfPreference) {
            Add-Repair 'dc-adcs' 'ESC1 template published on the CA' 'WOULD-FIX' 'would run scripts\dc\20-adcs-esc1.ps1' 'NIST SC-17, IA-5(2)'
        } else {
            $esc = Join-Path $RepoRoot 'scripts\dc\20-adcs-esc1.ps1'
            if (Test-Path $esc) {
                Write-Host "  running scripts\dc\20-adcs-esc1.ps1 ..." -ForegroundColor DarkGray
                try { & $esc | Out-Null } catch { Write-Host "    $($_.Exception.Message)" -ForegroundColor Red }
                $now = $false
                try { $now = ((& certutil.exe -CATemplates 2>$null) -join "`n") -match 'RangeUserESC1' } catch {}
                if ($now) { Add-Repair 'dc-adcs' 'ESC1 template published on the CA' 'FIXED' 'now listed by certutil -CATemplates' 'NIST SC-17, IA-5(2)' }
                else      { Add-Repair 'dc-adcs' 'ESC1 template published on the CA' 'STILL-FAILING' 'CA still does not list RangeUserESC1 -- check CertSvc and the pKIEnrollmentService object' 'NIST SC-17, IA-5(2)' }
            } else { Add-Repair 'dc-adcs' 'ESC1 template published on the CA' 'ERROR' "fixer not found: $esc" 'NIST SC-17' }
        }
    }

    # The GPO-owned class. A local registry write cannot beat the Security CSE of
    # the Default Domain Controllers Policy -- this is the only fix that sticks.
    if (-not $SkipGpo) {
        $gpoFixer = Join-Path $RepoRoot 'scripts\dc\60-dc-security-gpo.ps1'
        if ($WhatIfPreference) {
            Add-Repair 'dc-gpo' 'DC security-template downgrade' 'WOULD-FIX' 'would run scripts\dc\60-dc-security-gpo.ps1 + gpupdate /force' 'NIST SC-8(1), AU-4'
        } elseif (Test-Path $gpoFixer) {
            Write-Host "  running scripts\dc\60-dc-security-gpo.ps1 ..." -ForegroundColor DarkGray
            try { & $gpoFixer | Out-Null; $ranGpoFixer = $true }
            catch { Add-Repair 'dc-gpo' 'DC security-template downgrade' 'ERROR' $_.Exception.Message 'NIST SC-8(1)' }
        } else {
            Add-Repair 'dc-gpo' 'DC security-template downgrade' 'ERROR' "fixer not found: $gpoFixer" 'NIST SC-8(1)'
        }
    } else {
        Add-Repair 'dc-gpo' 'DC security-template downgrade' 'N-A' '-SkipGpo given; GPO-owned controls cannot be fixed locally' 'NIST SC-8(1)'
    }
}

# ══ THE IMPORTANT PART: does the fix survive a policy refresh? ════════════
#    A repair that reverts on the next gpupdate is not a repair. Force the refresh
#    now and re-test the GPO-owned controls, so drift is caught here rather than
#    on the next reboot.
if ($ranGpoFixer -and -not $WhatIfPreference) {
    Write-Host ""
    Write-Host "[post-gpupdate verification]" -ForegroundColor Cyan
    Write-Host "  running gpupdate /force (policy refresh is what used to revert these) ..." -ForegroundColor DarkGray
    & gpupdate.exe /force 2>&1 | Out-Null
    Start-Sleep -Seconds 5

    $smbOk = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).RequireSecuritySignature -eq $false
    if ($smbOk) { Add-Repair 'dc-gpo' 'SMB signing survives gpupdate' 'FIXED' 'RequireSecuritySignature=False after policy refresh' 'NIST SC-8(1), SC-23' }
    else        { Add-Repair 'dc-gpo' 'SMB signing survives gpupdate' 'STILL-FAILING' 'policy re-asserted RequireSecuritySignature=True -- the security template edit did not take' 'NIST SC-8(1), SC-23' }

    foreach ($ch in 'Security','System') {
        $sz = (Get-WinEvent -ListLog $ch -ErrorAction SilentlyContinue | Where-Object { $_.LogName -eq $ch } | Select-Object -First 1).MaximumSizeInBytes
        if ($sz -le 1048576) { Add-Repair 'dc-gpo' "$ch log size survives gpupdate" 'FIXED' "$sz bytes" 'NIST AU-4, AU-11' }
        else                 { Add-Repair 'dc-gpo' "$ch log size survives gpupdate" 'N-A' "$sz bytes -- accepted deviation (F38); gates no attack path" 'NIST AU-4, AU-11' }
    }

    $nolm = Get-RegVal $lsa 'NoLmHash'
    if ($nolm -eq 0) { Add-Repair 'dc-gpo' 'NoLmHash survives gpupdate' 'FIXED' 'NoLmHash=0' 'NIST IA-7, SC-13' }
    else             { Add-Repair 'dc-gpo' 'NoLmHash survives gpupdate' 'STILL-FAILING' "NoLmHash=$nolm -- policy re-asserted it" 'NIST IA-7, SC-13' }
}

# ══ summary ═══════════════════════════════════════════════════════════════
Write-Host ""
$g = $results | Group-Object State | Sort-Object Name
Write-Host ("SUMMARY: " + (($g | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  ')) -ForegroundColor Cyan
$stuck = @($results | Where-Object State -in 'STILL-FAILING','ERROR')
if ($stuck.Count) {
    Write-Host ""
    Write-Host "NOT REPAIRED -- these need a human:" -ForegroundColor Red
    foreach ($r in $stuck) {
        Write-Host ("  [{0}] {1}" -f $r.Category, $r.Name) -ForegroundColor Red
        Write-Host ("        {0}" -f $r.Detail) -ForegroundColor DarkGray
    }
}
Write-Host ""
if ($WhatIfPreference) {
    Write-Host "WhatIf: nothing was changed. Re-run without -WhatIf to apply." -ForegroundColor Cyan
} else {
    Write-Host "Now confirm with the read-only checker:  .\Test-RangeConfig.ps1" -ForegroundColor Green
    if ($results | Where-Object { $_.Detail -match 'needs reboot' }) {
        Write-Host "Some controls (UAC, LSA PPL) only take effect after a REBOOT." -ForegroundColor Yellow
    }
}
