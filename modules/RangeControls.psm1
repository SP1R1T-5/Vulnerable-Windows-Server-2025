#requires -Version 5.1
<#
    THE CONTROL TABLE -- one declarative source of truth for every intentional
    misconfiguration the range applies.

    WHY THIS EXISTS
    ---------------------------------------------------------------------------
    Each control used to be written out four times: the category script applied
    it, Test-RangeConfig checked it, its -Repair pass re-tested AND re-fixed
    it, and Reset-CyberRange reverted it. Twenty-six registry value names lived
    in all three of apply/test/repair verbatim. Nothing kept them in agreement,
    so a control could be applied one way and checked another -- and a comment
    had to be written to explain which copy won.

    Now there is one entry per control, and four thin verbs over it:

        Set-RangeControl     apply   (used by Setup-CyberRange.ps1)
        Test-RangeControl    check   (used by Test-RangeConfig.ps1)
        Repair               = Test -> Set -> Test (Test-RangeConfig.ps1 -Repair)
        Reset-RangeControl   revert  (used by Reset-CyberRange.ps1)

    Adding a control is ONE entry here, not four edits across four files.

    DELIBERATELY STANDALONE. Like the checker, this module must load on a
    half-built or damaged box, so it has no hard dependency on RangeCommon.psm1.
    When RangeCommon IS loaded, Set-RangeControl routes writes through
    Set-RegValue so the change manifest (the instructor answer key) still gets
    every entry.

    SCHEMA (see the New-* helpers below)
      Id         stable key, 'category.thing'
      Category   matches the apply script's $cat and the checker's section
      Name       human label, shown in every report
      Control    NIST SP 800-53 Rev.5 / CIS / CVE mapping for the scoring baseline
      Applies    All | DC | NonDC        -- host-role gate
      Requires   dotted config path, e.g. 'Categories.SmbNetwork' -- config gate
      Probe      reg | live              -- is this a declaration or the running state
      Why        the teaching/safety note that used to live as a code comment
      Note       annotation that downgrades a MATCHED value to WARN
                 (reboot pending, or a known no-op on Server 2025)
      NotRepairable  reason string; Repair reports N-A instead of trying

    Registry controls carry Path/ValueName/Type/Value plus a revert intent.
    Anything that is not a simple registry compare carries its own Test/Apply/
    Revert scriptblocks instead. Both kinds go through the same three verbs.
#>

$script:REVERT_NONE   = '@@no-revert@@'
$script:REVERT_REMOVE = '@@remove@@'

# ── low-level registry access (non-throwing; see Test-RangeConfig's note) ──
function Get-ControlRegValue {
    <# Probe rather than throw: Get-ItemProperty fills $Error with one record per
       missing key, which on an unbuilt host is ~100 entries of pure noise that
       looks like the tool is broken. #>
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return $null }
    if ($item.GetValueNames() -notcontains $Name) { return $null }
    return $item.GetValue($Name)
}

function Set-ControlRegValue {
    <# Routes through RangeCommon's Set-RegValue when it is loaded, so the applied
       change lands in the manifest. Falls back to a plain write when this module
       is used standalone (checker / repair / teardown on a damaged box). #>
    param([string]$Path, [string]$Name, [string]$Type, $Value, [string]$Category)
    $viaCommon = Get-Command Set-RegValue -ErrorAction SilentlyContinue
    if ($viaCommon) { Set-RegValue $Path $Name $Type $Value $Category; return }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction Stop | Out-Null
}

function Remove-ControlRegValue {
    param([string]$Path, [string]$Name)
    if (Test-Path -LiteralPath $Path) { Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue }
}

function Test-ControlValueMatch {
    <# String-compares scalars (so 4 and '4' agree, as the old checker did) and
       set-compares MultiString: every expected member must be present. #>
    param($Actual, $Expected)
    if ($null -eq $Actual) { return $false }
    if ($Expected -is [array]) {
        $have = @($Actual)
        return (@($Expected | Where-Object { $have -notcontains $_ }).Count -eq 0)
    }
    return ("$Actual" -eq "$Expected")
}

# ── table-building helpers ────────────────────────────────────────────────
function New-RegControl {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [string]$Control,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ValueName,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)]$Value,
        $RevertValue = $script:REVERT_NONE,
        [string]$RevertType,
        [switch]$RevertRemove,
        [string]$RevertNote,
        [string]$Note,
        [string]$Why,
        [ValidateSet('All','DC','NonDC')][string]$Applies = 'All',
        [string]$Requires,
        [string]$NotRepairable,
        [string[]]$Technique
    )
    [pscustomobject]@{
        Kind = 'Registry'; Id = $Id; Category = $Category; Name = $Name; Control = $Control
        Probe = 'reg'; Applies = $Applies; Requires = $Requires; Why = $Why; Note = $Note
        NotRepairable = $NotRepairable; Technique = $Technique
        Path = $Path; ValueName = $ValueName; Type = $Type; Value = $Value
        RevertValue = $(if ($RevertRemove) { $script:REVERT_REMOVE } else { $RevertValue })
        RevertType  = $(if ($RevertType) { $RevertType } else { $Type })
        RevertNote  = $RevertNote
        Test = $null; Apply = $null; Revert = $null
    }
}

function New-CustomControl {
    <# For anything that is not a plain registry compare: bitmask tests, live
       subsystem probes, absence-of-a-value checks. Test returns a hashtable
       @{ State = 'PASS'|'FAIL'|'WARN'|'N-A'; Detail = '...' }. Apply and Revert
       are optional -- a control with no Apply is check-only, and Repair reports
       it as N-A with the NotRepairable reason. #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [string]$Control,
        [Parameter(Mandatory)][scriptblock]$Test,
        [scriptblock]$Apply,
        [scriptblock]$Revert,
        [scriptblock]$RevertNeeded,
        [string]$RevertNote,
        [string]$Intended,
        [ValidateSet('reg','live')][string]$Probe = 'live',
        [ValidateSet('All','DC','NonDC')][string]$Applies = 'All',
        [string]$Requires,
        [string]$Why,
        [string]$NotRepairable,
        [string[]]$Technique
    )
    [pscustomobject]@{
        Kind = 'Custom'; Id = $Id; Category = $Category; Name = $Name; Control = $Control
        Probe = $Probe; Applies = $Applies; Requires = $Requires; Why = $Why; Note = $null
        NotRepairable = $NotRepairable; Technique = $Technique
        Path = $null; ValueName = $null; Type = $null; Value = $null
        RevertValue = $script:REVERT_NONE; RevertType = $null; RevertNote = $RevertNote
        Test = $Test; Apply = $Apply; Revert = $Revert; RevertNeeded = $RevertNeeded
        Intended = $Intended
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  THE TABLE  --  one function per category, concatenated by
#  Get-RangeControlTable at the bottom of this file.
# ══════════════════════════════════════════════════════════════════════════

# Well-known keys, shared by the category functions below.
$script:K = @{
    Lsa   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Msv   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    WDig  = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    Winlg = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Sys   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Srv   = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    Wks   = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    PsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    Rdp   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    Pnp   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    DevG  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    Def   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    Kerb  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    Audit = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
}

# ── MITRE ATT&CK technique mapping (WP15) ─────────────────────────────────
#  Keyed by control Id; wildcards allowed, FIRST MATCH WINS, so put specific
#  patterns above general ones. Applied by Get-RangeControlTable to any control
#  that did not declare -Technique inline.
#
#  DELIBERATELY INCOMPLETE. A control with no defensible technique is left
#  BLANK rather than mapped to something approximate -- students quote these
#  back, and a wrong technique ID is worse than an absent one. Notable blanks:
#  the Windows Update controls (a hardening finding, not an adversary
#  behaviour), SNMP community strings, and the persistence payload files
#  (the file is not the technique; the autostart that runs it is).
#
#  To add a mapping: put it here, not on the call site -- keeping them in one
#  block is what makes the coverage report reviewable.
$script:TechniqueMap = [ordered]@{
    # ── Impair defenses ──
    'def.*'                   = @('T1562.001')   # Disable or Modify Tools
    'log.live.Sysmon*'        = @('T1562.001')
    'fw.*'                    = @('T1562.004')   # Disable or Modify System Firewall
    'log.ps.*'                = @('T1562.002')   # Disable Windows Event Logging
    'log.cmdline4688'         = @('T1562.002')
    'log.eventlogservice'     = @('T1562.002')
    'log.size.*'              = @('T1070.001')   # Clear Windows Event Logs (shrink -> rollover)
    'log.live.size.*'         = @('T1070.001')
    'log.live.*'              = @('T1562.001')

    # ── Credential access ──
    'cred.wdigest.*'          = @('T1003.001')   # LSASS Memory
    'lsa.runasppl*'           = @('T1003.001')
    'lsa.live.dumpable'       = @('T1003.001')
    'vbs.lsacfgflags'         = @('T1003.001')
    'vbs.dg.lsacfgflags'      = @('T1003.001')
    'vbs.scenario.credguard'  = @('T1003.001')
    'vbs.enablevbs'           = @('T1003.001')
    'cred.nolmhash'           = @('T1003.002')   # Security Account Manager
    'cred.cachedlogons'       = @('T1003.005')   # Cached Domain Credentials
    'cred.kerberos.etypes'    = @('T1558.003')   # Kerberoasting (RC4 downgrade)
    'cred.lmcompat'           = @('T1562.010')   # Downgrade Attack
    'smb.ntlmmin.*'           = @('T1562.010')
    'cred.autologon.password' = @('T1552.002')   # Credentials in Registry
    'cred.anon.*'             = @('T1087')       # Account Discovery

    # ── Privilege escalation / lateral movement ──
    'uac.enablelua'           = @('T1548.002')   # Bypass User Account Control
    'uac.consent*'            = @('T1548.002')
    'uac.securedesktop'       = @('T1548.002')
    'uac.tokenfilter'         = @('T1550.002')   # Pass the Hash
    'smb.srv.smb1'            = @('T1210')       # Exploitation of Remote Services
    'smb.live.smb1'           = @('T1210')
    'smb.srv.enable'          = @('T1557.001')   # LLMNR/NBT-NS Poisoning and SMB Relay
    'smb.srv.require'         = @('T1557.001')
    'smb.wks.*'               = @('T1557.001')
    'smb.live.*signing'       = @('T1557.001')
    'smb.nullsess.*'          = @('T1135')       # Network Share Discovery
    'share.*'                 = @('T1135')
    'rdp.*'                   = @('T1021.001')   # Remote Desktop Protocol
    'winrm.*'                 = @('T1021.006')   # Windows Remote Management
    'ps.*execpolicy'          = @('T1059.001')   # PowerShell
    'legacy.live.psv2'        = @('T1059.001')
    'legacy.live.tftp'        = @('T1105')       # Ingress Tool Transfer

    # ── CVE reproductions ──
    'cve.spooler'             = @('T1068')       # Exploitation for Privilege Escalation
    'cve.pnp.*'               = @('T1068')
    'cve.hive.*'              = @('T1003.002')   # HiveNightmare -> SAM
    'cve.vss.shadow'          = @('T1003.002')

    # ── Persistence ──
    'persist.runkey'          = @('T1547.001')   # Registry Run Keys / Startup Folder
    'persist.startupfolder'   = @('T1547.001')
    'persist.winlogonshell'   = @('T1547.004')   # Winlogon Helper DLL
    'persist.service'         = @('T1543.003')   # Windows Service
    'persist.task.*'          = @('T1053.005')   # Scheduled Task
    'persist.ifeo.*'          = @('T1546.012')   # IFEO Injection
    'persist.beacon*'         = @('T1095')       # Non-Application Layer Protocol
}

function Resolve-ControlTechnique {
    <# First-match-wins lookup of $script:TechniqueMap. Returns $null when the
       control has no defensible mapping -- that is a valid, intended answer. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Id)
    foreach ($pattern in $script:TechniqueMap.Keys) {
        if ($Id -like $pattern) { return $script:TechniqueMap[$pattern] }
    }
    return $null
}

# ══ updates + Defender ════════════════════════════════════════════════════
function Get-UpdatesDefenderControls {
    $t = New-Object System.Collections.Generic.List[object]
    $cat    = 'updates-defender'
    $ctl    = 'NIST SI-2, CM-3; CIS 7.3'
    $ctlDef = 'NIST SI-3; CIS 10.1'
    $Def    = $script:K.Def

    # wuauserv defaults to Manual (3); the other two to Automatic (2).
    foreach ($svc in @(
        @{ N='wuauserv';     L='Windows Update (wuauserv)';    Back=3 },
        @{ N='WaaSMedicSvc'; L='Update Medic (WaaSMedicSvc)';  Back=2 },
        @{ N='UsoSvc';       L='Update Orchestrator (UsoSvc)'; Back=2 }
    )) {
        $sn = $svc.N
        $t.Add((New-RegControl -Id "upd.svc.$sn" -Category $cat -Name "$($svc.L) disabled" -Control $ctl `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$sn" -ValueName 'Start' -Type DWord -Value 4 `
            -RevertValue $svc.Back -RevertNote "Start=$($svc.Back) (service restored)" `
            -Why 'Freezes patch level so the red-team CVEs stay reachable. sc.exe config is often denied on these protected services, so the Start value is written directly. WaaSMedicSvc exists to undo exactly this, which is why it is disabled too.'))
        $t.Add((New-CustomControl -Id "upd.svclive.$sn" -Category $cat -Name "[live] $sn disabled + stopped" -Control $ctl `
            -Test {
                $s = Get-Service $sn -ErrorAction SilentlyContinue
                if (-not $s) { return @{ State='WARN'; Detail='service not found' } }
                if ($s.StartType -eq 'Disabled' -and $s.Status -ne 'Running') { return @{ State='PASS'; Detail="$($s.StartType)/$($s.Status)" } }
                if ($s.StartType -eq 'Disabled') { return @{ State='WARN'; Detail="$($s.StartType) but still $($s.Status) -- reboot to settle" } }
                return @{ State='FAIL'; Detail="StartType=$($s.StartType) -- registry set but service re-enabled" }
            }.GetNewClosure() `
            -Apply { Stop-Service $sn -Force -ErrorAction SilentlyContinue }.GetNewClosure() `
            -Intended 'disabled + stopped' `
            -Why 'The registry Start value is only a DECLARATION. F35: any servicing operation (Install-WindowsFeature, Add-WindowsCapability, DISM) re-enables wuauserv behind the build, so the live state must be checked separately.'))
    }

    $t.Add((New-RegControl -Id 'upd.noautoupdate' -Category $cat -Name 'NoAutoUpdate policy' -Control $ctl `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'NoAutoUpdate' -Type DWord -Value 1 `
        -RevertRemove -RevertNote 'policy removed'))

    # ── Defender policy registry (belt-and-suspenders behind Set-MpPreference) ──
    $t.Add((New-RegControl -Id 'def.rtp.realtime' -Category $cat -Name 'Defender policy: realtime disabled' -Control $ctlDef `
        -Path "$Def\Real-Time Protection" -ValueName 'DisableRealtimeMonitoring' -Type DWord -Value 1 `
        -RevertValue 0 -RevertNote 'real-time protection policy cleared'))
    $t.Add((New-RegControl -Id 'def.rtp.behavior' -Category $cat -Name 'Defender policy: behavior monitoring off' -Control $ctlDef `
        -Path "$Def\Real-Time Protection" -ValueName 'DisableBehaviorMonitoring' -Type DWord -Value 1 -RevertValue 0))
    $t.Add((New-RegControl -Id 'def.rtp.onaccess' -Category $cat -Name 'Defender policy: on-access protection off' -Control 'NIST SI-3' `
        -Path "$Def\Real-Time Protection" -ValueName 'DisableOnAccessProtection' -Type DWord -Value 1 -RevertValue 0))
    $t.Add((New-RegControl -Id 'def.rtp.scanonenable' -Category $cat -Name 'Defender policy: scan-on-realtime-enable off' -Control 'NIST SI-3' `
        -Path "$Def\Real-Time Protection" -ValueName 'DisableScanOnRealtimeEnable' -Type DWord -Value 1 -RevertValue 0))
    $t.Add((New-RegControl -Id 'def.antispyware' -Category $cat -Name 'Defender DisableAntiSpyware (parity only)' -Control 'NIST SI-3' `
        -Path $Def -ValueName 'DisableAntiSpyware' -Type DWord -Value 1 -RevertValue 0 `
        -Note 'IGNORED since the Aug-2020 platform update -- no effect on 2025' `
        -Why 'Kept so the 2019 lesson plan still maps onto this build, and so nobody re-adds it thinking it was forgotten.'))
    $t.Add((New-RegControl -Id 'def.spynet.reporting' -Category $cat -Name 'Defender SpyNet reporting off' -Control 'NIST SI-3' `
        -Path "$Def\Spynet" -ValueName 'SpyNetReporting' -Type DWord -Value 0 -RevertValue 2))
    $t.Add((New-RegControl -Id 'def.spynet.samples' -Category $cat -Name 'Defender sample submission = never send' -Control 'NIST SI-3' `
        -Path "$Def\Spynet" -ValueName 'SubmitSamplesConsent' -Type DWord -Value 2 -RevertValue 1))
    $t.Add((New-RegControl -Id 'def.asr' -Category $cat -Name 'Defender ASR rules off' -Control 'NIST SI-3; CIS 10.5' `
        -Path "$Def\Windows Defender Exploit Guard\ASR" -ValueName 'ExploitGuard_ASR_Rules' -Type DWord -Value 0 -RevertRemove))
    $t.Add((New-RegControl -Id 'def.tamper' -Category $cat -Name 'Tamper Protection registry toggle' -Control 'NIST SI-3' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -ValueName 'TamperProtection' -Type DWord -Value 0 -RevertValue 5 `
        -Note 'unreliable when cloud/Intune-managed; harmless otherwise'))

    $t.Add((New-CustomControl -Id 'def.live.realtime' -Category $cat -Name '[live] Defender real-time protection off' -Control $ctlDef `
        -Test {
            $mp = $null; try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}
            if (-not $mp) { return @{ State='WARN'; Detail='Get-MpComputerStatus unavailable (feature removed or cmdlet missing)' } }
            if ($mp.RealTimeProtectionEnabled -and $mp.IsTamperProtected) {
                return @{ State='FAIL'; Detail='RealTimeProtectionEnabled=True and Tamper Protection is ON -- every toggle is blocked; use RemoveDefenderFeature = $true' }
            }
            if (-not $mp.RealTimeProtectionEnabled) { return @{ State='PASS'; Detail='RealTimeProtectionEnabled=False' } }
            return @{ State='FAIL'; Detail='RealTimeProtectionEnabled=True -- Tamper Protection, or the Set-MpPreference splat bug (F4), has regressed' }
        } `
        -Apply {
            # F4: MUST splat from a VARIABLE. `Set-MpPreference @{...}` passes the
            # hashtable POSITIONALLY and always throws "A positional parameter
            # cannot be found", which the old catch mislabelled as Tamper
            # Protection -- so every toggle silently failed and Defender stayed on.
            if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) { return }
            $prefs = @{
                DisableRealtimeMonitoring = $true; DisableIOAVProtection     = $true
                DisableScriptScanning     = $true; DisableBehaviorMonitoring = $true
                DisableBlockAtFirstSeen   = $true; MAPSReporting             = 0
                SubmitSamplesConsent      = 2
            }
            foreach ($k in $prefs.Keys) {
                $arg = @{ $k = $prefs[$k] }
                try { Set-MpPreference @arg -ErrorAction Stop } catch {}
            }
            try { Add-MpPreference -ExclusionPath 'C:\','C:\ProgramData\SysTasks' -ErrorAction Stop } catch {}
        } `
        -RevertNeeded {
            $mp = $null; try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}
            [bool]($mp -and -not $mp.RealTimeProtectionEnabled)
        } `
        -Revert {
            if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) { return }
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableScriptScanning     $false -ErrorAction SilentlyContinue
            try { Remove-MpPreference -ExclusionPath 'C:\','C:\ProgramData\SysTasks' -ErrorAction SilentlyContinue } catch {}
        } `
        -RevertNote 'real-time protection re-enabled, range exclusions removed' `
        -Intended 'RealTimeProtectionEnabled=False' `
        -Why 'Set-MpPreference is silently blocked while Tamper Protection is on. On a fresh, non-onboarded lab box TP is usually off; if it is not, RemoveDefenderFeature = $true (uninstall the feature) is the reliable kill.'))

    $t.Add((New-CustomControl -Id 'def.live.tamper' -Category $cat -Name '[live] Tamper Protection state' -Control 'NIST SI-3' `
        -Test {
            $mp = $null; try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}
            if (-not $mp) { return @{ State='N-A'; Detail='Defender status unavailable' } }
            if ($mp.IsTamperProtected) { return @{ State='WARN'; Detail='ON -- registry/Set-MpPreference toggles are blocked; consider RemoveDefenderFeature' } }
            return @{ State='PASS'; Detail='off' }
        } `
        -NotRepairable 'Tamper Protection cannot be turned off programmatically -- disable it in the Defender UI or uninstall the feature'))

    $t.Add((New-CustomControl -Id 'def.live.featureremoved' -Category $cat -Name '[live] Defender feature removed' -Control $ctlDef `
        -Requires 'RemoveDefenderFeature' `
        -Test {
            if (-not (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) { return @{ State='WARN'; Detail='could not query feature' } }
            $f = Get-WindowsFeature -Name Windows-Defender -ErrorAction SilentlyContinue
            if (-not $f) { return @{ State='WARN'; Detail='could not query feature' } }
            if (-not $f.Installed) { return @{ State='PASS'; Detail='Windows-Defender not installed' } }
            return @{ State='FAIL'; Detail='Windows-Defender still installed' }
        } `
        -Apply { Uninstall-WindowsFeature -Name Windows-Defender -ErrorAction Stop | Out-Null } `
        -Intended 'Windows-Defender feature uninstalled (settles on the next reboot)' `
        -NotRepairable 'uninstalling a feature needs a reboot -- re-run the build rather than repairing in place'))
    ,$t
}

# ══ credential exposure ═══════════════════════════════════════════════════
function Get-CredentialExposureControls {
    param([hashtable]$Config)
    $t = New-Object System.Collections.Generic.List[object]
    $cat = 'credential-exposure'
    $Lsa = $script:K.Lsa; $WDig = $script:K.WDig; $Winlg = $script:K.Winlg; $Kerb = $script:K.Kerb

    $t.Add((New-RegControl -Id 'cred.wdigest.uselogon' -Category $cat -Name 'WDigest UseLogonCredential' -Control 'NIST IA-5(1), SC-28' `
        -Path $WDig -ValueName 'UseLogonCredential' -Type DWord -Value 1 -RevertValue 0 `
        -RevertNote 'UseLogonCredential=0' `
        -Why 'Caches plaintext credentials in LSASS -- the classic mimikatz sekurlsa::wdigest target. Still works on Server 2025.'))
    $t.Add((New-RegControl -Id 'cred.wdigest.negotiate' -Category $cat -Name 'WDigest Negotiate' -Control 'NIST IA-5(1)' `
        -Path $WDig -ValueName 'Negotiate' -Type DWord -Value 1 -RevertValue 0))

    $t.Add((New-RegControl -Id 'cred.nolmhash' -Category $cat -Name 'LM hash stored (NoLmHash=0)' -Control 'NIST IA-7, SC-13' `
        -Path $Lsa -ValueName 'NoLmHash' -Type DWord -Value 0 -RevertValue 1 `
        -RevertNote 'NoLmHash=1 (existing hashes clear on password change, not on this write)' `
        -Why 'Stores the crackable LM hash alongside the NT hash.'))
    $t.Add((New-RegControl -Id 'cred.lmcompat' -Category $cat -Name 'LmCompatibilityLevel=0' -Control 'NIST IA-7, SC-13' `
        -Path $Lsa -ValueName 'LmCompatibilityLevel' -Type DWord -Value 0 -RevertValue 5 `
        -RevertNote 'LmCompatibilityLevel=5 (NTLMv2 only)' `
        -Note 'NTLMv1 is removed on Server 2025 -- config finding only, not an exploit (F9)' `
        -Why 'Send LM and NTLMv1 and never refuse them. On 2025 this is a paper finding rather than a live downgrade.'))

    foreach ($n in @(
        @{ V='RestrictAnonymous';    Val=0; Back=1 },
        @{ V='RestrictAnonymousSAM'; Val=0; Back=1 },
        @{ V='EveryoneIncludesAnonymous'; Val=1; Back=0 }
    )) {
        $t.Add((New-RegControl -Id "cred.anon.$($n.V)" -Category $cat -Name "$($n.V)=$($n.Val)" -Control 'NIST AC-3, AC-14' `
            -Path $Lsa -ValueName $n.V -Type DWord -Value $n.Val -RevertValue $n.Back `
            -RevertNote 'anonymous SAM/share enumeration blocked'))
    }

    $t.Add((New-RegControl -Id 'cred.cachedlogons' -Category $cat -Name 'CachedLogonsCount=50' -Control 'NIST AC-3, IA-5' `
        -Path $Winlg -ValueName 'CachedLogonsCount' -Type String -Value '50' -RevertValue '4' -RevertType String `
        -RevertNote 'CachedLogonsCount=4' `
        -Why 'A deep cache of domain credentials for offline cracking (DCC2 / mscash2).'))

    # ── Kerberos encryption types: a bitmask, not an equality test ─────────
    $t.Add((New-CustomControl -Id 'cred.kerberos.etypes' -Category $cat -Probe 'reg' `
        -Name 'Kerberos etypes RC4+AES (0x1C)' -Control 'NIST SC-13' `
        -Test {
            $v = Get-ControlRegValue $script:K.Kerb 'SupportedEncryptionTypes'
            if ($null -eq $v) { return @{ State='FAIL'; Detail='SupportedEncryptionTypes not set' } }
            $i = [int]$v
            if (($i -band 0x4) -and ($i -band 0x18)) { return @{ State='PASS'; Detail="SupportedEncryptionTypes=$v (RC4 for Kerberoast + AES so domain logon works)" } }
            if (($i -band 0x4) -and -not ($i -band 0x18)) { return @{ State='FAIL'; Detail="SupportedEncryptionTypes=$v = RC4-ONLY -- breaks every domain logon on 2025 (F26); must be 28" } }
            return @{ State='WARN'; Detail="SupportedEncryptionTypes=$v (no RC4 bit -- the Kerberoast downgrade is weaker)" }
        } `
        -Apply { Set-ControlRegValue $script:K.Kerb 'SupportedEncryptionTypes' DWord 0x1C 'credential-exposure' } `
        -RevertNeeded {
            $v = Get-ControlRegValue $script:K.Kerb 'SupportedEncryptionTypes'
            [bool]($null -ne $v -and ([int]$v -band 0x4))
        } `
        -Revert { Set-ControlRegValue $script:K.Kerb 'SupportedEncryptionTypes' DWord 0x18 'credential-exposure' } `
        -RevertNote 'AES only (0x18)' `
        -Intended '=28 (RC4 for Kerberoast + AES so domain logon still works)' `
        -Why @'
DO NOT set this to 4. 0x4 is RC4-HMAC *only*, with AES128 (0x8) and AES256 (0x10)
cleared. On a standalone box that is survivable, but this control is re-applied
after DC promotion -- and a domain controller that supports only RC4 cannot
complete Kerberos AS/TGS exchanges on Server 2025, where RC4 is deprecated and
disabled by default. Every domain logon then fails, including Administrator and
the operator account, with no local SAM left to fall back on. That is the "locked
out of everything after the second reboot" failure (F26); it cannot appear before
promotion, because local accounts authenticate over NTLM rather than Kerberos.

0x1C = RC4 (0x4) + AES128 (0x8) + AES256 (0x10). RC4 stays available, so the
Kerberoast downgrade still works -- dc\10 stamps msDS-SupportedEncryptionTypes=4
on the svc_* accounts individually, which forces an RC4 (etype 23, hashcat -m
13100) service ticket for exactly those principals. The weakness is scoped to the
target accounts instead of breaking the whole KDC.
'@))

    # ── Autologon: the cleartext-password artifact, and its lockout guards ──
    $ctlAuto = 'NIST IA-5(1)(c), AC-2'
    $t.Add((New-RegControl -Id 'cred.autologon.enabled' -Category $cat -Name 'AutoAdminLogon=1' -Control $ctlAuto `
        -Path $Winlg -ValueName 'AutoAdminLogon' -Type String -Value '1' -RevertValue '0' -RevertType String `
        -RevertNote 'autologon off'))
    $t.Add((New-CustomControl -Id 'cred.autologon.user' -Category $cat -Probe 'reg' `
        -Name 'DefaultUserName set' -Control $ctlAuto `
        -Test {
            $v = Get-ControlRegValue $script:K.Winlg 'DefaultUserName'
            if ($v) { return @{ State='PASS'; Detail="$v" } }
            return @{ State='FAIL'; Detail='not set' }
        } `
        -NotRepairable 'set by the autologon block in Setup-CyberRange.ps1, which also sets the real account password -- re-run Setup rather than writing the value alone'))
    $t.Add((New-CustomControl -Id 'cred.autologon.password' -Category $cat -Probe 'reg' `
        -Name 'DefaultPassword present (cleartext)' -Control $ctlAuto `
        -Test {
            if ($null -ne (Get-ControlRegValue $script:K.Winlg 'DefaultPassword')) { return @{ State='PASS'; Detail='set in Winlogon' } }
            return @{ State='FAIL'; Detail='not set' }
        } `
        -RevertNeeded { $null -ne (Get-ControlRegValue $script:K.Winlg 'DefaultPassword') } `
        -Revert {
            Remove-ControlRegValue $script:K.Winlg 'DefaultPassword'
            Remove-ControlRegValue $script:K.Winlg 'ForceAutoLogon'
            Set-ControlRegValue $script:K.Winlg 'AutoAdminLogon' String '0' 'credential-exposure'
        } `
        -RevertNote 'cleartext password removed, autologon off' `
        -Why 'The highest-value loot on the box: a readable plaintext password in the registry.' `
        -NotRepairable 'the value must match the real account password -- re-run Setup-CyberRange.ps1'))

    $wantDom = if ($Config -and $Config.DC -and $Config.DC.NetbiosName) { [string]$Config.DC.NetbiosName } else { 'RANGE' }
    # GetNewClosure() snapshots the LOCAL scope into a fresh module scope, where
    # $script:K does not exist -- so the key has to be captured as a local first.
    $winlgKey = $Winlg
    $t.Add((New-CustomControl -Id 'cred.autologon.domain' -Category $cat -Probe 'reg' `
        -Name 'DefaultDomainName correct for role (F1)' -Control $ctlAuto `
        -Test {
            $v = Get-ControlRegValue $winlgKey 'DefaultDomainName'
            if (-not $v) { return @{ State='FAIL'; Detail='absent -- autologon fails after promotion' } }
            $isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
            $want = if ($isDC) { $wantDom } else { '.' }
            if ("$v" -eq "$want") { return @{ State='PASS'; Detail="$v" } }
            return @{ State='WARN'; Detail="=$v but this host expects '$want' -- autologon may fail" }
        }.GetNewClosure() `
        -Apply {
            $isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
            $want = if ($isDC) { $wantDom } else { '.' }
            Set-ControlRegValue $winlgKey 'DefaultDomainName' String $want 'credential-exposure'
        }.GetNewClosure() `
        -Intended "'.' on a standalone host, the NetBIOS domain name on a DC" `
        -Why 'F1: this was never set, so autologon failed after promotion -- Administrator had become a domain principal while DefaultDomainName still said "this machine".'))

    $t.Add((New-CustomControl -Id 'cred.autologon.noforce' -Category $cat -Probe 'reg' `
        -Name 'ForceAutoLogon NOT set (F1)' -Control $ctlAuto `
        -Test {
            $v = Get-ControlRegValue $script:K.Winlg 'ForceAutoLogon'
            if ($null -eq $v -or "$v" -eq '0') { return @{ State='PASS'; Detail='absent or 0 (no autologon loop)' } }
            return @{ State='FAIL'; Detail="ForceAutoLogon=$v -- LOCKOUT RISK" }
        } `
        -Apply { Remove-ControlRegValue $script:K.Winlg 'ForceAutoLogon' } `
        -Intended 'absent' `
        -Why 'F1: with ForceAutoLogon a failed autologon retries forever and never reaches the logon screen. With AutoAdminLogon alone, a wrong password simply drops you at the sign-in prompt. This control asserts the ABSENCE of a value, and the build strips it if an earlier run left it behind.'))
    ,$t
}

# ══ UAC / LSA Protection (PPL) / Credential Guard / VBS ═══════════════════
function Get-UacLsaVbsControls {
    $t = New-Object System.Collections.Generic.List[object]
    $cat = 'uac-lsa-vbs'
    $Sys = $script:K.Sys; $Lsa = $script:K.Lsa; $DevG = $script:K.DevG

    # ── UAC fully disabled + never-notify ─────────────────────────────────
    $t.Add((New-RegControl -Id 'uac.enablelua' -Category $cat -Name 'UAC disabled (EnableLUA=0)' -Control 'NIST AC-6(2), AC-6(9)' `
        -Path $Sys -ValueName 'EnableLUA' -Type DWord -Value 0 -RevertValue 1 `
        -Note 'takes effect after reboot' -RevertNote 'EnableLUA=1 (needs reboot)'))
    $t.Add((New-RegControl -Id 'uac.consentadmin' -Category $cat -Name 'ConsentPromptBehaviorAdmin=0' -Control 'NIST AC-6(9)' `
        -Path $Sys -ValueName 'ConsentPromptBehaviorAdmin' -Type DWord -Value 0 -RevertValue 5))
    $t.Add((New-RegControl -Id 'uac.consentuser' -Category $cat -Name 'ConsentPromptBehaviorUser=0' -Control 'NIST AC-6(9)' `
        -Path $Sys -ValueName 'ConsentPromptBehaviorUser' -Type DWord -Value 0 -RevertValue 3))
    $t.Add((New-RegControl -Id 'uac.securedesktop' -Category $cat -Name 'PromptOnSecureDesktop=0' -Control 'NIST AC-6(9)' `
        -Path $Sys -ValueName 'PromptOnSecureDesktop' -Type DWord -Value 0 -RevertValue 1))
    $t.Add((New-RegControl -Id 'uac.codesigning' -Category $cat -Name 'ValidateAdminCodeSignatures=0' -Control 'NIST SI-7' `
        -Path $Sys -ValueName 'ValidateAdminCodeSignatures' -Type DWord -Value 0 -RevertValue 0))
    $t.Add((New-RegControl -Id 'uac.uiadesktop' -Category $cat -Name 'EnableUIADesktopToggle=1' -Control 'NIST AC-6' `
        -Path $Sys -ValueName 'EnableUIADesktopToggle' -Type DWord -Value 1 -RevertValue 0))
    $t.Add((New-RegControl -Id 'uac.tokenfilter' -Category $cat -Name 'LocalAccountTokenFilterPolicy=1' -Control 'NIST AC-6, AC-17' `
        -Path $Sys -ValueName 'LocalAccountTokenFilterPolicy' -Type DWord -Value 1 -RevertRemove `
        -RevertNote 'remote UAC token filtering restored' `
        -Why 'Remote UAC token filtering off: local admins get a FULL token over the network, which is what makes pass-the-hash to an admin share work.'))

    # ── LSA Protection (PPL) off -> LSASS is dumpable ─────────────────────
    $t.Add((New-RegControl -Id 'lsa.runasppl' -Category $cat -Name 'LSA PPL off (RunAsPPL=0)' -Control 'NIST SC-39, SI-3' `
        -Path $Lsa -ValueName 'RunAsPPL' -Type DWord -Value 0 -RevertValue 1 -RevertNote 'RunAsPPL=1 (needs reboot)'))
    $t.Add((New-RegControl -Id 'lsa.runaspplboot' -Category $cat -Name 'LSA PPL boot off (RunAsPPLBoot=0)' -Control 'NIST SC-39' `
        -Path $Lsa -ValueName 'RunAsPPLBoot' -Type DWord -Value 0 -RevertValue 1))

    # ── Credential Guard / VBS off ────────────────────────────────────────
    $t.Add((New-RegControl -Id 'vbs.lsacfgflags' -Category $cat -Name 'Credential Guard off (LsaCfgFlags=0)' -Control 'NIST IA-2, SC-39' `
        -Path $Lsa -ValueName 'LsaCfgFlags' -Type DWord -Value 0 -RevertValue 1))
    $t.Add((New-RegControl -Id 'vbs.enablevbs' -Category $cat -Name 'VBS off (DeviceGuard)' -Control 'NIST IA-2, SC-39' `
        -Path $DevG -ValueName 'EnableVirtualizationBasedSecurity' -Type DWord -Value 0 -RevertValue 1))
    $t.Add((New-RegControl -Id 'vbs.platformfeatures' -Category $cat -Name 'RequirePlatformSecurityFeatures=0' -Control 'NIST SC-39' `
        -Path $DevG -ValueName 'RequirePlatformSecurityFeatures' -Type DWord -Value 0 -RevertValue 1))
    $t.Add((New-RegControl -Id 'vbs.dg.lsacfgflags' -Category $cat -Name 'DeviceGuard LsaCfgFlags=0' -Control 'NIST IA-2, SC-39' `
        -Path $DevG -ValueName 'LsaCfgFlags' -Type DWord -Value 0 -RevertValue 1))
    $t.Add((New-RegControl -Id 'vbs.scenario.credguard' -Category $cat -Name 'Credential Guard scenario off' -Control 'NIST IA-2, SC-39' `
        -Path "$DevG\Scenarios\CredentialGuard" -ValueName 'Enabled' -Type DWord -Value 0 -RevertValue 1))
    $t.Add((New-RegControl -Id 'vbs.scenario.hvci' -Category $cat -Name 'HVCI off (DeviceGuard scenario)' -Control 'NIST SI-7' `
        -Path "$DevG\Scenarios\HypervisorEnforcedCodeIntegrity" -ValueName 'Enabled' -Type DWord -Value 0 -RevertValue 1))

    # ── [live] the operational truth behind RunAsPPL ──────────────────────
    $t.Add((New-CustomControl -Id 'lsa.live.dumpable' -Category $cat -Name '[live] LSASS dumpable (PPL not enforced)' -Control 'NIST SC-39, SI-3' `
        -Test {
            $open = Test-LsassReadable
            $ev   = Get-LsassPplEvent
            if ($open -eq $true) {
                if ($null -ne $ev) { return @{ State='WARN'; Detail="readable now, but Wininit event 12 says lsass started protected at level $ev -- verify after a clean reboot" } }
                return @{ State='PASS'; Detail='OpenProcess(VM_READ) on lsass succeeded -- credential dumping will work' }
            }
            if ($open -eq $false) {
                $lvl = if ($null -ne $ev) { " (Wininit event 12 reports level $ev)" } else { '' }
                return @{ State='FAIL'; Detail="OpenProcess(VM_READ) on lsass DENIED -- lsass is still protected$lvl. If RunAsPPL=0 and you have rebooted, the UEFI lock needs clearing (see the uac-lsa-vbs notes in this table)" }
            }
            return @{ State='WARN'; Detail='could not probe lsass (run elevated)' }
        } `
        -NotRepairable 'PPL clears on reboot once RunAsPPL=0; if it survives a reboot the feature was enabled with a UEFI lock and the EFI variable must be removed' `
        -Why 'A registry 0 is a DECLARATION. It means nothing if PPL was enabled with a UEFI lock, or if the box has not rebooted since. This opens a real handle to lsass.'))

    $t.Add((New-CustomControl -Id 'vbs.live.running' -Category $cat -Name '[live] Credential Guard / VBS not running' -Control 'NIST IA-2, SC-39' `
        -Test {
            try {
                $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
                $running = @($dg.SecurityServicesRunning)
                if ($running -contains 1) { return @{ State='FAIL'; Detail='SecurityServicesRunning includes 1 (Credential Guard active) -- may need UEFI-lock removal' } }
                if ($dg.VirtualizationBasedSecurityStatus -eq 2) { return @{ State='FAIL'; Detail='VirtualizationBasedSecurityStatus=2 (VBS running)' } }
                return @{ State='PASS'; Detail="CredGuard not running; VBS status=$($dg.VirtualizationBasedSecurityStatus)" }
            } catch { return @{ State='WARN'; Detail='could not query Win32_DeviceGuard' } }
        } `
        -NotRepairable 'clears on reboot with the registry values above; a UEFI lock needs DG_Readiness_Tool -Disable and two reboots'))
    ,$t
}

# ══ SMB + network exposure ════════════════════════════════════════════════
function Get-SmbNetworkControls {
    $t = New-Object System.Collections.Generic.List[object]
    $cat = 'smb-network'
    $Srv = $script:K.Srv; $Wks = $script:K.Wks; $Msv = $script:K.Msv

    $t.Add((New-RegControl -Id 'smb.srv.smb1' -Category $cat -Name 'SMB1 enabled (LanmanServer)' -Control 'NIST CM-7, SC-8; CIS 4.8' `
        -Path $Srv -ValueName 'SMB1' -Type DWord -Value 1 -RevertValue 0 `
        -Why 'SMB1 is not installed by default on 2025 -- the FS-SMB1 optional feature has to go in first (the category script does that).'))

    foreach ($sig in @(
        @{ Id='smb.srv.require'; P=$Srv; V='RequireSecuritySignature'; N='SMB server signing not required'; Ctl='NIST SC-8(1), SC-23' },
        @{ Id='smb.wks.require'; P=$Wks; V='RequireSecuritySignature'; N='SMB client signing not required'; Ctl='NIST SC-8(1)' },
        @{ Id='smb.wks.enable';  P=$Wks; V='EnableSecuritySignature';  N='SMB client signing not offered';  Ctl='NIST SC-8(1)' }
    )) {
        $t.Add((New-RegControl -Id $sig.Id -Category $cat -Name $sig.N -Control $sig.Ctl `
            -Path $sig.P -ValueName $sig.V -Type DWord -Value 0 -RevertValue 1 -RevertNote 'signing required again' `
            -Why 'SMB signing is REQUIRED BY DEFAULT on Server 2025 / Win11 24H2, client and server. Turning it off is therefore a genuine downgrade that re-opens NTLM relay practice.'))
    }

    # smb.srv.enable is role-aware. On a DC the SMB server ALWAYS offers signing --
    # SYSVOL/NETLOGON require it, and the service re-forces EnableSecuritySignature=1
    # no matter what the registry or the Default Domain Controllers Policy says. So
    # on a DC this is N-A (not settable by any supported mechanism), and it is not
    # the relay-relevant toggle anyway -- RequireSecuritySignature (=0) is (F40).
    $t.Add((New-CustomControl -Id 'smb.srv.enable' -Category $cat -Name 'SMB server signing not offered' -Control 'NIST SC-8(1)' -Probe 'reg' `
        -Test {
            $v = Get-ControlRegValue -Path $script:K.Srv -Name 'EnableSecuritySignature'
            if ((Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).DomainRole -ge 4) {
                return @{ State='N-A'; Detail="EnableSecuritySignature=$v -- a DC always OFFERS SMB signing (SYSVOL/NETLOGON require it); not settable by registry or GPO, and relay still works because signing is not REQUIRED (F40)" }
            }
            if ("$v" -eq '0') { return @{ State='PASS'; Detail='EnableSecuritySignature=0' } }
            return @{ State='FAIL'; Detail="EnableSecuritySignature=$v (expected 0)" }
        } `
        -Apply {
            Set-SmbServerConfiguration -EnableSecuritySignature $false -Force -ErrorAction SilentlyContinue
            Set-ControlRegValue $script:K.Srv 'EnableSecuritySignature' DWord 0 'smb-network'
        } `
        -RevertNeeded { (Get-ControlRegValue -Path $script:K.Srv -Name 'EnableSecuritySignature') -ne 1 } `
        -Revert { Set-ControlRegValue $script:K.Srv 'EnableSecuritySignature' DWord 1 'smb-network' } `
        -RevertNote 'signing offered again' -Intended 'EnableSecuritySignature=0 (N-A on a DC)' `
        -Why 'A domain controller re-forces EnableSecuritySignature=1 because SYSVOL/NETLOGON require signing; not suppressible, so N-A on a DC.'))

    $t.Add((New-RegControl -Id 'smb.wks.guest' -Category $cat -Name 'LanmanWorkstation AllowInsecureGuestAuth=1' -Control 'NIST IA-2, AC-3' `
        -Path $Wks -ValueName 'AllowInsecureGuestAuth' -Type DWord -Value 1 -RevertValue 0 `
        -Why 'The SMB client blocks guest/insecure logons by default on 2025, so weak shares are unreachable without this.'))

    $t.Add((New-RegControl -Id 'smb.nullsess.access' -Category $cat -Name 'RestrictNullSessAccess=0' -Control 'NIST AC-3, AC-14' `
        -Path $Srv -ValueName 'RestrictNullSessAccess' -Type DWord -Value 0 -RevertValue 1 -RevertNote 'null session access restricted'))
    $t.Add((New-RegControl -Id 'smb.nullsess.pipes' -Category $cat -Name 'NullSessionPipes seeded' -Control 'NIST AC-3, AC-14' `
        -Path $Srv -ValueName 'NullSessionPipes' -Type MultiString -Value @('samr','lsarpc','netlogon','browser') `
        -RevertValue @() -RevertType MultiString))
    $t.Add((New-RegControl -Id 'smb.nullsess.shares' -Category $cat -Name 'NullSessionShares seeded' -Control 'NIST AC-3, AC-14' `
        -Path $Srv -ValueName 'NullSessionShares' -Type MultiString -Value @('IPC$') `
        -RevertValue @() -RevertType MultiString))

    foreach ($n in 'NtlmMinClientSec','NtlmMinServerSec') {
        $t.Add((New-RegControl -Id "smb.ntlmmin.$n" -Category $cat -Name "$n=0" -Control 'NIST SC-8, SC-13' `
            -Path $Msv -ValueName $n -Type DWord -Value 0 -RevertValue 537395200 `
            -RevertNote 'NTLMv2 + 128-bit session security required'))
    }

    foreach ($p in 'DomainProfile','PrivateProfile','PublicProfile','StandardProfile') {
        $t.Add((New-RegControl -Id "fw.policy.$p" -Category $cat -Name "Firewall policy off: $p" -Control 'NIST SC-7, CM-7; CIS 4.4' `
            -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$p" -ValueName 'EnableFirewall' -Type DWord -Value 0 `
            -RevertRemove -RevertNote 'policy cleared (profile returns to its configured state)'))
    }

    # ── [live] the running SMB stack, not the policy intent ───────────────
    $t.Add((New-CustomControl -Id 'smb.live.smb1' -Category $cat -Name '[live] SMB1 enabled' -Control 'NIST CM-7, SC-8; CIS 4.8' `
        -Test {
            $s = $null; try { $s = Get-SmbServerConfiguration -ErrorAction Stop } catch {}
            if (-not $s) { return @{ State='WARN'; Detail='Get-SmbServerConfiguration failed' } }
            if ($s.EnableSMB1Protocol) { return @{ State='PASS'; Detail='EnableSMB1Protocol=True' } }
            return @{ State='FAIL'; Detail='EnableSMB1Protocol=False (the FS-SMB1 feature may be absent on this build)' }
        } `
        -Apply { Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction Stop } `
        -RevertNeeded { (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol -eq $true } `
        -Revert { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop } `
        -RevertNote 'SMB1 disabled' -Intended 'EnableSMB1Protocol=True'))

    $t.Add((New-CustomControl -Id 'smb.live.srvsigning' -Category $cat -Name '[live] SMB server signing not required' -Control 'NIST SC-8(1), SC-23' `
        -Test {
            $s = $null; try { $s = Get-SmbServerConfiguration -ErrorAction Stop } catch {}
            if (-not $s) { return @{ State='WARN'; Detail='Get-SmbServerConfiguration failed' } }
            if (-not $s.RequireSecuritySignature) { return @{ State='PASS'; Detail='RequireSecuritySignature=False' } }
            return @{ State='FAIL'; Detail='RequireSecuritySignature=True' }
        } `
        -Apply {
            Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -EncryptData $false -Force -ErrorAction SilentlyContinue
            Set-ControlRegValue $script:K.Srv 'RequireSecuritySignature' DWord 0 'smb-network'
            Set-ControlRegValue $script:K.Srv 'EnableSecuritySignature'  DWord 0 'smb-network'
        } `
        -RevertNeeded { (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).RequireSecuritySignature -eq $false } `
        -Revert {
            Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -ErrorAction Stop
            Set-ControlRegValue $script:K.Srv 'RequireSecuritySignature' DWord 1 'smb-network'
            Set-ControlRegValue $script:K.Srv 'EnableSecuritySignature'  DWord 1 'smb-network'
        } `
        -RevertNote 'signing required again' -Intended 'RequireSecuritySignature=False' `
        -Why 'On a DC this is GPO-owned: the local write holds only until the next policy refresh, and dc\60 is what makes it stick by pushing it into the Default Domain Controllers Policy (F33).'))

    $t.Add((New-CustomControl -Id 'smb.live.clientsigning' -Category $cat -Name '[live] SMB client signing not required' -Control 'NIST SC-8(1)' `
        -Test {
            $c = $null; try { $c = Get-SmbClientConfiguration -ErrorAction Stop } catch {}
            if (-not $c) { return @{ State='WARN'; Detail='Get-SmbClientConfiguration failed' } }
            if (-not $c.RequireSecuritySignature) { return @{ State='PASS'; Detail='RequireSecuritySignature=False' } }
            return @{ State='FAIL'; Detail='RequireSecuritySignature=True' }
        } `
        -Apply { Set-SmbClientConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -EnableInsecureGuestLogons $true -Force -ErrorAction Stop } `
        -Intended 'RequireSecuritySignature=False'))

    $t.Add((New-CustomControl -Id 'smb.live.guestlogons' -Category $cat -Name '[live] Insecure guest logons enabled' -Control 'NIST IA-2, AC-3' `
        -Test {
            $c = $null; try { $c = Get-SmbClientConfiguration -ErrorAction Stop } catch {}
            if (-not $c) { return @{ State='WARN'; Detail='Get-SmbClientConfiguration failed' } }
            if ($c.EnableInsecureGuestLogons) { return @{ State='PASS'; Detail='EnableInsecureGuestLogons=True' } }
            return @{ State='WARN'; Detail='EnableInsecureGuestLogons=False' }
        } `
        -Apply { Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force -ErrorAction Stop } `
        -Intended 'EnableInsecureGuestLogons=True'))

    $t.Add((New-CustomControl -Id 'smb.live.encryption' -Category $cat -Name '[live] SMB encryption off' -Control 'NIST SC-8' `
        -Test {
            $s = $null; try { $s = Get-SmbServerConfiguration -ErrorAction Stop } catch {}
            if (-not $s) { return @{ State='WARN'; Detail='Get-SmbServerConfiguration failed' } }
            if (-not $s.EncryptData) { return @{ State='PASS'; Detail='EncryptData=False' } }
            return @{ State='WARN'; Detail='EncryptData=True' }
        } `
        -Apply { Set-SmbServerConfiguration -EncryptData $false -Force -ErrorAction Stop } `
        -Intended 'EncryptData=False'))

    $t.Add((New-CustomControl -Id 'fw.live.alloff' -Category $cat -Name '[live] Windows Firewall off (all profiles)' -Control 'NIST SC-7, CM-7; CIS 4.4' `
        -Test {
            try {
                $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
                $on = @($profiles | Where-Object { $_.Enabled })
                if ($on.Count -eq 0) { return @{ State='PASS'; Detail=('disabled: ' + (($profiles.Name) -join ',')) } }
                return @{ State='FAIL'; Detail=('still ENABLED on: ' + (($on.Name) -join ',')) }
            } catch { return @{ State='WARN'; Detail='Get-NetFirewallProfile failed' } }
        } `
        -Apply { Set-NetFirewallProfile -All -Enabled False -ErrorAction Stop } `
        -RevertNeeded { @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Enabled }).Count -gt 0 } `
        -Revert {
            foreach ($p in 'DomainProfile','PrivateProfile','PublicProfile','StandardProfile') {
                Remove-ControlRegValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$p" 'EnableFirewall'
            }
            # The RDP rule is left ENABLED on purpose so a remote operator is not
            # cut off the moment the profiles come back on.
            Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
            Set-NetFirewallProfile -All -Enabled True -ErrorAction Stop
        } `
        -RevertNote 'all profiles ON (RDP rule kept enabled)' -Intended 'all profiles disabled'))
    ,$t
}

# ══ RDP + WinRM / PowerShell remoting ═════════════════════════════════════
function Get-RdpWinrmControls {
    $t = New-Object System.Collections.Generic.List[object]
    $cat = 'rdp-winrm'
    $Rdp = $script:K.Rdp; $PsPol = $script:K.PsPol

    $t.Add((New-RegControl -Id 'rdp.enabled' -Category $cat -Name 'RDP enabled (fDenyTSConnections=0)' -Control 'NIST AC-17' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ValueName 'fDenyTSConnections' -Type DWord -Value 0 -RevertValue 1))
    $t.Add((New-RegControl -Id 'rdp.nla' -Category $cat -Name 'RDP NLA off (UserAuthentication=0)' -Control 'NIST IA-2, SC-8, AC-17' `
        -Path $Rdp -ValueName 'UserAuthentication' -Type DWord -Value 0 -RevertValue 1 -RevertNote 'NLA required again'))
    $t.Add((New-RegControl -Id 'rdp.securitylayer' -Category $cat -Name 'RDP SecurityLayer=0 (no TLS)' -Control 'NIST SC-8, SC-13' `
        -Path $Rdp -ValueName 'SecurityLayer' -Type DWord -Value 0 -RevertValue 2 -RevertNote 'TLS required again'))
    $t.Add((New-RegControl -Id 'rdp.promptpassword' -Category $cat -Name 'RDP fPromptForPassword=0' -Control 'NIST IA-2' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName 'fPromptForPassword' -Type DWord -Value 0 -RevertValue 1))

    $t.Add((New-RegControl -Id 'ps.execpolicy' -Category $cat -Name 'PowerShell ExecutionPolicy=Unrestricted (policy)' -Control 'NIST CM-7(1), SI-7' `
        -Path $PsPol -ValueName 'ExecutionPolicy' -Type String -Value 'Unrestricted' -RevertRemove `
        -RevertNote 'policy removed; machine scope set back to RemoteSigned'))

    $t.Add((New-CustomControl -Id 'rdp.live.listener' -Category $cat -Name '[live] RDP listener: NLA not required' -Control 'NIST IA-2, AC-17' `
        -Test {
            try {
                $ts = Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'" -ErrorAction Stop
                if ($ts.UserAuthenticationRequired -eq 0) { return @{ State='PASS'; Detail='UserAuthenticationRequired=0' } }
                return @{ State='FAIL'; Detail="UserAuthenticationRequired=$($ts.UserAuthenticationRequired) -- registry set but the listener still requires NLA" }
            } catch { return @{ State='WARN'; Detail='Win32_TSGeneralSetting unavailable (run elevated / check the RDS role state)' } }
        } `
        -NotRepairable 'the listener re-reads UserAuthentication at service restart -- restart TermService or reboot'))

    $t.Add((New-CustomControl -Id 'rdp.live.seclayer' -Category $cat -Name '[live] RDP listener: security layer = RDP' -Control 'NIST SC-8' `
        -Test {
            try {
                $ts = Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'" -ErrorAction Stop
                if ($ts.SecurityLayer -eq 0) { return @{ State='PASS'; Detail='SecurityLayer=0' } }
                return @{ State='WARN'; Detail="SecurityLayer=$($ts.SecurityLayer)" }
            } catch { return @{ State='WARN'; Detail='Win32_TSGeneralSetting unavailable' } }
        } `
        -NotRepairable 'settles when the RDP listener restarts'))

    $t.Add((New-CustomControl -Id 'rdp.live.listening' -Category $cat -Name '[live] RDP listening on 3389' -Control 'NIST AC-17' `
        -Test {
            try {
                $l = Get-NetTCPConnection -State Listen -LocalPort 3389 -ErrorAction Stop
                if ($l) { return @{ State='PASS'; Detail='listener present' } }
                return @{ State='WARN'; Detail='no listener on 3389' }
            } catch { return @{ State='WARN'; Detail='no listener on 3389' } }
        } `
        -NotRepairable 'follows from fDenyTSConnections and the TermService state'))

    # ── WinRM: read the RUNNING service config, not the policy intent ─────
    $ctlWinrm = 'NIST SC-8, IA-5, AC-17(2)'
    foreach ($i in @(
        @{ Id='winrm.svc.unencrypted'; P='WSMan:\localhost\Service\AllowUnencrypted'; N='WinRM AllowUnencrypted' },
        @{ Id='winrm.svc.basic';       P='WSMan:\localhost\Service\Auth\Basic';       N='WinRM Basic auth' },
        @{ Id='winrm.svc.credssp';     P='WSMan:\localhost\Service\Auth\CredSSP';     N='WinRM CredSSP (service)' },
        @{ Id='winrm.client.unencrypted'; P='WSMan:\localhost\Client\AllowUnencrypted'; N='WinRM client unencrypted' }
    )) {
        $wp = $i.P
        $t.Add((New-CustomControl -Id $i.Id -Category $cat -Name ("[live] " + $i.N) -Control $ctlWinrm `
            -Test {
                try {
                    $v = (Get-Item $wp -ErrorAction Stop).Value
                    if ("$v" -eq 'true') { return @{ State='PASS'; Detail="$v" } }
                    return @{ State='FAIL'; Detail="=$v (expected true)" }
                } catch { return @{ State='WARN'; Detail='WSMan provider unavailable (WinRM not configured?)' } }
            }.GetNewClosure() `
            -Apply { Set-Item $wp $true -Force -ErrorAction Stop }.GetNewClosure() `
            -RevertNeeded { "$((Get-Item $wp -ErrorAction SilentlyContinue).Value)" -eq 'true' }.GetNewClosure() `
            -Revert { Set-Item $wp $false -Force -ErrorAction SilentlyContinue }.GetNewClosure() `
            -RevertNote 'encryption required / weak auth off' -Intended 'true'))
    }

    $t.Add((New-CustomControl -Id 'winrm.trustedhosts' -Category $cat -Name '[live] WinRM TrustedHosts = *' -Control $ctlWinrm `
        -Test {
            try {
                $th = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value
                if ("$th" -eq '*') { return @{ State='PASS'; Detail='*' } }
                if ($th) { return @{ State='WARN'; Detail="=$th (not wildcard)" } }
                return @{ State='FAIL'; Detail='empty' }
            } catch { return @{ State='WARN'; Detail='WSMan provider unavailable' } }
        } `
        -Apply { Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force -ErrorAction Stop } `
        -RevertNeeded { "$((Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value)" -eq '*' } `
        -Revert { Set-Item WSMan:\localhost\Client\TrustedHosts -Value '' -Force -ErrorAction SilentlyContinue } `
        -RevertNote 'TrustedHosts cleared' -Intended '*'))

    $t.Add((New-CustomControl -Id 'ps.live.execpolicy' -Category $cat -Name '[live] Effective execution policy' -Control 'NIST CM-7(1), SI-7' `
        -Test {
            try {
                $eff = Get-ExecutionPolicy
                if ($eff -in @('Unrestricted','Bypass')) { return @{ State='PASS'; Detail="$eff" } }
                return @{ State='FAIL'; Detail="$eff -- policy value set but not effective" }
            } catch { return @{ State='WARN'; Detail='Get-ExecutionPolicy failed' } }
        } `
        -Apply { Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force -ErrorAction Stop } `
        -RevertNeeded { (Get-ExecutionPolicy) -in @('Unrestricted','Bypass') } `
        -Revert { Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction SilentlyContinue } `
        -RevertNote 'RemoteSigned' -Intended 'Unrestricted'))
    ,$t
}

# ══ logging / blue-team visibility ════════════════════════════════════════
function Get-LoggingVisibilityControls {
    param([hashtable]$Config)
    $t = New-Object System.Collections.Generic.List[object]
    $cat = 'logging-visibility'
    $PsPol = $script:K.PsPol
    $ctlLog = 'NIST AU-2, AU-3, AU-12; CIS 8.2, 8.5'

    $t.Add((New-RegControl -Id 'log.ps.scriptblock' -Category $cat -Name 'ScriptBlockLogging off' -Control $ctlLog `
        -Path "$PsPol\ScriptBlockLogging" -ValueName 'EnableScriptBlockLogging' -Type DWord -Value 0 -RevertValue 1 `
        -RevertNote 'script-block logging on'))
    $t.Add((New-RegControl -Id 'log.ps.module' -Category $cat -Name 'ModuleLogging off' -Control $ctlLog `
        -Path "$PsPol\ModuleLogging" -ValueName 'EnableModuleLogging' -Type DWord -Value 0 -RevertValue 1))
    $t.Add((New-RegControl -Id 'log.ps.transcription' -Category $cat -Name 'Transcription off' -Control $ctlLog `
        -Path "$PsPol\Transcription" -ValueName 'EnableTranscripting' -Type DWord -Value 0 -RevertValue 1))
    $t.Add((New-RegControl -Id 'log.cmdline4688' -Category $cat -Name 'Cmdline in 4688 off' -Control 'NIST AU-3(1)' `
        -Path $script:K.Audit -ValueName 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 0 -RevertValue 1 `
        -Why 'Without the command line in event 4688, process-creation telemetry stops being useful for hunting.'))

    foreach ($ch in 'Security','System') {
        $t.Add((New-RegControl -Id "log.size.$ch" -Category $cat -Name "$ch log shrunk (MaxSize=1MB)" -Control 'NIST AU-4, AU-11; CIS 8.3' `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$ch" -ValueName 'MaxSize' -Type DWord -Value 1048576 `
            -RevertValue 201326592 -RevertNote 'restored to 192 MB'))
    }

    # ── [live] channel size is the truth; the legacy key is not authoritative ──
    foreach ($ch in 'Security','System') {
        $chan = $ch
        $t.Add((New-CustomControl -Id "log.live.size.$chan" -Category $cat -Name "[live] $chan channel max size" -Control 'NIST AU-4, AU-11; CIS 8.3' `
            -Test {
                try {
                    $li = Get-WinEvent -ListLog $chan -ErrorAction Stop | Where-Object { $_.LogName -eq $chan } | Select-Object -First 1
                    # The intent is "small enough that evidence rolls over fast", not
                    # an exact byte count. Windows rounds a requested size up when it
                    # commits: the field run asked for 1048576 and the System channel
                    # came back 1052672, exactly one 4096-byte page over, which a
                    # strict -le test called a FAIL even though the setting applied.
                    # Allow 64KB of allocation granularity; that still fails the
                    # 20 MB DC default by a wide margin.
                    if ($li.MaximumSizeInBytes -le (1048576 + 65536)) {
                        return @{ State='PASS'; Detail="$($li.MaximumSizeInBytes) bytes (target 1048576 + rounding)" }
                    }
                    # F38 -- ACCEPTED DEVIATION, reported N-A rather than FAIL.
                    # This is a log SIZE. It gates no attack path; its only role is to
                    # make evidence roll over quickly. On this Server 2025 DC it
                    # resisted every supported mechanism: the legacy Services\EventLog
                    # key (not authoritative), the WINEVT channel config (written, not
                    # reloaded without a service restart), `wevtutil sl` (denied on
                    # Security, which needs SeSecurityPrivilege), the EventLog
                    # administrative-template policy key (KB-denominated, produced
                    # 1 GB) and the security template's [Security Log] section
                    # (MB-denominated, also 1 GB). Kept as a row -- not deleted -- so
                    # the control stays in the scoring baseline and nobody re-opens it
                    # from scratch.
                    return @{ State='N-A'; Detail="$($li.MaximumSizeInBytes) bytes -- accepted deviation (F38): not settable by any supported mechanism on this host; gates no attack path" }
                } catch { return @{ State='WARN'; Detail='Get-WinEvent -ListLog failed' } }
            }.GetNewClosure() `
            -Apply {
                # Three locations, because the obvious one is not authoritative.
                # Services\EventLog\<ch>\MaxSize is the LEGACY value: writing only
                # that made the registry check pass while the live channel stayed at
                # the 20 MB DC default. The channel's real config lives under
                # WINEVT\Channels, which is what wevtutil writes and what
                # Get-WinEvent -ListLog reports.
                Set-ControlRegValue "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$chan" 'MaxSize' DWord 1048576 'logging-visibility'
                Set-ControlRegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$chan" 'MaxSize' DWord 1048576 'logging-visibility'
                $out = & "$env:SystemRoot\System32\wevtutil.exe" sl $chan /ms:1048576 2>&1
                if ($LASTEXITCODE -ne 0) {
                    Write-Verbose ("wevtutil sl $chan failed (exit $LASTEXITCODE): " + (($out | Select-Object -First 1) -join ' '))
                }
            }.GetNewClosure() `
            -RevertNeeded {
                $v = Get-ControlRegValue "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$chan" 'MaxSize'
                [bool]($v -and [int]$v -le 1114112)
            }.GetNewClosure() `
            -Revert {
                Set-ControlRegValue "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$chan" 'MaxSize' DWord 201326592 'logging-visibility'
                Set-ControlRegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$chan" 'MaxSize' DWord 201326592 'logging-visibility'
                & "$env:SystemRoot\System32\wevtutil.exe" sl $chan /ms:201326592 2>&1 | Out-Null
            }.GetNewClosure() `
            -RevertNote 'restored to 192 MB' `
            -Intended 'MaximumSizeInBytes <= 1048576 (+64KB rounding)'))
    }

    foreach ($sm in 'Sysmon','Sysmon64') {
        $svc = $sm
        $t.Add((New-CustomControl -Id "log.live.$svc" -Category $cat -Name "[live] $svc neutralized" -Control 'NIST SI-4; CIS 8.5' `
            -Test {
                $s = Get-Service $svc -ErrorAction SilentlyContinue
                if (-not $s) { return @{ State='N-A'; Detail='Sysmon not installed on this host' } }
                if ($s.StartType -eq 'Disabled' -or $s.Status -ne 'Running') { return @{ State='PASS'; Detail="$($s.StartType)/$($s.Status)" } }
                return @{ State='FAIL'; Detail='running' }
            }.GetNewClosure() `
            -Apply {
                if (-not (Get-Service $svc -ErrorAction SilentlyContinue)) { return }
                Set-ControlRegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" 'Start' DWord 4 'logging-visibility'
                Stop-Service $svc -Force -ErrorAction SilentlyContinue
            }.GetNewClosure() `
            -Intended 'disabled + stopped' `
            -Why 'Only meaningful if the blue team deployed Sysmon; on a stock image this is N-A.'))
    }

    # DANGEROUS and off by default: killing the EventLog service can stop 2025
    # booting cleanly. Gated on the config toggle, and there is no revert entry
    # because teardown restores the service in its own defenses pass.
    $t.Add((New-RegControl -Id 'log.eventlogservice' -Category $cat -Name 'EventLog service disabled' -Control 'NIST AU-2, AU-12' `
        -Requires 'DisableEventLogService' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog' -ValueName 'Start' -Type DWord -Value 4 `
        -RevertValue 2 -RevertNote 'EventLog service restored to Automatic' `
        -Why 'Prefer shrinking and rolling the logs over killing the service. This exists because the 2019 baseline had it; it is left OFF by default for a reason.'))
    ,$t
}

# ══ legacy / vulnerable services + shares ═════════════════════════════════
function Get-LegacyServicesControls {
    $t = New-Object System.Collections.Generic.List[object]
    $cat = 'legacy-services'

    $t.Add((New-RegControl -Id 'snmp.community' -Category $cat -Name "SNMP community 'public'" -Control 'NIST IA-5; CIS 4.8' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities' -ValueName 'public' -Type DWord -Value 4 `
        -RevertRemove -RevertNote 'community string removed' `
        -Why '4 = READ ONLY. The default community string is the classic SNMP recon finding.'))
    $t.Add((New-RegControl -Id 'snmp.managers' -Category $cat -Name 'SNMP PermittedManagers = any' -Control 'NIST AC-3; CIS 4.8' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers' -ValueName '1' -Type String -Value '0.0.0.0' `
        -RevertRemove))

    $t.Add((New-CustomControl -Id 'snmp.live.service' -Category $cat -Name '[live] SNMP service present' -Control 'NIST IA-5, CM-7; CIS 4.8' `
        -Test {
            $s = Get-Service SNMP -ErrorAction SilentlyContinue
            if ($s) { return @{ State='PASS'; Detail="$($s.Status)" } }
            return @{ State='WARN'; Detail='not installed -- SNMP is a Feature-on-Demand and needs Windows Update, which the build disables first (F13)' }
        } `
        -Apply {
            $ok = $false
            try {
                $cap = Get-WindowsCapability -Online -Name 'SNMP.Server*' -ErrorAction Stop | Select-Object -First 1
                if ($cap -and $cap.State -ne 'Installed') { Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop | Out-Null }
                $ok = $true
            } catch {
                try { Install-WindowsFeature SNMP-Service -IncludeManagementTools -ErrorAction Stop | Out-Null; $ok = $true } catch {}
            }
            if ($ok) {
                Set-Service SNMP -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service SNMP -ErrorAction SilentlyContinue
            }
        } `
        -RevertNeeded { [bool](Get-Service SNMP -ErrorAction SilentlyContinue) } `
        -Revert { Stop-Service SNMP -Force -ErrorAction SilentlyContinue; Set-Service SNMP -StartupType Disabled -ErrorAction SilentlyContinue } `
        -RevertNote 'SNMP stopped and disabled' -Intended 'SNMP installed and running'))

    $t.Add((New-CustomControl -Id 'legacy.live.psv2' -Category $cat -Name '[live] PowerShell v2 engine enabled' -Control 'NIST CM-7, AU-12; CIS 4.8' `
        -Test {
            try {
                $v2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
                if ($v2.State -eq 'Enabled') { return @{ State='PASS'; Detail='MicrosoftWindowsPowerShellV2Root=Enabled' } }
                if ($v2.State -eq 'DisabledWithPayloadRemoved') { return @{ State='N-A'; Detail='payload removed on Server 2025 -- cannot be enabled without Windows Update, which the build disables (F13)' } }
                # An EMPTY State is not a build failure: on Server 2025 the DISM
                # query can return the object without resolving State (payload
                # absent / servicing stack busy). The field run showed literally
                # "State=". Reporting FAIL there blamed the build for something it
                # never did -- treat unknown as unknown.
                if ([string]::IsNullOrWhiteSpace([string]$v2.State)) { return @{ State='N-A'; Detail='DISM returned no State -- payload almost certainly absent; not verifiable offline (F13)' } }
                return @{ State='FAIL'; Detail="State=$($v2.State)" }
            } catch { return @{ State='N-A'; Detail='optional feature not present on this build' } }
        } `
        -Apply { Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop | Out-Null } `
        -Intended 'MicrosoftWindowsPowerShellV2Root=Enabled' `
        -NotRepairable 'payload removed on Server 2025; enabling needs a Windows Update/ISO source, which the build disables (F13)'))

    $t.Add((New-CustomControl -Id 'legacy.live.tftp' -Category $cat -Name '[live] TFTP client installed' -Control 'NIST CM-7; CIS 4.8' `
        -Test {
            if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
                $f = Get-WindowsFeature -Name TFTP-Client -ErrorAction SilentlyContinue
                if ($f) {
                    if ($f.Installed) { return @{ State='PASS'; Detail='TFTP-Client installed' } }
                    return @{ State='FAIL'; Detail='TFTP-Client not installed' }
                }
            }
            if (Test-Path "$env:SystemRoot\System32\tftp.exe") { return @{ State='PASS'; Detail='tftp.exe present' } }
            return @{ State='WARN'; Detail='could not determine' }
        } `
        -Apply { Install-WindowsFeature TFTP-Client -ErrorAction Stop | Out-Null } `
        -RevertNeeded { [bool]((Get-WindowsFeature -Name TFTP-Client -ErrorAction SilentlyContinue).Installed) } `
        -Revert { Uninstall-WindowsFeature TFTP-Client -ErrorAction SilentlyContinue | Out-Null } `
        -RevertNote 'TFTP-Client removed' -Intended 'TFTP-Client installed'))

    foreach ($sh in 'Public','SYSVOL$') {
        $name = $sh
        $t.Add((New-CustomControl -Id "share.$name" -Category $cat -Name "[live] Share '$name' present + Everyone:Full" -Control 'NIST AC-3, AC-6; CIS 3.3' `
            -Test {
                $share = Get-SmbShare -Name $name -ErrorAction SilentlyContinue
                if (-not $share) { return @{ State='FAIL'; Detail='missing' } }
                try {
                    $acc = @(Get-SmbShareAccess -Name $name -ErrorAction Stop | Where-Object { $_.AccountName -match 'Everyone' -and $_.AccessRight -eq 'Full' })
                    if ($acc.Count) { return @{ State='PASS'; Detail="$($share.Path) -- Everyone has Full" } }
                    return @{ State='FAIL'; Detail="$($share.Path) -- Everyone:Full not granted" }
                } catch { return @{ State='WARN'; Detail='Get-SmbShareAccess failed' } }
            }.GetNewClosure() `
            -Apply {
                New-Item -ItemType Directory -Path 'C:\Public' -Force | Out-Null
                if (-not (Get-SmbShare -Name $name -ErrorAction SilentlyContinue)) {
                    New-SmbShare -Name $name -Path 'C:\Public' -FullAccess 'Everyone' -ErrorAction Stop | Out-Null
                } else {
                    Grant-SmbShareAccess -Name $name -AccountName 'Everyone' -AccessRight Full -Force -ErrorAction SilentlyContinue | Out-Null
                }
            }.GetNewClosure() `
            -RevertNeeded { [bool](Get-SmbShare -Name $name -ErrorAction SilentlyContinue) }.GetNewClosure() `
            -Revert { Remove-SmbShare -Name $name -Force -ErrorAction SilentlyContinue }.GetNewClosure() `
            -RevertNote 'share removed' -Intended "share '$name' -> C:\Public, Everyone:Full" `
            -Why "SYSVOL\$ is deliberately named to look like a domain share so it draws attention during enumeration."))
    }

    $t.Add((New-CustomControl -Id 'share.publicacl' -Category $cat -Probe 'live' `
        -Name 'C:\Public NTFS Everyone:Full' -Control 'NIST AC-3, AC-6; CIS 3.3' `
        -Test {
            if (-not (Test-Path 'C:\Public')) { return @{ State='FAIL'; Detail='C:\Public does not exist' } }
            try {
                $acl = (& icacls.exe 'C:\Public' 2>$null) -join "`n"
                if ($acl -match 'Everyone:\(.*F\)|Everyone:\(F\)') { return @{ State='PASS'; Detail='Everyone Full on the folder' } }
                return @{ State='WARN'; Detail='Everyone:F not visible in icacls output' }
            } catch { return @{ State='WARN'; Detail='icacls read failed' } }
        } `
        -Apply {
            New-Item -ItemType Directory -Path 'C:\Public' -Force | Out-Null
            'Range public share - drop files here.' | Set-Content 'C:\Public\README.txt'
            & icacls.exe 'C:\Public' '/grant' 'Everyone:(OI)(CI)F' 2>&1 | Out-Null
        } `
        -RevertNeeded { Test-Path 'C:\Public' } `
        -Revert { & icacls.exe 'C:\Public' '/remove' 'Everyone' 2>&1 | Out-Null } `
        -RevertNote 'Everyone ACE removed from C:\Public' -Intended 'Everyone:(OI)(CI)F'))
    ,$t
}

# ══ CVE reproduction artifacts ════════════════════════════════════════════
function Get-CveReproControls {
    $t = New-Object System.Collections.Generic.List[object]
    $cat = 'cve-repro'
    $Pnp = $script:K.Pnp
    $ctl = 'CVE-2021-34527 (KEV); NIST SI-2, CM-7'

    $t.Add((New-CustomControl -Id 'cve.spooler' -Category $cat -Name '[live] Print Spooler running (PrintNightmare)' -Control $ctl `
        -Test {
            $s = Get-Service Spooler -ErrorAction SilentlyContinue
            if (-not $s) { return @{ State='FAIL'; Detail='Spooler service not found' } }
            if ($s.Status -eq 'Running') { return @{ State='PASS'; Detail='Running' } }
            return @{ State='FAIL'; Detail="$($s.Status)" }
        } `
        -Apply { Set-Service Spooler -StartupType Automatic -ErrorAction Stop; Start-Service Spooler -ErrorAction SilentlyContinue } `
        -RevertNeeded { (Get-Service Spooler -ErrorAction SilentlyContinue).Status -eq 'Running' } `
        -Revert { Stop-Service Spooler -Force -ErrorAction SilentlyContinue; Set-Service Spooler -StartupType Disabled -ErrorAction SilentlyContinue } `
        -RevertNote 'Spooler stopped and disabled' -Intended 'Spooler Automatic + Running'))

    $t.Add((New-RegControl -Id 'cve.pnp.noelevation' -Category $cat -Name 'Point-and-Print NoWarningNoElevationOnInstall' -Control 'CVE-2021-34527; NIST CM-7' `
        -Path $Pnp -ValueName 'NoWarningNoElevationOnInstall' -Type DWord -Value 1 -RevertValue 0))
    $t.Add((New-RegControl -Id 'cve.pnp.updateprompt' -Category $cat -Name 'Point-and-Print UpdatePromptSettings=2' -Control 'CVE-2021-34527; NIST CM-7' `
        -Path $Pnp -ValueName 'UpdatePromptSettings' -Type DWord -Value 2 -RevertValue 0))
    $t.Add((New-RegControl -Id 'cve.pnp.restrictdrivers' -Category $cat -Name 'RestrictDriverInstallationToAdministrators=0' -Control 'CVE-2021-34527; NIST AC-6' `
        -Path $Pnp -ValueName 'RestrictDriverInstallationToAdministrators' -Type DWord -Value 0 -RevertValue 1 `
        -RevertNote 'driver install restricted to admins' `
        -Why 'This single value is what re-opens Point-and-Print abuse; the mitigation for CVE-2021-34527 is setting it back to 1.'))

    # ── HiveNightmare / SeriousSAM ────────────────────────────────────────
    #    The live config hives are held open by the kernel from early boot, so
    #    their on-disk DACL CANNOT be rewritten while the OS is running --
    #    `icacls /grant` is denied even after takeown, because Administrators lack
    #    WRITE_DAC on them (only SYSTEM has it). A machine that carries the weak
    #    Users ACE (genuinely vulnerable, or set offline) reads PASS; otherwise
    #    this is N-A, not FAIL, because the condition is unsettable on a live
    #    host. The exploitable artifact on 2025 is the VSS shadow copy below.
    foreach ($hv in 'SAM','SYSTEM','SECURITY') {
        $hive = $hv
        $t.Add((New-CustomControl -Id "cve.hive.$hive" -Category $cat `
            -Name "[live] HiveNightmare: $hive readable by Users" -Control 'CVE-2021-36934; NIST AC-3, AC-6' `
            -Test {
                try {
                    $acl = (& icacls.exe "C:\Windows\System32\config\$hive" 2>$null) -join "`n"
                    if ($acl -match 'S-1-5-32-545|BUILTIN\\Users') { return @{ State='PASS'; Detail="Users ACE present on $hive" } }
                    return @{ State='N-A'; Detail="no Users ACE on $hive -- the live hive DACL cannot be rewritten while the OS holds it open; exploit via the VSS shadow copy" }
                } catch { return @{ State='WARN'; Detail='icacls read failed' } }
            }.GetNewClosure() `
            -Apply {
                $f = "C:\Windows\System32\config\$hive"
                & takeown.exe '/F' $f 2>&1 | Out-Null
                & icacls.exe $f '/grant' '*S-1-5-32-545:(RX)' 2>&1 | Out-Null
            }.GetNewClosure() `
            -Intended 'BUILTIN\Users (S-1-5-32-545) read on the hive' `
            -NotRepairable 'the kernel holds SAM/SYSTEM/SECURITY open -- icacls is denied even after takeown; the VSS shadow copy is the exploitable artifact'))
    }

    $t.Add((New-CustomControl -Id 'cve.vss.shadow' -Category $cat -Name '[live] VSS shadow copy present' -Control 'CVE-2021-36934; NIST AC-3' `
        -Test {
            try {
                $sc = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop)
                if ($sc.Count -ge 1) { return @{ State='PASS'; Detail="$($sc.Count) shadow copy/copies" } }
                return @{ State='FAIL'; Detail='none -- HiveNightmare cannot read the live hives without one' }
            } catch { return @{ State='WARN'; Detail='Win32_ShadowCopy query failed' } }
        } `
        -Apply { & "$env:SystemRoot\System32\vssadmin.exe" create shadow /for=C: 2>&1 | Out-Null } `
        -RevertNeeded { @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue).Count -gt 0 } `
        -Revert { & vssadmin.exe delete shadows /all /quiet 2>&1 | Out-Null } `
        -RevertNote 'shadow copies deleted' `
        -Intended 'at least one shadow copy of C:' `
        -Why 'The shadow copy contains readable SAM/SYSTEM hives -- that IS the HiveNightmare artifact on 2025, and it is a real credential exposure, so teardown removes it.'))
    ,$t
}

# ══ persistence artifacts ═════════════════════════════════════════════════
function Get-PersistenceControls {
    $t = New-Object System.Collections.Generic.List[object]
    $cat = 'persistence'
    $ctl = 'NIST CM-7, SI-4'
    $payload = 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ProgramData\SysTasks\health.ps1'

    $t.Add((New-RegControl -Id 'persist.runkey' -Category $cat -Name 'Run key (SysHealth)' -Control $ctl `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ValueName 'SysHealth' -Type String -Value $payload `
        -RevertRemove -RevertNote 'run-key removed'))
    $t.Add((New-RegControl -Id 'persist.winlogonshell' -Category $cat -Name 'Winlogon Shell hijack' -Control $ctl `
        -Path $script:K.Winlg -ValueName 'Shell' -Type String -Value "explorer.exe, $payload" `
        -RevertValue 'explorer.exe' -RevertType String -RevertNote "Shell='explorer.exe'" `
        -Why 'explorer.exe still launches first, so the desktop works normally and the hijack is only visible to someone reading the value.'))

    $t.Add((New-CustomControl -Id 'persist.service' -Category $cat -Name '[live] Fake service present + Automatic' -Control $ctl `
        -Test {
            $s = Get-Service WinTelemetryHelper -ErrorAction SilentlyContinue
            if (-not $s) { return @{ State='FAIL'; Detail='WinTelemetryHelper not present' } }
            if ($s.StartType -eq 'Automatic') { return @{ State='PASS'; Detail="StartType=Automatic, Status=$($s.Status)" } }
            return @{ State='FAIL'; Detail="StartType=$($s.StartType) (expected Automatic)" }
        } `
        -Apply { Set-Service WinTelemetryHelper -StartupType Automatic -ErrorAction Stop } `
        -RevertNeeded { [bool](Get-Service WinTelemetryHelper -ErrorAction SilentlyContinue) } `
        -Revert {
            Stop-Service WinTelemetryHelper -Force -ErrorAction SilentlyContinue
            & sc.exe delete WinTelemetryHelper 2>&1 | Out-Null
        } `
        -RevertNote 'service deleted' `
        -Intended 'WinTelemetryHelper exists, StartType=Automatic (Stopped is expected)' `
        -Why 'The "service" is powershell.exe running a script, which is NOT a service binary -- it never answers the SCM, so Start-Service always fails with error 1053. Stopped is the healthy state; the artifact is its existence and its Automatic start type.'))

    foreach ($tn in 'System Update Check','Windows Health Monitor') {
        $taskName = $tn
        $t.Add((New-CustomControl -Id "persist.task.$($taskName -replace '\s','')" -Category $cat `
            -Name "[live] Scheduled task '$taskName'" -Control 'NIST CM-7, SI-4; ATT&CK T1053.005' `
            -Test {
                $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if ($task) { return @{ State='PASS'; Detail="State=$($task.State)  [ATT&CK T1053.005]" } }
                return @{ State='FAIL'; Detail='missing' }
            }.GetNewClosure() `
            -RevertNeeded { [bool](Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) }.GetNewClosure() `
            -Revert { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop }.GetNewClosure() `
            -RevertNote 'unregistered' `
            -NotRepairable 'created by Setup-CyberRange.ps1 with the beacon target baked in -- re-run Setup'))
    }

    $startupItem = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\SysHealth.ps1"
    $t.Add((New-CustomControl -Id 'persist.startupfolder' -Category $cat -Name '[live] Startup-folder payload' -Control 'NIST CM-7, SI-4; ATT&CK T1547.001' `
        -Test {
            if (Test-Path $startupItem) { return @{ State='PASS'; Detail="$startupItem  [ATT&CK T1547.001]" } }
            return @{ State='FAIL'; Detail='SysHealth.ps1 not in the all-users Startup folder' }
        }.GetNewClosure() `
        -RevertNeeded { Test-Path $startupItem }.GetNewClosure() `
        -Revert { Remove-Item $startupItem -Force -ErrorAction Stop }.GetNewClosure() `
        -RevertNote 'deleted' `
        -NotRepairable 'copied from the generated beacon payload -- re-run Setup-CyberRange.ps1'))

    foreach ($pl in 'C:\ProgramData\SysTasks\health.ps1','C:\ProgramData\SysTasks\svc.ps1') {
        $payloadPath = $pl
        $leaf = Split-Path $payloadPath -Leaf
        $t.Add((New-CustomControl -Id "persist.payload.$leaf" -Category $cat -Name "[live] Beacon payload ($leaf)" -Control 'NIST CM-7, SI-4' `
            -Test {
                if (Test-Path $payloadPath) { return @{ State='PASS'; Detail=$payloadPath } }
                return @{ State='FAIL'; Detail="$payloadPath missing" }
            }.GetNewClosure() `
            -NotRepairable 'generated from the beacon config -- re-run Setup-CyberRange.ps1'))
    }

    # ── Accessibility SYSTEM shell (IFEO debugger) ────────────────────────
    #    Operator break-glass AND a gradable persistence artifact. Applied by
    #    Setup-CyberRange.ps1; listed here so the checker and the
    #    teardown both know about it. Removing it is the single most important
    #    teardown step -- it is an authentication bypass.
    foreach ($ex in 'utilman.exe','sethc.exe','osk.exe','magnify.exe') {
        $exe = $ex
        $graded = $exe -in @('utilman.exe','sethc.exe')
        $t.Add((New-CustomControl -Id "persist.ifeo.$exe" -Category $cat -Probe 'reg' `
            -Name "Accessibility shell ($exe)" -Control 'NIST AC-3, IA-2; ATT&CK T1546.008' `
            -Requires $(if ($graded) { 'AccessibilityShell' } else { $null }) `
            -Test {
                $ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"
                $dbg = Get-ControlRegValue $ifeo 'Debugger'
                if ($dbg -and $dbg -match 'cmd\.exe|powershell') { return @{ State='PASS'; Detail="Debugger=$dbg  [ATT&CK T1546.008]" } }
                if ($graded) { return @{ State='FAIL'; Detail='no IFEO Debugger set' } }
                return @{ State='N-A'; Detail='not one of the two shells the build sets' }
            }.GetNewClosure() `
            -RevertNeeded {
                $ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"
                $null -ne (Get-ControlRegValue $ifeo 'Debugger')
            }.GetNewClosure() `
            -Revert {
                $ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"
                Remove-ControlRegValue $ifeo 'Debugger'
            }.GetNewClosure() `
            -RevertNote 'IFEO Debugger removed (auth bypass closed)' `
            -NotRepairable 'applied by Setup-CyberRange.ps1 -- re-run Setup'))
    }
    ,$t
}

# ══ beacon containment ════════════════════════════════════════════════════
function Get-BeaconContainmentControls {
    param([hashtable]$Config)
    $t = New-Object System.Collections.Generic.List[object]
    $beaconHost = if ($Config -and $Config.BeaconHost) { [string]$Config.BeaconHost } else { $null }
    $t.Add((New-CustomControl -Id 'persist.beacon.contained' -Category 'persistence' -Probe 'reg' `
        -Name 'Beacon target is RFC 5737 (containment)' -Control 'NIST SC-7' `
        -Test {
            if (-not $beaconHost) { return @{ State='N-A'; Detail='no BeaconHost in config' } }
            if ($beaconHost -match '^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)') { return @{ State='PASS'; Detail=$beaconHost } }
            return @{ State='FAIL'; Detail="$beaconHost is NOT documentation space -- clones will reach a real host (F6)" }
        }.GetNewClosure() `
        -NotRepairable 'set BeaconHost in config\range.config.psd1 to an RFC 5737 address and re-run Setup-CyberRange.ps1' `
        -Why 'F6: the beacon is a discoverable artifact, not real C2. Pointing it at anything routable turns every clone into an outbound connection to a real host.'))
    ,$t
}

# ══════════════════════════════════════════════════════════════════════════
#  LIVE PROBES used by the table
# ══════════════════════════════════════════════════════════════════════════

function Test-LsassReadable {
    <# Can lsass actually be opened for read? This is the operational truth
       behind RunAsPPL -- a registry 0 means nothing if the feature was enabled
       with a UEFI lock, or if the box has not rebooted.
       Returns $true (dumpable / PPL off), $false (protected), $null (unknown). #>
    try {
        if (-not ('RangePPL' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RangePPL {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr h);
    // PROCESS_VM_READ (0x0010) | PROCESS_QUERY_INFORMATION (0x0400)
    public static int TryOpen(int pid) {
        IntPtr h = OpenProcess(0x0010 | 0x0400, false, pid);
        if (h == IntPtr.Zero) return Marshal.GetLastWin32Error();
        CloseHandle(h);
        return 0;
    }
}
'@
        }
        $p = Get-Process lsass -ErrorAction Stop
        return ([RangePPL]::TryOpen($p.Id) -eq 0)
    } catch { return $null }
}

function Get-LsassPplEvent {
    <# Wininit logs event 12 at boot when lsass starts protected. Corroborates
       the OpenProcess probe above. #>
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Wininit'; Id=12 } -MaxEvents 1 -ErrorAction Stop
        if ($ev -and $ev.Message -match 'level:\s*(\d+)') { return [int]$Matches[1] }
    } catch {}
    return $null
}

# ══════════════════════════════════════════════════════════════════════════
#  THE TABLE, assembled
# ══════════════════════════════════════════════════════════════════════════
# ══ benign anomalies (WP17) ═══════════════════════════════════════════════
#  NOT misconfigurations. These are artifacts that LOOK suspicious and are
#  entirely legitimate, each with a discoverable exculpatory trail, so that
#  "escalate everything" is a losing strategy and students have to write
#  "no action, and here is why" -- which is a real deliverable they will write
#  constantly. Scored in BOTH directions: missing a true positive and
#  escalating a false one both cost marks.
#
#  F24 SEPARATION. Everything here is branded 'Northwind' (a fictional vendor)
#  and documented under C:\IT. The range's own seeded persistence is
#  SysHealth / WinTelemetryHelper under C:\ProgramData\SysTasks, and live
#  red-cell implants are neither. Do not blur those three naming schemes --
#  the whole IR exercise depends on being able to tell them apart.
#
#  Answer key: every item here is BENIGN. None of it should be reported as a
#  finding, and none of it should be removed by the blue team.
function Get-BenignAnomalyControls {
    $t = New-Object System.Collections.Generic.List[object]
    $cat = 'benign-anomaly'
    $ctl = 'NIST IR-4, SI-4 (triage); no finding -- benign by design'

    $itDir     = 'C:\IT\change-records'
    $agentDir  = 'C:\Program Files\Northwind Agent'
    $agentPs1  = Join-Path $agentDir 'nwagent.ps1'
    $taskName  = 'Northwind Nightly Report'
    $evtSource = 'NorthwindAgent'

    # 1. The exculpatory trail itself. Its own control so that -Repair restores
    #    it if a student "cleans up" the evidence that proves the rest benign.
    $recordsDir = $itDir
    $t.Add((New-CustomControl -Id 'anomaly.changerecords' -Category $cat `
        -Name 'IT change records present (exculpatory trail)' -Control $ctl `
        -Test {
            $f = Join-Path $recordsDir 'CHG-2026-0142-northwind-agent.txt'
            if (Test-Path $f) { return @{ State='PASS'; Detail="trail present: $recordsDir" } }
            return @{ State='FAIL'; Detail="missing: $f" }
        }.GetNewClosure() `
        -Apply {
            New-Item -ItemType Directory -Path $recordsDir -Force | Out-Null
            @"
CHANGE RECORD  CHG-2026-0142
Requested by : M. Okafor (Infrastructure)
Approved by  : Change Advisory Board, 2026-07-14
Implemented  : 2026-07-18 21:40

Install Northwind Agent 4.2 (capacity reporting) on the domain controller.
  - Installs to C:\Program Files\Northwind Agent
  - Registers a logon autostart (HKLM Run: NorthwindAgent) so the collector
    re-attaches after a reboot. This is expected and documented.
  - Registers scheduled task '$taskName' at 03:15 daily. The 03:15
    run is inside the approved maintenance window (Mon-Sun 03:00-04:00).
  - Writes informational events to the Application log, source '$evtSource'.

The vendor does not code-sign the PowerShell collector. This was raised at the
CAB and accepted; see risk acceptance RA-2026-011. Do NOT remove this agent
without raising a change -- capacity reporting for the whole estate depends
on it.
"@ | Set-Content -Path (Join-Path $recordsDir 'CHG-2026-0142-northwind-agent.txt') -Encoding UTF8
            @"
MAINTENANCE WINDOW (standing, approved 2026-01-09)
  Daily 03:00-04:00 local.
  Automated jobs, agent check-ins and backup verification run in this window.
  Interactive administrative logons in this window are EXPECTED.
"@ | Set-Content -Path (Join-Path $recordsDir 'maintenance-window.txt') -Encoding UTF8
        }.GetNewClosure() `
        -RevertNeeded { Test-Path $recordsDir }.GetNewClosure() `
        -Revert { Remove-Item $recordsDir -Recurse -Force -ErrorAction SilentlyContinue }.GetNewClosure() `
        -RevertNote 'change-record trail removed' `
        -Intended "$itDir holds the change record and maintenance-window note" `
        -Why 'Without a reachable trail the benign artifacts become a coin flip rather than an investigation. The right answer must be DISCOVERABLE, not guessable.'))

    # 2. Unsigned vendor script in Program Files -- looks like a dropped payload.
    $dir = $agentDir; $ps1 = $agentPs1
    $t.Add((New-CustomControl -Id 'anomaly.vendoragent' -Category $cat `
        -Name 'Unsigned vendor agent in Program Files' -Control $ctl `
        -Test {
            if (Test-Path $ps1) { return @{ State='PASS'; Detail="present: $ps1 (unsigned, benign)" } }
            return @{ State='FAIL'; Detail="missing: $ps1" }
        }.GetNewClosure() `
        -Apply {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            @'
# Northwind Agent 4.2 -- capacity collector
# Vendor-supplied, unsigned. Writes a local capacity line once per run.
# BENIGN: no network egress, no credential access, no persistence beyond the
# documented autostart. See C:\IT\change-records\CHG-2026-0142.
$log = Join-Path $PSScriptRoot 'capacity.log'
$free = (Get-PSDrive C).Free
"{0}  C: free={1}" -f (Get-Date -Format s), $free | Add-Content -Path $log -Encoding UTF8
'@ | Set-Content -Path $ps1 -Encoding UTF8
            @'
Northwind Agent 4.2
Capacity reporting collector.

The collector is shipped as an unsigned PowerShell script. Code signing is on
the vendor roadmap for 5.0. Deployment was approved under CHG-2026-0142 with
risk acceptance RA-2026-011.

Support: support@northwind.example (fictional vendor -- range artifact)
'@ | Set-Content -Path (Join-Path $dir 'README.txt') -Encoding UTF8
        }.GetNewClosure() `
        -RevertNeeded { Test-Path $dir }.GetNewClosure() `
        -Revert { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }.GetNewClosure() `
        -RevertNote 'vendor agent directory removed' `
        -Intended "$agentPs1 present, unsigned, inert" `
        -Why 'An unsigned script in Program Files is the single most over-reported benign artifact in real SOCs. The script is deliberately inert -- it reads free disk space and writes a local line.'))

    # 3. Run key for the agent -- indistinguishable from persistence at a glance.
    $t.Add((New-RegControl -Id 'anomaly.runkey.vendor' -Category $cat `
        -Name 'Run key (NorthwindAgent) -- documented vendor autostart' -Control $ctl `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ValueName 'NorthwindAgent' `
        -Type String -Value "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$agentPs1`"" `
        -RevertRemove -RevertNote 'vendor run-key removed' `
        -Why 'Structurally identical to the SysHealth run key that IS the finding. The only thing separating them is the change record -- which is exactly the discrimination being taught.'))

    # 4. Off-hours scheduled task, inside the documented maintenance window.
    $tn = $taskName; $script = $agentPs1
    $t.Add((New-CustomControl -Id 'anomaly.task.nightly' -Category $cat `
        -Name "[live] Scheduled task '$taskName' at 03:15" -Control $ctl `
        -Test {
            if (Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue) {
                return @{ State='PASS'; Detail='present, 03:15 daily (inside approved window)' }
            }
            return @{ State='FAIL'; Detail='missing' }
        }.GetNewClosure() `
        -Apply {
            $a = New-ScheduledTaskAction -Execute 'powershell.exe' `
                 -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $script)
            $g = New-ScheduledTaskTrigger -Daily -At '03:15'
            $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $tn -Action $a -Trigger $g -Principal $p `
                -Description 'Northwind Agent nightly capacity report (CHG-2026-0142)' -Force | Out-Null
        }.GetNewClosure() `
        -RevertNeeded { [bool](Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue) }.GetNewClosure() `
        -Revert { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue }.GetNewClosure() `
        -RevertNote 'unregistered' `
        -Intended "scheduled task '$taskName', daily 03:15, SYSTEM" `
        -Why 'Off-hours SYSTEM execution is a classic escalation trigger. Here it is inside a standing maintenance window that is documented in C:\IT\change-records\maintenance-window.txt.'))

    # 5. Application-log events, so the agent has a telemetry footprint too.
    $src = $evtSource
    $t.Add((New-CustomControl -Id 'anomaly.eventsource' -Category $cat `
        -Name "[live] Application-log event source '$evtSource'" -Control $ctl `
        -Test {
            # SourceExists enumerates every log, so a non-elevated caller throws
            # on Security/State. Report that as FAIL, NOT WARN: Repair-OneControl
            # treats WARN as "already in the intended state" and would skip the
            # control forever. FAIL is also honest -- we could not confirm it.
            try {
                if ([System.Diagnostics.EventLog]::SourceExists($src)) {
                    return @{ State='PASS'; Detail='source registered; benign informational events' }
                }
                return @{ State='FAIL'; Detail='source not registered' }
            } catch {
                return @{ State='FAIL'; Detail="could not confirm (run elevated): $($_.Exception.Message)" }
            }
        }.GetNewClosure() `
        -Apply {
            # Defensive: if the existence probe throws (non-elevated, or a log we
            # cannot read), still attempt creation and swallow "already exists"
            # rather than letting the whole control fail on the probe.
            $exists = $false
            try { $exists = [System.Diagnostics.EventLog]::SourceExists($src) } catch { $exists = $false }
            if (-not $exists) {
                try { New-EventLog -LogName Application -Source $src -ErrorAction Stop }
                catch { if ($_.Exception.Message -notmatch 'already exists') { throw } }
            }
            foreach ($n in 1..3) {
                Write-EventLog -LogName Application -Source $src -EventId 4200 -EntryType Information `
                    -Message "Northwind Agent capacity report completed successfully (run $n). CHG-2026-0142." -ErrorAction SilentlyContinue
            }
        }.GetNewClosure() `
        -RevertNeeded {
            try { [System.Diagnostics.EventLog]::SourceExists($src) } catch { $false }
        }.GetNewClosure() `
        -Revert { Remove-EventLog -Source $src -ErrorAction SilentlyContinue }.GetNewClosure() `
        -RevertNote 'event source removed' `
        -Intended "Application-log source '$evtSource' registered" `
        -Why 'Gives the benign agent a log footprint, so a student working from the event log alone still meets it and has to adjudicate it rather than only meeting it on disk.'))

    ,$t
}

function Get-RangeControlTable {
    <# The complete control set. -Config is optional: it is only used to resolve
       role/config-gated entries (and the expected NetBIOS name for autologon), so
       the checker still works on a box with no readable config. #>
    [CmdletBinding()]
    param([hashtable]$Config)

    $all = New-Object System.Collections.Generic.List[object]
    $all.AddRange((Get-UpdatesDefenderControls))
    $all.AddRange((Get-CredentialExposureControls -Config $Config))
    $all.AddRange((Get-UacLsaVbsControls))
    $all.AddRange((Get-SmbNetworkControls))
    $all.AddRange((Get-RdpWinrmControls))
    $all.AddRange((Get-LoggingVisibilityControls -Config $Config))
    $all.AddRange((Get-LegacyServicesControls))
    $all.AddRange((Get-CveReproControls))
    $all.AddRange((Get-PersistenceControls))
    $all.AddRange((Get-BeaconContainmentControls -Config $Config))
    $all.AddRange((Get-BenignAnomalyControls))

    # WP15: stamp the ATT&CK technique onto anything that did not declare one
    # inline. Done here rather than at 125 call sites so the whole mapping stays
    # reviewable in one block -- see $script:TechniqueMap.
    foreach ($c in $all) {
        if (-not $c.Technique) { $c.Technique = Resolve-ControlTechnique -Id $c.Id }
    }

    # Streams the controls one by one. Callers wrap in @() when they need an
    # array; returning ,$all instead would hand every @()-wrapping caller a
    # single-element array CONTAINING the list, which silently turns "125
    # controls" into "one control that is a list".
    $all
}

function Get-RangeControl {
    <# Filtered view of the table. -Category and -Id accept multiple values;
       -ApplicableOnly drops entries this host's role or this config excludes. #>
    [CmdletBinding()]
    param(
        [string[]]$Category,
        [string[]]$Id,
        [hashtable]$Config,
        [switch]$ApplicableOnly
    )
    $controls = @(Get-RangeControlTable -Config $Config)
    if ($Category) { $controls = @($controls | Where-Object { $Category -contains $_.Category }) }
    if ($Id)       { $controls = @($controls | Where-Object { $Id       -contains $_.Id }) }
    if ($ApplicableOnly) {
        $controls = @($controls | Where-Object { (Test-ControlApplicable -Control $_ -Config $Config).Applicable })
    }
    $controls
}

function Test-ControlApplicable {
    <# Role and config gates. Returns @{ Applicable = $bool; Reason = '...' } so a
       caller can report N-A with the reason instead of silently dropping a row. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Control, [hashtable]$Config)

    if ($Control.Applies -ne 'All') {
        $isDC = $false
        try { $isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4 } catch {}
        if ($Control.Applies -eq 'DC'    -and -not $isDC) { return @{ Applicable=$false; Reason='domain-controller only' } }
        if ($Control.Applies -eq 'NonDC' -and $isDC)      { return @{ Applicable=$false; Reason='not applicable on a domain controller' } }
    }

    if ($Control.Requires) {
        if (-not $Config) { return @{ Applicable=$false; Reason="config gate '$($Control.Requires)' not readable" } }
        $node = $Config
        foreach ($seg in ($Control.Requires -split '\.')) {
            if ($null -eq $node) { break }
            $node = $node[$seg]
        }
        if (-not $node) { return @{ Applicable=$false; Reason="disabled in config ($($Control.Requires))" } }
    }
    return @{ Applicable=$true; Reason='' }
}

# ══════════════════════════════════════════════════════════════════════════
#  THE FOUR VERBS
# ══════════════════════════════════════════════════════════════════════════

function Test-RangeControl {
    <# CHECK. Returns one result row:
         Id / Category / Name / Control / State / Detail / Probe
       State is PASS | FAIL | WARN | N-A, matching the checker's vocabulary.
       A matched value carrying a Note is downgraded to WARN with that note --
       that is how "set, but needs a reboot" and "set, but a no-op on 2025" are
       reported without pretending the control is simply present. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Control, [hashtable]$Config)

    $row = [pscustomobject]@{
        Id = $Control.Id; Category = $Control.Category; Name = $Control.Name
        Control = $Control.Control; State = 'WARN'; Detail = ''; Probe = $Control.Probe
        Technique = $Control.Technique
    }

    $gate = Test-ControlApplicable -Control $Control -Config $Config
    if (-not $gate.Applicable) { $row.State = 'N-A'; $row.Detail = $gate.Reason; return $row }

    if ($Control.Kind -eq 'Custom') {
        try {
            $r = & $Control.Test
            if ($r -is [hashtable]) { $row.State = $r.State; $row.Detail = $r.Detail }
            else { $row.State = 'WARN'; $row.Detail = 'test returned no state' }
        } catch {
            $row.State = 'WARN'; $row.Detail = "test threw: $($_.Exception.Message)"
        }
        return $row
    }

    $v = Get-ControlRegValue $Control.Path $Control.ValueName
    if ($null -eq $v) {
        $row.State = 'FAIL'; $row.Detail = "not set ($($Control.ValueName) absent under $($Control.Path))"
        return $row
    }
    if (Test-ControlValueMatch $v $Control.Value) {
        $shown = if ($v -is [array]) { ($v -join ',') } else { "$v" }
        if ($Control.Note) { $row.State = 'WARN'; $row.Detail = "$($Control.ValueName)=$shown; $($Control.Note)" }
        else               { $row.State = 'PASS'; $row.Detail = "$($Control.ValueName)=$shown" }
        return $row
    }
    if ($Control.Value -is [array]) {
        $have = @($v)
        $miss = @($Control.Value | Where-Object { $have -notcontains $_ })
        $row.State = 'WARN'; $row.Detail = "$($Control.ValueName) present but missing: $($miss -join ',')"
        return $row
    }
    $row.State = 'FAIL'; $row.Detail = "$($Control.ValueName)=$v (expected $($Control.Value))"
    return $row
}

function Set-RangeControl {
    <# APPLY. Registry controls write through RangeCommon's Set-RegValue when it
       is loaded, so the change lands in the manifest. Returns $true if the
       control was applied, $false if it was gated out or has no apply action. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)]$Control, [hashtable]$Config)

    $gate = Test-ControlApplicable -Control $Control -Config $Config
    if (-not $gate.Applicable) { return $false }
    if (-not $PSCmdlet.ShouldProcess($Control.Name, 'apply')) { return $false }

    if ($Control.Kind -eq 'Custom') {
        if (-not $Control.Apply) { return $false }
        & $Control.Apply
        return $true
    }
    Set-ControlRegValue $Control.Path $Control.ValueName $Control.Type $Control.Value $Control.Category
    return $true
}

function Test-RangeControlRevertNeeded {
    <# Is the range state actually present, i.e. is there anything to undo?
       Teardown uses this so a second run is a no-op instead of a pile of errors. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Control)

    if ($Control.Kind -eq 'Custom') {
        if (-not $Control.Revert -or -not $Control.RevertNeeded) { return $false }
        try { return [bool](& $Control.RevertNeeded) } catch { return $false }
    }
    if ($Control.RevertValue -eq $script:REVERT_NONE) { return $false }
    $v = Get-ControlRegValue $Control.Path $Control.ValueName
    if ($null -eq $v) { return $false }
    return (Test-ControlValueMatch $v $Control.Value)
}

function Reset-RangeControl {
    <# REVERT. Restores a KNOWN-GOOD value, not the machine's previous value --
       the build never captured that. Returns $true if it acted. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)]$Control)

    if (-not $PSCmdlet.ShouldProcess($Control.Name, 'revert')) { return $false }

    if ($Control.Kind -eq 'Custom') {
        if (-not $Control.Revert) { return $false }
        & $Control.Revert
        return $true
    }
    if ($Control.RevertValue -eq $script:REVERT_NONE) { return $false }
    if ($Control.RevertValue -eq $script:REVERT_REMOVE) {
        Remove-ControlRegValue $Control.Path $Control.ValueName
        return $true
    }
    Set-ControlRegValue $Control.Path $Control.ValueName $Control.RevertType $Control.RevertValue $Control.Category
    return $true
}

function Get-RangeControlRevertNote {
    <# What the revert will do, for the teardown dry run. #>
    param([Parameter(Mandatory)]$Control)
    if ($Control.RevertNote) { return $Control.RevertNote }
    if ($Control.Kind -eq 'Registry') {
        if ($Control.RevertValue -eq $script:REVERT_REMOVE) { return "remove $($Control.ValueName)" }
        if ($Control.RevertValue -ne $script:REVERT_NONE)   { return "$($Control.ValueName)=$($Control.RevertValue)" }
    }
    return 'restore default'
}

function Invoke-RangeControlCategory {
    <# Apply every control in one category. This is what the scripts\NN-*.ps1
       Setup-CyberRange.ps1 calls for its registry/state work; anything genuinely
       imperative (feature installs, file drops, AD objects) stays in the script.

       -ExcludeId leaves named controls to the calling script. Use it only where
       the value depends on runtime state the table cannot know -- the autologon
       block in Setup-CyberRange.ps1 decides whether to enable autologon at
       all, based on whether it could actually set the account's password. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Category, [hashtable]$Config, [string[]]$ExcludeId)

    $log = Get-Command Write-RangeLog -ErrorAction SilentlyContinue
    $applied = 0; $skipped = 0
    foreach ($c in (Get-RangeControl -Category $Category -Config $Config)) {
        if ($ExcludeId -and $ExcludeId -contains $c.Id) { continue }
        $gate = Test-ControlApplicable -Control $c -Config $Config
        if (-not $gate.Applicable) {
            $skipped++
            if ($log) { Write-RangeLog "skip $($c.Id): $($gate.Reason)" }
            continue
        }
        try {
            if (Set-RangeControl -Control $c -Config $Config) { $applied++ }
        } catch {
            if ($log) { Write-RangeLog "control $($c.Id) failed: $($_.Exception.Message)" 'WARN' }
            else { Write-Warning "control $($c.Id) failed: $($_.Exception.Message)" }
        }
    }
    if ($log) { Write-RangeLog "category '$Category': $applied control(s) applied, $skipped skipped." }
}

Export-ModuleMember -Function `
    Get-RangeControlTable, Get-RangeControl, Test-ControlApplicable, `
    Test-RangeControl, Set-RangeControl, Reset-RangeControl, `
    Test-RangeControlRevertNeeded, Get-RangeControlRevertNote, `
    Invoke-RangeControlCategory, `
    Get-ControlRegValue, Set-ControlRegValue, Remove-ControlRegValue, `
    Test-LsassReadable, Get-LsassPplEvent
