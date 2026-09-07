@{
    # ─── SAFETY GUARD ─────────────────────────────────────────────────────
    # This build INTENTIONALLY weakens security for red-vs-blue training.
    # Only run on an ISOLATED, authorized lab host with NO production data
    # and NO unrestricted internet path. Flip to $true to acknowledge.
    Confirmed = $true

    # ─── Standalone categories to apply ──────────────────────────────────
    Categories = @{
        UpdatesDefender    = $true
        CredentialExposure = $true
        UacLsaVbs          = $true
        SmbNetwork         = $true
        RdpWinrm           = $true
        LoggingVisibility  = $true
        LegacyServices     = $true
        Persistence        = $true
        HiddenAccounts     = $true
    }

    # ─── Domain Controller (AD-DS) module ────────────────────────────────
    # Set Enabled = $true ONLY on the box you intend to promote. Promotion
    # (dc\00-promote-dc.ps1) reboots; run the remaining dc\* scripts after.
    DC = @{
        Enabled          = $true
        DomainName       = 'range.lab'
        NetbiosName      = 'RANGE'
        SafeModePassword = 'dLxekh0jyF5LBBASDmzVAa9!'   # DSRM / directory-restore password. RECORD OFF-BOX.
        InstallAdcs      = $true                  # AD CS + ESC1-vulnerable template
        SeedUsers        = $true                  # Kerberoast / AS-REP-roast fodder
        WeakAcls         = $true                  # DCSync + GenericAll delegation
        LegacyGpo        = $true                  # GPP cpassword in SYSVOL, weak policy
        SecurityGpoDowngrade = $true              # push SMB-signing-off / NoLMHash / 1MB-logs INTO the Default Domain Controllers Policy so they survive gpupdate (F33)
    }

    # ─── Operator recovery account (the one you log in as) ───────────────
    # NOT part of the exercise, and must NOT appear in any scenario brief handed
    # to participants.
    #
    # A standing administrator the build NEVER rewrites -- unlike the built-in
    # Administrator, whose password the build sets to LocalAdminAutoLogonPass for
    # the exposed-credential lesson. Provisioned by the pre-flight BEFORE the
    # first weakening step, re-created as a DOMAIN admin after promotion
    # (Phase 3), re-asserted and validated at the end (Phase 4), and re-asserted
    # again on EVERY boot by the operator keeper task. Not hidden from the
    # sign-in screen. Log in as this.
    #
    # There was a second, near-identical 'rangebreak' account here until
    # 2026-09-07. Two accounts read from this same file are not two recovery
    # paths; the real layers are the VM snapshot, this account, the logon-screen
    # accessibility shell, DSRM and Windows RE. See docs\BREAK-GLASS.md.
    Analyst = @{
        Enabled  = $true
        User     = 'analyst'
        Password = 'EbUeXDN3WDM4tXqgKzt9Aa9!'   # YOUR LOGIN. RECORD OFF-BOX.
    }

    # ─── Local credentials the range exposes ─────────────────────────────
    # The build now SETS LocalAdminAutoLogonUser's password to this value in
    # Phase 1 and validates it before enabling autologon, so the account, the
    # registry value, and the "exposed credential" lesson can never diverge.
    # Whatever you put here BECOMES the Administrator password.
    LocalAdminAutoLogonUser = 'Administrator'
    LocalAdminAutoLogonPass = 'Celcius0525*'       # CHANGE THIS to the canonical competition password.

    HiddenAdminPassword = 'CrazySnow2024*'
    HiddenAdminAccounts = @('svc-backup','smb-backup','wsus-backup','iis-backup','adfs-backup')

    # ─── Persistence beacon target ───────────────────────────────────────
    # The beacon is a DISCOVERABLE ARTIFACT, not real C2 -- the service/task
    # just TCP-connects here every interval so the blue team can find and kill
    # the persistence. NOTHING has to be listening; a failed/timed-out connect
    # is expected and fine.
    #
    # Standalone per-participant VMs (no shared range network): leave this as a
    # reserved, non-routable "documentation" IP (RFC 5737, 192.0.2.0/24) so no
    # clone can ever phone a real internet host. Bake one value into the golden
    # image before cloning; the same value on every VM is correct. NEVER a real
    # external address.
    #
    # Only change this to a real IP if you run a central sinkhole/scoring host
    # that should actually receive the check-ins.
    BeaconHost            = '192.0.2.1'    # RFC 5737 TEST-NET-1: routes nowhere real
    BeaconPort            = 4444           # classic MSF port (obvious). Use 443/8080 for a subtler hunt.
    BeaconIntervalSeconds = 300

    # ─── Toggles ─────────────────────────────────────────────────────────
    RemoveDefenderFeature = $false   # $true fully uninstalls Defender (reboot); $false just disables
    DisableEventLogService = $false  # DANGER: can destabilize boot on 2025; leave $false unless you know

    # IFEO SYSTEM shell at the logon screen (utilman / sethc). Operator break-glass
    # -- a guaranteed no-password SYSTEM cmd to recover from any lockout -- AND a
    # gradable persistence artifact (MITRE T1546.008 / T1546.012). Applied in Phase 1.
    AccessibilityShell = $true

    # Operator keeper: a permanent SYSTEM-at-startup task that re-asserts the
    # Analyst account (enabled, unlocked, admin, password) on EVERY boot, disables
    # account lockout, and drops C:\range-fix.cmd (a short, typeable recovery
    # command for the logon-screen shell, where paste does not work). This is the
    # "you can never be locked out of analyst again" safety net.
    OperatorKeeper = $true
}
