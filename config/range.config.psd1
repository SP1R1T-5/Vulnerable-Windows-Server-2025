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
        SafeModePassword = 'S@feM0de-ChangeMe!'   # DSRM / directory-restore password
        InstallAdcs      = $true                  # AD CS + ESC1-vulnerable template
        SeedUsers        = $true                  # Kerberoast / AS-REP-roast fodder
        WeakAcls         = $true                  # DCSync + GenericAll delegation
        LegacyGpo        = $true                  # GPP cpassword in SYSVOL, weak policy
    }

    # ─── Break-glass operator recovery account ───────────────────────────
    # NOT part of the exercise. Created by scripts\00-break-glass.ps1 BEFORE the
    # first weakening step (Phase 1) and re-created as a DOMAIN account after
    # promotion, so the operator always has a way back in. It is deliberately
    # NOT hidden from the sign-in screen and must NOT appear in any scenario
    # brief handed to participants.
    BreakGlass = @{
        Enabled  = $true
        User     = 'rangebreak'
        Password = 'ChangeMe-BreakGlass!2026'   # CHANGE THIS. Record it off-box.
    }

    # ─── Local credentials the range exposes ─────────────────────────────
    # The build now SETS LocalAdminAutoLogonUser's password to this value in
    # Phase 1 and validates it before enabling autologon, so the account, the
    # registry value, and the "exposed credential" lesson can never diverge.
    # Whatever you put here BECOMES the Administrator password.
    LocalAdminAutoLogonUser = 'Administrator'
    LocalAdminAutoLogonPass = 'Password!'       # CHANGE THIS to the canonical competition password.

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
}
