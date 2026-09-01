# FSLogix Health Check

A single PowerShell script that audits an FSLogix installation on a Windows session
host (AVD, RDS, or any Windows Server/10/11 multi-user box) against Microsoft's
documented best practices, and reports what it finds in plain English.

Built for AVD/EUC admins who want a fast, trustworthy answer to "is FSLogix actually
set up right on this box?" - whether that's day one of a deployment, or troubleshooting
a "my profile didn't roam" ticket.

## What it checks

**Installation & version**
- FSLogix installed, and which version

**Configuration** (registry)
- Profile Container enabled
- Storage location mode (VHDLocations vs Cloud Cache CCDLocations, and that only one is set)
- Volume type (`vhd` vs the recommended `vhdx`)
- Container size ceiling
- `RoamIdentity` - flagged if enabled on an Entra-joined device, which Microsoft does not recommend
- Concurrent-session profile mode - flagged if set on an AVD host, since AVD host pools don't support concurrent connections at all
- Local profile fallback protection (`DeleteLocalProfileWhenVHDShouldApply`)
- Cloud Cache cache/proxy directory separation

**AV/EDR exclusions**
- Compares live Windows Defender exclusions against Microsoft's full documented list
  (processes, drivers, folders) and names exactly what's missing. Missing AV exclusions
  are called out by Microsoft's own troubleshooting docs as the leading cause of FSLogix
  container corruption.

**Storage**
- Profile share reachability (SMB/445)
- Write access (a distinct check from reachability - "can browse" and "can write" are
  different failure modes)
- Free space on the profile share, against Microsoft's recommended thresholds
- Kerberos encryption type on Azure Files shares (RC4 vs AES), ahead of Microsoft's
  upcoming Kerberos hardening change

**Live runtime health**
- `frxsvc` / `frxccds` services running
- FSLogix minifilter drivers loaded
- Current session's FSLogix mount status (when run in a signed-in user's context)
- Recent FSLogix event log errors (filtered to skip known-benign noise)
- Orphaned `.lock` files on the profile share

Every check reports **PASS**, **WARN**, **FAIL**, or **INFO**, with a plain-English
reason - never just a registry value with no explanation.

## Requirements

- Windows PowerShell 5.1 (built into Windows Server 2016+/Windows 10+) - no external modules
- Run elevated (the checks read HKLM, services, Defender preferences, and event logs)
- FSLogix must be installed on the host being checked

## Usage

Report only (safe, read-only, the default):

```powershell
.\FSLogix-HealthCheck.ps1
```

Report and offer fixes - prompts before changing anything:

```powershell
.\FSLogix-HealthCheck.ps1 -Fix
```

Choose where the HTML report is written:

```powershell
.\FSLogix-HealthCheck.ps1 -ReportPath 'C:\Reports\fslogix-check.html'
```

By default the HTML report is saved to `C:\ProgramData\FSLogixHealthCheck\`, and a full
transcript log is saved to `C:\Windows\Temp\NMWLogs\ScriptedActions\` (a directory
convention borrowed from Nerdio Manager, but not a dependency - it's just a sensible,
always-writable location under `C:\Windows\Temp`).

### `-Fix` behaviour and safety

`-Fix` never silently changes anything. For each WARN/FAIL that has a known-safe fix
(currently: adding the missing Defender exclusions, setting `VolumeType` to `vhdx`,
raising a too-small `SizeInMBs`, and correcting a misconfigured `RoamIdentity`), the
script asks **at the console, per item, before applying it**.

If the script detects it's running non-interactively - under an RMM tool, a scheduled
task, or a Nerdio Manager for Enterprise scripted action - `-Fix` is automatically
disabled and it falls back to report-only, logging that a fix was available but skipped.
**A fix is only ever applied by a human answering yes at a real console.**

Some issues are deliberately *never* auto-fixed, because the "fix" carries real risk:
enabling `DeleteLocalProfileWhenVHDShouldApply` can delete a user's existing local
profile, so the script only ever reports it and lets you decide.

## Example output

An example HTML report is in [`examples/FSLogix-HealthCheck-Sample-Report.html`](examples/FSLogix-HealthCheck-Sample-Report.html) -
generated on a real AVD session host that has FSLogix installed but not yet configured
(a common state right after imaging), so it shows a realistic mix of PASS/WARN/FAIL/INFO.

Console output looks like this:

```
FSLogix Health Check - HOST01 - 2026-09-01 12:32
================================================================

[PASS] Install        FSLogix installed
       Installed, version 3.25.822.19044.
[FAIL] Config         Profile Container enabled
       Enabled is 0, not 1. Profile Container is not active.
[FAIL] AV Exclusions  Defender process and path exclusions
       Missing exclusions: frxsvc.exe, frxccds.exe, C:\Program Files\FSLogix\Apps\, C:\ProgramData\FSLogix\.
       Fix available but skipped: running non-interactively. Run with -Fix at an interactive console to apply.
...
================================================================
Summary: 7 pass, 2 warn, 3 fail, 3 info
================================================================
```

## Running as a Nerdio Manager for Enterprise (NME) scripted action

The script's header comments (`#description`, `#execution mode`, `#tags`) are already
in NME's scripted-action format, so it can be uploaded as-is as a Windows (CustomScript)
scripted action and run against a host pool. This is entirely optional - the script has
no NME dependency and runs the same way as a plain `.ps1` anywhere else.

## What this does not do

- It does not manage licensing/entitlement checks beyond confirming FSLogix is
  installed - FSLogix licensing is entitlement-based (via M365/Windows/AVD licensing),
  not a product key, so there's nothing to technically validate there.
- It cannot verify third-party (non-Defender) AV exclusion lists remotely - Windows
  doesn't expose a way to query another vendor's exclusion list locally. When Defender
  isn't the active engine, the script tells you the full list to check by hand instead.
- Microsoft doesn't publish one master table of every FSLogix session status/error
  code, so the script decodes the codes it can confirm from Microsoft's own docs and
  points you at the official reference for anything else, rather than guessing.

## Sources

Every check is based on current Microsoft Learn FSLogix documentation - the
[Prerequisites](https://learn.microsoft.com/fslogix/overview-prerequisites),
[Configuration Setting Reference](https://learn.microsoft.com/fslogix/reference-configuration-settings),
and [Troubleshooting](https://learn.microsoft.com/fslogix/troubleshooting-fslogix-service) pages.

## License

MIT - see [LICENSE](LICENSE).
