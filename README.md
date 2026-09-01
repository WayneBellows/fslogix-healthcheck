# FSLogix Health Check

PowerShell that audits an FSLogix installation on a Windows session host (AVD, RDS, or
any Windows Server / 10 / 11 multi-user box) against Microsoft's documented best
practice, and reports what it finds in plain English.

Built for AVD and EUC admins who want a fast, trustworthy answer to "is FSLogix actually
set up right on this box?" - whether that is day one of a deployment, or troubleshooting
a "my profile didn't roam" ticket.

## Which script to use

| | `FSLogix-HealthCheck-v2.ps1` | `FSLogix-HealthCheck.ps1` |
|---|---|---|
| **Use when** | You want the full picture, a score you can trend, or a run across a whole host pool | You want a quick read on one box at a console |
| Checks | 47 (mode-dependent) | 14 |
| Health score | Weighted 0-100 with a grade band | None |
| Output | JSON plus HTML, either can go to a UNC path | HTML |
| Remediation | `-Remediate`, allow-listed, `-WhatIf` supported, never prompts | `-Fix`, prompts per item, disabled under automation |
| Docs | **[README-v2.md](README-v2.md)** | This page, below |

v2 is the current version and the one to reach for. v1 stays in the repo because a
single-file script with no score and no JSON is still the right tool for a five-minute
look at one host.

---

## v2 - what it adds

Full detail is in **[README-v2.md](README-v2.md)**. In short:

**A rule set, not a script.** Every check carries a stable ID, a severity, evidence, a
recommendation and a link to the Microsoft page it came from. The rules can be reviewed
without reading PowerShell.

**A number you can trend.** Severity-weighted 0-100 health score. A pass earns full
weight, a warning half, a failure none. Critical failures are also reported separately,
because a host can score well and still be broken for its users right now.

**JSON as the source of truth.** HTML is rendered from it. Both can be written to a UNC
path, so every host in a pool lands in one place and can be aggregated. Check IDs are
stable, so findings join across hosts and trend over time.

**Remediation that is safe unattended.** `-Remediate` is explicit and allow-listed,
filterable with `-RemediateOnly`, and supports `-WhatIf`. It never prompts.
`DeleteLocalProfileWhenVHDShouldApply` is never applied automatically, because doing so
permanently deletes a user's local profile.

**Coverage v1 did not have,** including: Microsoft's full antivirus exclusion list rather
than a subset; `ObjectSpecific` SID overrides, which mean the machine-level settings are
not the effective settings; the six Cloud Cache resilience settings; the FSLogix local
include and exclude groups; `PreventLoginWithFailure` and `PreventLoginWithTempProfile`;
temporary and orphaned profile detection; the Entra Kerberos client settings required on
Azure Files; and Status and Reason codes decoded against Microsoft's published tables.

**Three v1 bugs fixed.** The minifilter check used a substring match, so `frxdrv`
reported as loaded when only `frxdrvvt` was. A global `$ErrorActionPreference = 'Stop'`
meant one unhandled error lost the whole report. The antivirus check covered 2 processes
and 2 folders against a much longer documented list.

```powershell
.\FSLogix-HealthCheck-v2.ps1                                    # read-only
.\FSLogix-HealthCheck-v2.ps1 -ReportPath \\fileserver\fslogix-health -Quiet
.\FSLogix-HealthCheck-v2.ps1 -Remediate -WhatIf                 # preview fixes
```

---

## v1 - `FSLogix-HealthCheck.ps1`

### What it checks

**Installation and version**
- FSLogix installed, and which version

**Configuration** (registry)
- Profile Container enabled
- Storage location mode (`VHDLocations` versus Cloud Cache `CCDLocations`, and that only one is set)
- Volume type (`vhd` versus the recommended `vhdx`)
- Container size ceiling
- `RoamIdentity` - flagged if enabled on an Entra-joined device, which Microsoft does not recommend
- Concurrent-session profile mode - flagged if set on an AVD host, since AVD host pools do not support concurrent connections at all
- Local profile fallback protection (`DeleteLocalProfileWhenVHDShouldApply`)
- Cloud Cache cache and proxy directory separation

**Antivirus exclusions**
- Compares live Windows Defender exclusions against a core subset of Microsoft's
  documented list and names exactly what is missing. Missing exclusions are called out by
  Microsoft's own troubleshooting guidance as a leading cause of container corruption.
  (v2 checks the full documented list, including drivers, temp VHD patterns, Cloud Cache
  folders and the share-side container patterns.)

**Storage**
- Profile share reachability (SMB 445)
- Write access, a distinct check from reachability - "can browse" and "can write" are different failure modes
- Free space on the profile share, against Microsoft's recommended thresholds
- Kerberos encryption type on Azure Files shares (RC4 versus AES), ahead of Microsoft's
  April 2026 Kerberos hardening change

**Live runtime health**
- `frxsvc` and `frxccds` services running
- FSLogix minifilter drivers loaded
- Current session's FSLogix mount status, when run in a signed-in user's context
- Recent FSLogix event log errors, filtered to skip known-benign noise
- Orphaned `.lock` files on the profile share

Every check reports **PASS**, **WARN**, **FAIL** or **INFO** with a plain-English reason,
never just a registry value with no explanation.

### Usage

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
transcript log to `C:\Windows\Temp\NMWLogs\ScriptedActions\` (a directory convention
borrowed from Nerdio Manager, but not a dependency - just a sensible, always-writable
location under `C:\Windows\Temp`).

### `-Fix` behaviour and safety

`-Fix` never silently changes anything. For each WARN or FAIL that has a known-safe fix
(adding missing Defender exclusions, setting `VolumeType` to `vhdx`, raising a too-small
`SizeInMBs`, correcting a misconfigured `RoamIdentity`), the script asks **at the
console, per item, before applying it**.

If the script detects it is running non-interactively - under an RMM tool, a scheduled
task, or a Nerdio Manager for Enterprise scripted action - `-Fix` is automatically
disabled and it falls back to report-only, logging that a fix was available but skipped.
**A fix is only ever applied by a human answering yes at a real console.** v2 replaces
this with an explicit allow-list that works unattended.

Enabling `DeleteLocalProfileWhenVHDShouldApply` can permanently delete a user's existing
local profile, so it is only ever reported, never applied.

### Example output

An example HTML report is in
[`examples/FSLogix-HealthCheck-Sample-Report.html`](examples/FSLogix-HealthCheck-Sample-Report.html),
generated on a real AVD session host that has FSLogix installed but not yet configured -
a common state right after imaging - so it shows a realistic mix of PASS, WARN, FAIL and INFO.

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

---

## Requirements

Both scripts:

- Windows PowerShell 5.1 (built into Windows Server 2016 and later, Windows 10 and later). No external modules.
- Run elevated. The checks read HKLM, services, Defender preferences and event logs.
- FSLogix installed on the host being checked.

## Running as a Nerdio Manager for Enterprise (NME) scripted action

Both scripts carry the `#description`, `#execution mode` and `#tags` header comments NME
expects, so either uploads as-is as a Windows (CustomScript) scripted action and runs
against a host pool. This is optional - neither has an NME dependency and both run the
same way as a plain `.ps1` anywhere else.

v2 writes a single summary line to standard output for the calling automation to capture:

```
FSLogix Health Check v2.0 | HOST01 | Score 73.6/100 (Needs attention) | 24 pass, 12 warn, 4 fail, 7 info | Critical: AV-EXCLUSIONS | JSON: \\fileserver\fslogix-health\FSLogix-HealthCheck-HOST01-20260901-140233.json
```

## What neither script does

- **No licensing check beyond confirming FSLogix is installed.** FSLogix entitlement
  comes through M365, Windows or AVD licensing rather than a product key, so there is
  nothing to validate technically.
- **Third-party antivirus exclusion lists cannot be read.** Windows exposes no way to
  query another vendor's exclusion list locally. Where Defender is not the active engine,
  both scripts say so and name the full list to check by hand.
- **The storage back end is out of scope.** Share-side antivirus exclusions, share and
  NTFS permissions for real user accounts, and storage throughput cannot be observed from
  a session host. A host-side pass does not prove the share is correct.
- **A scripted action runs as SYSTEM,** so the share write test proves computer account
  access, not user access.

## Sources

Every check traces to current Microsoft Learn FSLogix documentation:

- [Prerequisites, including the antivirus exclusion list](https://learn.microsoft.com/fslogix/overview-prerequisites)
- [Configuration Setting Reference](https://learn.microsoft.com/fslogix/reference-configuration-settings)
- [Configuration examples](https://learn.microsoft.com/fslogix/concepts-configuration-examples) - the recommended-value tables v2's score is built on
- [FSLogix Codes and what they mean](https://learn.microsoft.com/fslogix/troubleshooting-error-codes) - the Status and Reason tables v2 decodes against
- [Local include and exclude groups](https://learn.microsoft.com/fslogix/concepts-include-exclude-groups)
- [Configure SMB Storage Permissions](https://learn.microsoft.com/fslogix/how-to-configure-storage-permissions)
- [Troubleshooting the FSLogix service](https://learn.microsoft.com/fslogix/troubleshooting-fslogix-service)
- [Release notes](https://learn.microsoft.com/fslogix/overview-release-notes)

## License

MIT - see [LICENSE](LICENSE).
