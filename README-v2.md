# FSLogix Health Check v2

`FSLogix-HealthCheck-v2.ps1`

A reference implementation for a native FSLogix health check inside Nerdio Manager
for Enterprise. It scores an FSLogix installation on a session host against
Microsoft's documented best practice and emits a weighted health score, an HTML
report and a machine-readable JSON document.

v1 (`FSLogix-HealthCheck.ps1`) is a good single-host troubleshooting script and
stays in this repo. v2 is what a product feature needs: a reviewable rule set,
a number an operations dashboard can trend, and output a fleet run can aggregate.

---

## What changed from v1

| | v1 | v2 |
|---|---|---|
| Checks | 14 | 47 (mode-dependent) |
| Result model | PASS/WARN/FAIL/INFO | plus a severity, a stable check ID, evidence, a recommendation, and a documentation link per check |
| Score | none | weighted 0-100 health score with a grade band |
| Output | HTML in `C:\ProgramData` | JSON (the source of truth) plus HTML rendered from it; both can be written to a UNC path so a whole host pool lands in one place |
| Remediation | `Read-Host` prompt per item, disabled under automation | `-Remediate` switch with an allow-list, `-RemediateOnly` filter and full `-WhatIf` support. Never prompts |
| Error handling | `$ErrorActionPreference = 'Stop'` globally, so one failure lost the whole report | every check is wrapped; a failing check degrades to one INFO row |
| Object-specific settings | not read | `ObjectSpecific\<SID>` overrides are enumerated and flagged, because machine-level values are not the effective values when they exist |
| Status / Reason codes | reported raw, undecoded | decoded against Microsoft's published Status and Reason tables |

### Bugs fixed from v1

- **Minifilter check.** `frxdrv` is a prefix of `frxdrvvt`, so v1's substring match
  reported `frxdrv` as loaded when only `frxdrvvt` was. v2 matches filter names exactly.
- **Global `ErrorActionPreference = 'Stop'`.** One unhandled error in any check aborted
  the run and no report was written.
- **Antivirus exclusion list was incomplete.** v1 checked 2 processes and 2 folders.
  Microsoft's documented list also covers three driver files, the per-user
  `AppData\Local\FSLogix` folder, the temp VHD/VHDX patterns, the Cloud Cache cache and
  proxy folders, and the container patterns on the share itself.

---

## What v2 checks

**Host context** - OS and build, multi-session, AVD agent, Entra and domain join state,
system drive free space.

**Install** - FSLogix present, and installed version against a configurable baseline.

**Configuration** - `Enabled`; `VHDLocations` versus `CCDLocations` exclusivity and the
multiple-`VHDLocations` trap Microsoft warns about; `VolumeType`; `SizeInMBs`;
`IsDynamic`; `DeleteLocalProfileWhenVHDShouldApply`; `FlipFlopProfileDirectoryName`;
`LockedRetryCount` and `LockedRetryInterval`; `ReAttachRetryCount` and
`ReAttachIntervalSeconds`; `ProfileType` against the AVD no-concurrent-connections rule;
`PreventLoginWithFailure`; `PreventLoginWithTempProfile`; `RoamIdentity` against the
device join state; `RoamSearch`; `AccessNetworkAsComputerObject` as a security finding;
`RedirXMLSourceFolder` including whether the XML exists and parses; ODFC container;
and `ObjectSpecific` SID overrides.

**Cloud Cache** (only when `CCDLocations` is set) - cache and proxy directory separation,
cache volume free space, `ClearCacheOnLogoff`, `HealthyProvidersRequiredForRegister`,
`HealthyProvidersRequiredForUnregister`, `CcdUnregisterTimeout`.

**Antivirus** - registered engines, and Microsoft's full documented exclusion list
compared against the live Windows Defender configuration, including the container
patterns for whichever share is actually configured. A folder exclusion is treated as
covering everything beneath it.

**Storage** - reachability on TCP 445 with a real 5-second timeout; write access as a
separate finding from reachability; free space against Microsoft's thresholds; Kerberos
encryption type on Azure Files ahead of the April 2026 Windows Server hardening change;
the two client-side Entra Kerberos settings Microsoft requires on Entra-joined hosts;
optional container-size-against-ceiling scan; stale lock files.

**Services** - `frxsvc` and `frxccds` state and start mode, and exact-match minifilter
driver checks.

**Groups** - the FSLogix local include and exclude groups and their membership. An empty
include group means no user on the host is processed by FSLogix at all.

**Runtime** - every recorded session's Status and Reason decoded against Microsoft's
tables; `.bak` ProfileList keys and `C:\Users\TEMP` as evidence of a temporary-profile
event; unexpected local profile folders; Error-level FSLogix events in the last 7 days
grouped by event ID; whether FSLogix text logging is on.

---

## The health score

Each check carries a severity. Critical weighs 10, High 6, Medium 3, Low 1. A PASS earns
the full weight, a WARN half, a FAIL none. Informational rows weigh 0 and are excluded.

| Score | Grade |
|---|---|
| 95-100 | Healthy |
| 85-94 | Good |
| 70-84 | Needs attention |
| 50-69 | At risk |
| below 50 | Critical |

The score is designed to be trended per host pool over time, not read as an absolute.
A host can score 85 and still have a critical failure, so `summary.criticalFails` is
reported separately and rendered at the top of the HTML report.

---

## Usage

Read-only, the default:

```powershell
.\FSLogix-HealthCheck-v2.ps1
```

Write both outputs to a share so a whole host pool aggregates in one place:

```powershell
.\FSLogix-HealthCheck-v2.ps1 -ReportPath \\fileserver\fslogix-health -Quiet
```

JSON only, for a fleet run:

```powershell
.\FSLogix-HealthCheck-v2.ps1 -JsonOnly -JsonPath \\fileserver\fslogix-health -Quiet
```

Preview what remediation would change, without changing it:

```powershell
.\FSLogix-HealthCheck-v2.ps1 -Remediate -WhatIf
```

Apply only two specific fixes:

```powershell
.\FSLogix-HealthCheck-v2.ps1 -Remediate -RemediateOnly CFG-VOLUMETYPE,CFG-PREVENTTEMP
```

Include the container size scan (walks the share, so it is off by default):

```powershell
.\FSLogix-HealthCheck-v2.ps1 -ScanContainers -MaxContainersToScan 1000
```

### Parameters

| Parameter | Purpose |
|---|---|
| `-ReportPath` | Directory for the HTML report. Accepts a UNC path. |
| `-JsonPath` | Directory for the JSON document. Defaults to `-ReportPath`. |
| `-JsonOnly` | Skip HTML rendering. |
| `-Remediate` | Apply allow-listed fixes. Supports `-WhatIf` and `-Confirm`. |
| `-RemediateOnly` | Restrict remediation to the named check IDs. |
| `-ScanContainers` | Enumerate containers on the share and compare size to `SizeInMBs`. |
| `-MaxContainersToScan` | Cap on that enumeration. The cap is reported in the finding, never silently applied. |
| `-MinimumFSLogixVersion` | Version baseline for the agent-version check. |
| `-Quiet` | Suppress the console table. |

---

## Remediation safety

`-Remediate` is off by default and applies only to an explicit allow-list of registry
values plus the Defender exclusion list. It honours `-WhatIf` and `-Confirm`, it never
prompts, and every applied change is recorded in `remediation.applied` in the JSON and
marked on the HTML row.

Two things are deliberately never auto-remediated:

- **`DeleteLocalProfileWhenVHDShouldApply`.** Setting this to 1 permanently deletes a
  user's existing local profile at their next sign-in. It is reported, never applied.
- **Anything under `ObjectSpecific`.** Those overrides exist because someone made a
  decision; a health check should surface them, not overwrite them.

---

## JSON contract

The JSON document is the source of truth. HTML is a rendering of it.

```
schemaVersion   "2.0"
generatedUtc    ISO 8601
durationMs      int
host            { computerName, osCaption, osVersion, isMultiSession,
                  isAvdHost, entraJoined, domainJoined, systemDriveFreeGB }
fslogix         { installed, version, baselineVersion,
                  mode: Standard | CloudCache | Unconfigured, storageRoot }
summary         { healthScore, grade, pass, warn, fail, info, criticalFails[] }
remediation     { requested, applied[ { Id, Path, Name, Value } ] }
checks[]        { id, category, name, status, severity, weight, detail,
                  evidence, recommendation, reference, fixable,
                  fixApplied, fixError }
```

`id` is stable across runs and versions. It is the key to join findings across a host
pool, trend a single rule over time, or target `-RemediateOnly`.

---

## Running as an NME scripted action

The header comments are already in NME's scripted-action format, so the file uploads as
a Windows (CustomScript) scripted action and runs against a host pool unchanged. The
script writes a single summary line to standard output for NME to capture:

```
FSLogix Health Check v2.0 | HOST01 | Score 73.6/100 (Needs attention) | 24 pass, 12 warn, 4 fail, 7 info | Critical: AV-EXCLUSIONS | JSON: \\fileserver\fslogix-health\FSLogix-HealthCheck-HOST01-20260901-140233.json
```

There is no NME dependency. It runs the same way as a plain `.ps1` anywhere else.

---

## Compatibility notes

Windows PowerShell 5.1, no external modules, must run elevated.

The script avoids three things that break in this context, and the reasons are in the
code comments so they survive a refactor:

- **No here-strings.** The NME scripted-action delivery wrapper re-serializes them.
- **No `(if ...)` as an argument expression.** It parses under 5.1 and then fails at
  runtime with "the term 'if' is not recognized".
- **No nested `[ordered]` hashtable literals, and no `@(...)` around a generic List
  inside one.** Both throw "Argument types do not match" under 5.1.

---

## Validation

Verified on a real AVD session host (Windows 11 multi-session, FSLogix 3.25.822.19044)
across four configurations:

| Configuration | Result |
|---|---|
| FSLogix installed, unconfigured | 37 checks, score 64.1, 3 critical failures correctly identified |
| Standard mode, unreachable share | 41 checks, score 78.6; reachability PASS and write FAIL correctly separated |
| Cloud Cache, two providers, `HealthyProvidersRequiredForUnregister` deliberately 0 | 47 checks, score 73.1, that setting correctly raised as a critical failure |
| `-Remediate -RemediateOnly` with two IDs | exactly those two values changed, Defender untouched, `remediation.applied` correct |

`-Remediate -WhatIf` was confirmed to change nothing.

---

## Known limits

- **Third-party antivirus cannot be verified.** Windows exposes no way to read another
  vendor's exclusion list locally. Where Defender is not the engine, the script says so
  and points at the full list to check by hand.
- **The storage back end is out of scope.** Share-side antivirus exclusions, share and
  NTFS permissions for real user accounts, and storage throughput cannot be observed
  from a session host. A host-side pass does not prove the share is correct, and the
  report says so.
- **A scripted action runs as SYSTEM.** The share write test therefore proves computer
  account access, not user access. The finding states this.
- **The version baseline is a parameter, not a live lookup.** The script never claims to
  know the current release. `-MinimumFSLogixVersion` defaults to 3.26.126.19110
  (FSLogix 26.01 CU1, 10 February 2026) and needs updating as Microsoft ships.

---

## Sources

Every rule traces to current Microsoft Learn documentation:

- [Prerequisites, including the antivirus exclusion list](https://learn.microsoft.com/fslogix/overview-prerequisites)
- [Configuration Setting Reference](https://learn.microsoft.com/fslogix/reference-configuration-settings)
- [Configuration examples](https://learn.microsoft.com/fslogix/concepts-configuration-examples) - the recommended-value tables the score is built on
- [FSLogix Codes and what they mean](https://learn.microsoft.com/fslogix/troubleshooting-error-codes)
- [Local include and exclude groups](https://learn.microsoft.com/fslogix/concepts-include-exclude-groups)
- [Configure SMB Storage Permissions](https://learn.microsoft.com/fslogix/how-to-configure-storage-permissions)
- [Release notes](https://learn.microsoft.com/fslogix/overview-release-notes)
