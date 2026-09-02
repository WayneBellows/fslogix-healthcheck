# FSLogix Health Check

> **Public preview — 0.1.0.** Tested on a real AVD session host across several
> configurations, but **not yet across a range of customer environments**. Treat findings
> as advice to verify, not instructions to apply. The JSON schema may change before 1.0.
> See [Road to 1.0](#road-to-10).

A single PowerShell script that audits an FSLogix installation on a Windows session host
(AVD, RDS, or any Windows Server / 10 / 11 multi-user box) against Microsoft's documented
best practice, scores it, and reports what it finds in plain English.

**It is strictly read-only.** It never writes to the host.

Built for AVD and EUC admins who want a fast, trustworthy answer to "is FSLogix actually
set up right on this box?" — whether that is day one of a deployment, or troubleshooting
a "my profile didn't roam" ticket.

```powershell
.\FSLogix-HealthCheck.ps1
```

---

## What it checks

47 checks, mode-dependent. Every one carries a stable ID, a severity, the evidence it
found, a recommendation, and a link to the Microsoft page it came from.

**Host context** — OS and build, multi-session, AVD agent, Entra and domain join state,
system drive free space.

**Install** — FSLogix present, and installed version against a configurable baseline.

**Configuration** — `Enabled`; `VHDLocations` versus `CCDLocations` exclusivity and the
multiple-`VHDLocations` trap Microsoft warns about; `VolumeType`; `SizeInMBs`;
`IsDynamic`; `DeleteLocalProfileWhenVHDShouldApply`; `FlipFlopProfileDirectoryName`;
`LockedRetryCount` and `LockedRetryInterval`; `ReAttachRetryCount` and
`ReAttachIntervalSeconds`; `ProfileType` against the AVD no-concurrent-connections rule;
`PreventLoginWithFailure`; `PreventLoginWithTempProfile`; `RoamIdentity` against the
device join state; `RoamSearch`; `AccessNetworkAsComputerObject` as a security finding;
`RedirXMLSourceFolder` including whether the XML exists and parses; ODFC container; and
`ObjectSpecific` SID overrides — which mean the machine-level values are *not* the
effective values for those users.

**Cloud Cache** (only when `CCDLocations` is set) — cache and proxy directory separation,
cache volume free space, `ClearCacheOnLogoff`, `HealthyProvidersRequiredForRegister`,
`HealthyProvidersRequiredForUnregister`, `CcdUnregisterTimeout`.

**Antivirus** — registered engines, and Microsoft's full documented exclusion list
compared against the live Windows Defender configuration, including the container
patterns for whichever share is actually configured. A folder exclusion is treated as
covering everything beneath it.

**Storage** — reachability on TCP 445 with a real timeout; write access as a separate
finding from reachability; free space against Microsoft's thresholds; Kerberos encryption
type on Azure Files ahead of the April 2026 Windows Server hardening change; the two
client-side Entra Kerberos settings Microsoft requires on Entra-joined hosts; optional
container-size-against-ceiling scan; stale lock files.

**Services** — `frxsvc` and `frxccds` state and start mode, and exact-match minifilter
driver checks.

**Groups** — the FSLogix local include and exclude groups and their membership. An empty
include group means no user on the host is processed by FSLogix at all.

**Runtime** — every recorded session's Status and Reason decoded against Microsoft's
published tables; `.bak` ProfileList keys and `C:\Users\TEMP` as evidence of a
temporary-profile event; unexpected local profile folders; Error-level FSLogix events in
the last 7 days grouped by event ID; whether FSLogix text logging is on.

---

## The health score

Each check carries a severity. Critical weighs 10, High 6, Medium 3, Low 1. A PASS earns
the full weight, a WARN half, a FAIL none. Informational rows weigh 0 and are excluded.

| Score | Grade |
|---|---|
| 95–100 | Healthy |
| 85–94 | Good |
| 70–84 | Needs attention |
| 50–69 | At risk |
| below 50 | Critical |

The score is for trending per host pool over time, not for reading as an absolute. A host
can score 85 and still have a critical failure, so `summary.criticalFails` is reported
separately and rendered at the top of the HTML report.

Every numeric judgement lives in one `$Thresholds` table at the top of the file, so the
whole set is visible at once and one value can be changed without hunting through the
script. Values taken from Microsoft's guidance are marked as such; the rest are this
script's own judgement and are open to argument.

---

## Usage

Read-only, the default:

```powershell
.\FSLogix-HealthCheck.ps1
```

Write both outputs to a share so a whole host pool aggregates in one place:

```powershell
.\FSLogix-HealthCheck.ps1 -ReportPath \\fileserver\fslogix-health -Quiet
```

JSON only, for a fleet run:

```powershell
.\FSLogix-HealthCheck.ps1 -JsonOnly -JsonPath \\fileserver\fslogix-health -Quiet
```

Include the container size scan, which walks the share and is off by default:

```powershell
.\FSLogix-HealthCheck.ps1 -ScanContainers -MaxContainersToScan 1000
```

### Parameters

| Parameter | Purpose |
|---|---|
| `-ReportPath` | Directory for the HTML report. Accepts a UNC path. |
| `-JsonPath` | Directory for the JSON document. Defaults to `-ReportPath`. |
| `-JsonOnly` | Skip HTML rendering. |
| `-ScanContainers` | Enumerate containers on the share and compare size to `SizeInMBs`. |
| `-MaxContainersToScan` | Cap on that enumeration. Reported in the finding, never applied silently. |
| `-ShareScanDepth` | Directory levels to descend on the share. Default 2, which reaches every container in the standard layout. |
| `-MinimumFSLogixVersion` | Version baseline for the agent-version check. |
| `-Quiet` | Suppress the console table. |

### Requirements

- Windows PowerShell 5.1 (built into Windows Server 2016 and later, Windows 10 and later). No external modules.
- Run elevated. The checks read HKLM, services, Defender preferences and event logs.
- FSLogix installed on the host being checked.

---

## Why there is no remediation

The script never writes to the host. That is a design decision, not a missing feature.

Unattended registry changes across a session host fleet need change control, batching, a
rollback path and an audit trail. A community script has none of those, and a half-safe
fix engine is worse than an honest report. Two findings make the point:

- **`DeleteLocalProfileWhenVHDShouldApply`.** Setting this to 1 permanently deletes a
  user's existing local profile at their next sign-in.
- **Antivirus exclusions.** Adding exclusions changes a host's security posture. That
  belongs in a change record, not in a script someone downloaded.

Instead, every finding with a known correction carries a machine-readable `remediation`
block in the JSON, so whatever *does* have change control can act on it:

```json
{
  "id": "CFG-VOLUMETYPE",
  "remediationAvailable": true,
  "remediation": {
    "Path": "HKLM:\\SOFTWARE\\FSLogix\\Profiles",
    "Name": "VolumeType",
    "Value": "VHDX",
    "Type": "String"
  }
}
```

Two shapes exist. Registry findings use `{ Path, Name, Value, Type }`. The antivirus
finding uses `{ Kind: "DefenderExclusions", Processes[], Paths[] }`, because it is not a
single value.

---

## JSON contract

The JSON document is the source of truth. HTML is a rendering of it.

```
toolVersion     e.g. "0.1.0"
schemaVersion   "1.0"
generatedUtc    ISO 8601
durationMs      int
readOnly        always true
host            { computerName, osCaption, osVersion, isMultiSession,
                  isAvdHost, entraJoined, domainJoined, systemDriveFreeGB }
fslogix         { installed, version, baselineVersion,
                  mode: Standard | CloudCache | Unconfigured, storageRoot }
summary         { healthScore, grade, pass, warn, fail, info, criticalFails[] }
checks[]        { id, category, name, status, severity, weight, detail,
                  evidence, recommendation, reference,
                  remediationAvailable, remediation }
```

`id` is stable across runs and versions. It is the key to join findings across a host
pool or trend a single rule over time. `toolVersion` and `schemaVersion` are versioned
independently: the tool can change without breaking a consumer, and any schema change
increments `schemaVersion` and is recorded in [CHANGELOG.md](CHANGELOG.md).

---

## Deliberate design decisions

These are choices, not omissions. Raised in review, and answered here so they need not be
re-litigated.

**One file, no dependencies.** The whole thing is a single `.ps1` with no modules and no
external templates. That is what lets it be pasted into an RMM console, a scripted action
or a remote shell and just run. A template-based HTML generator or an external rules file
would each add a second file that has to travel with it.

**No plugin interface, no `-CustomCheckPath`.** Adding a check means editing the script.
For a single-file community tool that is the right trade. A pluggable rule registry, an
externalised rule set and per-organisation overrides belong in a management platform,
where there is a backend to hold them.

**Partly table-driven, and it says so.** Simple recommended-value rules run through
`Test-RecommendedSetting`. Checks needing real logic are written out. This is not a fully
data-driven rule engine and does not claim to be one.

**HTML is generated in PowerShell, without here-strings.** Here-strings do not survive
being re-serialised by some scripted-action delivery wrappers, so the report is built
with a `StringBuilder`. Uglier to read, works everywhere.

**Errors are isolated per check.** A failing check degrades to a single INFO row saying
it could not complete, and never aborts the run. An operator with 46 answers and one
stated gap is better served than one with none.

**A failed detection is never reported as a negative result.** If `dsregcmd` cannot be
read, the host is reported as "join state could not be determined" — not as a workgroup
machine — and the two checks that depend on join state say they could not be evaluated
rather than quietly returning the wrong verdict.

---

## Road to 1.0

0.1.0 becomes 1.0 when:

- It has run in a spread of real customer environments, not just a lab — Standard and
  Cloud Cache, Azure Files and ANF, AD-joined and Entra-joined, and at least one
  third-party antivirus.
- The JSON schema has held across those runs without a breaking change.
- A Pester suite covers the pure functions: version comparison, path parsing, exclusion
  coverage matching, the score arithmetic and the Status/Reason decode tables.
- A sample HTML report from a real environment ships in the repo. One is deliberately
  absent at 0.1.0 rather than publishing a sample generated on a lab host that was
  misconfigured on purpose.

Findings from real environments are the most useful thing anyone can contribute. Open an
issue with the JSON, minus anything you would rather not share.

---

## Known limits

- **Third-party antivirus cannot be verified.** Windows exposes no way to read another
  vendor's exclusion list locally. Where Defender is not the engine, the script says so
  and names the full list to check by hand.
- **The storage back end is out of scope.** Share-side antivirus exclusions, share and
  NTFS permissions for real user accounts, and storage throughput cannot be observed from
  a session host. A host-side pass does not prove the share is correct, and the report
  says so.
- **Running as SYSTEM proves computer-account access, not user access.** Run as a
  scheduled task or a scripted action, the share write test reflects the machine account.
  The finding states this.
- **The version baseline is a parameter, not a live lookup.** The script never claims to
  know the current release. `-MinimumFSLogixVersion` defaults to 3.26.126.19110
  (FSLogix 26.01 CU1, 10 February 2026) and needs updating as Microsoft ships.
- **One host, one moment.** Estate-wide comparison, and checking whether the
  configuration intended by a management platform actually reached the host, are beyond
  what a single-host script can do.

---

## Running as a scripted action

The `#description`, `#execution mode` and `#tags` header comments are in Nerdio Manager
scripted-action format, so the file uploads as a Windows (CustomScript) scripted action
and runs against a host pool unchanged. This is optional — there is no dependency, and it
runs the same way as a plain `.ps1` anywhere else.

It writes a single summary line to standard output for the calling automation to capture:

```
FSLogix Health Check 0.1.0 | HOST01 | Score 73.6/100 (Needs attention) | 24 pass, 12 warn, 4 fail, 7 info | Critical: AV-EXCLUSIONS | JSON: \\fileserver\fslogix-health\FSLogix-HealthCheck-HOST01-20260902-140233.json
```

---

## Sources

Every check traces to current Microsoft Learn FSLogix documentation:

- [Prerequisites, including the antivirus exclusion list](https://learn.microsoft.com/fslogix/overview-prerequisites)
- [Configuration Setting Reference](https://learn.microsoft.com/fslogix/reference-configuration-settings)
- [Configuration examples](https://learn.microsoft.com/fslogix/concepts-configuration-examples) — the recommended-value tables the score is built on
- [FSLogix Codes and what they mean](https://learn.microsoft.com/fslogix/troubleshooting-error-codes) — the Status and Reason tables the script decodes against
- [Local include and exclude groups](https://learn.microsoft.com/fslogix/concepts-include-exclude-groups)
- [Configure SMB Storage Permissions](https://learn.microsoft.com/fslogix/how-to-configure-storage-permissions)
- [Troubleshooting the FSLogix service](https://learn.microsoft.com/fslogix/troubleshooting-fslogix-service)
- [Release notes](https://learn.microsoft.com/fslogix/overview-release-notes)

## Contributing

Issues and pull requests welcome. The most valuable contributions at 0.1.0 are findings
from real environments, and corrections where a rule misreads Microsoft's guidance. Every
rule should be traceable to a documentation page — if one is not, that is a bug.

## Licence

MIT — see [LICENSE](LICENSE).
