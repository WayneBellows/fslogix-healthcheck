# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The tool version and the JSON `schemaVersion` are versioned independently. A consumer of
the JSON only needs to care about `schemaVersion`; any change to it is called out below
under **Schema**.

---

## [0.2.0] — 2026-11-17

**Schema:** `1.1` — additive. Two new top-level fields, `configuration` and `drift`. No
existing field changed, so a 1.0 consumer keeps working.

### Added

- `-BaselinePath`: compares this host's FSLogix registry configuration against a JSON
  result from a reference host and adds a `DRIFT-CONFIG` row. Order inside `VHDLocations`
  and `CCDLocations` is significant; comparison is otherwise case-insensitive. The row has
  severity Info, so it never moves the health score.
- `configuration` in the JSON: every value under the FSLogix `Profiles`, `ODFC` and `Apps`
  keys as `"Key\\ValueName": "string"`, so any result can later be a baseline.
- `-SummariseFolder` (with optional `-ExpectedHosts`): a pool summary built from a folder
  of JSON results. Newest result per host; version below baseline; stale results; settings
  that differ between hosts; findings across the pool; missing hosts; unreadable files.
  Runs no host checks.

### Security

- Storage account keys and SAS signatures (`AccountKey=`, `SharedAccessSignature=`,
  `sig=`) in Cloud Cache connection strings are replaced by a short SHA-256 fingerprint in
  the `configuration` section and in the `CCDLocations` evidence. The JSON and HTML never
  hold the secret; drift can still tell that two hosts use different keys. The evidence
  redaction also fixes 0.1.0, which printed `CCDLocations` as it was.
- The pool summary treats result files as untrusted input: every value is HTML-escaped, a
  `generatedUtc` later than the file's own write time is capped to that time, and a result
  whose host differs from its file name is flagged at the top of the page.

### Changed

- `-MinimumFSLogixVersion` default raised to 3.26.826.17182 (FSLogix 26.08, published
  31 August 2026). Hosts on 26.01 CU1 now get a version warning.

## [0.1.0] — 2026-09-02

First public release. Public preview: tested on a real AVD session host across several
configurations, but not yet across a range of customer environments.

**Schema:** `1.0` — first published JSON contract.

### Added

- 47 checks across nine categories: host context, install, configuration, Cloud Cache,
  antivirus, storage, services, groups and runtime.
- Severity-weighted 0–100 health score with a grade band. Critical failures reported
  separately from the score.
- Machine-readable JSON output as the source of truth, with the HTML report rendered from
  it. Both can be written to a UNC path so a host pool aggregates in one place.
- Stable check IDs, so a finding can be joined across hosts and trended over time.
- Advisory `remediation` block per finding, describing the change that would correct it
  without applying it.
- Microsoft's full documented antivirus exclusion list, including driver files, per-user
  folders, temp VHD patterns, Cloud Cache folders and share-side container patterns.
- `ObjectSpecific` SID override detection, which determines whether the machine-level
  settings are the effective settings at all.
- The six Cloud Cache resilience settings, including
  `HealthyProvidersRequiredForUnregister`, which Microsoft explicitly warns against
  setting to 0.
- FSLogix local include and exclude group membership.
- Temporary and orphaned profile detection via `.bak` ProfileList keys and
  `C:\Users\TEMP`.
- Entra Kerberos client-side settings check on Entra-joined hosts using Azure Files.
- Session Status and Reason codes decoded against Microsoft's published tables.
- All numeric judgements collected into one `$Thresholds` table at the top of the file.
- `-ShareScanDepth` to bound share enumeration. Default 2, which reaches every container
  in the standard layout.

### Changed

- **Strictly read-only.** The script contains no write operation. An earlier draft had a
  `-Remediate` switch; it was removed because unattended registry changes across a fleet
  need change control, batching, a rollback path and an audit trail, none of which a
  community script can offer.
- Single script. The earlier two-script layout (`FSLogix-HealthCheck.ps1` plus a `-v2`
  variant) is gone; there is one script and it is this one.

### Fixed

Carried over from the pre-release drafts, recorded because they are real defects someone
building something similar would hit:

- **Minifilter check used a substring match.** `frxdrv` is a prefix of `frxdrvvt`, so
  `frxdrv` was reported as loaded when only `frxdrvvt` was present. Now an exact name
  match.
- **`$ErrorActionPreference = 'Stop'` was set globally.** One unhandled error in any
  check aborted the whole run and no report was written. Each check is now isolated and
  degrades to a single INFO row.
- **A `dsregcmd` failure was indistinguishable from a workgroup machine.** The host was
  silently reported as "Workgroup / unknown", and two checks that branch on join state
  (`CFG-ROAMIDENTITY`, `STG-ENTRAKERB`) then returned a verdict based on a value that had
  never been read. The script now confirms `dsregcmd` reported the fields, and where it
  did not, says so and marks the dependent checks as not evaluated.
- **Unbounded `-Recurse` over the container share.** Replaced with a bounded `-Depth`,
  which is both correct for the standard container layout and much faster.
- **A false PASS on lock files.** An unreadable share returned zero files and was
  reported as "no lock files found". It now proves the path is enumerable first.
- Six occurrences of `Microsoft s` instead of `Microsoft's` in report text, caused by
  avoiding apostrophes inside single-quoted PowerShell strings.
- Kerberos encryption-type bit tests now use named constants rather than bare integers.

### Known issues

- Third-party antivirus exclusion lists cannot be read locally; only Windows Defender can
  be verified.
- No test suite yet. Planned for 1.0 — see [Road to 1.0](README.md#road-to-10).
- No sample report in the repo yet, deliberately. One will ship with 1.0 from a real
  environment rather than from a lab host misconfigured on purpose.

### Windows PowerShell 5.1 notes

Three constructs parse cleanly under 5.1 and then fail at runtime. They are avoided, and
commented in the source so they are not reintroduced:

- `SomeFunction (if ($x) { 'a' } else { 'b' })` as an argument expression
- a nested `[ordered]` hashtable literal inside another
- `@(...)` around an empty generic `List` inside an `[ordered]` literal

Here-strings are also avoided throughout, because some scripted-action delivery wrappers
re-serialise them and break the script.

[0.2.0]: https://github.com/WayneBellows/fslogix-healthcheck/releases/tag/v0.2.0
[0.1.0]: https://github.com/WayneBellows/fslogix-healthcheck/releases/tag/v0.1.0
