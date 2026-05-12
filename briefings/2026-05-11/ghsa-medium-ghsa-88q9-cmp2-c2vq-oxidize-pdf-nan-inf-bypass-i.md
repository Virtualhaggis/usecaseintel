# [MED] [GHSA / MEDIUM] GHSA-88q9-cmp2-c2vq: oxidize-pdf: NaN/inf bypass in colour content-stream emission causes PDF rejection (DoS)

**Source:** GitHub Security Advisories
**Published:** 2026-05-11
**Article:** https://github.com/advisories/GHSA-88q9-cmp2-c2vq

## Threat Profile

oxidize-pdf: NaN/inf bypass in colour content-stream emission causes PDF rejection (DoS)

### Impact

  `oxidize-pdf` defines `Color` as a `pub enum` with public tuple-struct variants `Rgb(f64, f64, f64)`, `Gray(f64)`, and `Cmyk(f64, f64, f64, f64)`. The constructors `Color::rgb`, `Color::gray`, and `Color::cmyk` clamp incoming
  components to `[0.0, 1.0]`, but because the variants are `pub`, callers can construct values directly without going through the constructors:

  ```rust
  let safe   = …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — [GHSA / MEDIUM] GHSA-88q9-cmp2-c2vq: oxidize-pdf: NaN/inf bypass in colour conte

`UC_89_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / MEDIUM] GHSA-88q9-cmp2-c2vq: oxidize-pdf: NaN/inf bypass in colour conte ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("pdf.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("pdf.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / MEDIUM] GHSA-88q9-cmp2-c2vq: oxidize-pdf: NaN/inf bypass in colour conte
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("pdf.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("pdf.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
