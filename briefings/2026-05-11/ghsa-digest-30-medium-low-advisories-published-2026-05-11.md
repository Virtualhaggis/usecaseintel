# [MED] [GHSA / DIGEST] 30 medium/low advisories published 2026-05-11

**Source:** GitHub Security Advisories
**Published:** 2026-05-11
**Article:** https://github.com/advisories?published=2026-05-11&severity=medium,low&type=reviewed

## Threat Profile

Daily roundup of 30 medium- and low-severity GitHub Security Advisories reviewed on 2026-05-11. Individual high-severity advisories still get their own cards.

- [MEDIUM] CVE-2026-33052: MantisBT Has Authorization Bypass in Global Profile Creation  (affects: composer:mantisbt/mantisbt (vuln >= 2.28.0, < 2.28.2))
- [MEDIUM] CVE-2026-34390: MantisBT Vulnerable to Privilege Escalation from Manager to Administrator  (affects: composer:mantisbt/mantisbt (vuln <= 2.28.1))
- [MEDIUM] CVE-2026-34579: Ma…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33052`
- **CVE:** `CVE-2026-34390`
- **CVE:** `CVE-2026-34579`
- **CVE:** `CVE-2026-34744`
- **CVE:** `CVE-2026-34754`
- **CVE:** `CVE-2026-34970`
- **CVE:** `CVE-2026-39960`
- **CVE:** `CVE-2026-40598`
- **CVE:** `CVE-2026-41148`
- **CVE:** `CVE-2026-41149`
- **CVE:** `CVE-2026-41150`
- **CVE:** `CVE-2026-41159`
- **CVE:** `CVE-2026-41897`
- **CVE:** `CVE-2026-42070`
- **CVE:** `CVE-2026-43979`
- **CVE:** `CVE-2026-44353`
- **CVE:** `CVE-2026-44475`
- **CVE:** `CVE-2026-44571`
- **CVE:** `CVE-2026-44576`
- **CVE:** `CVE-2026-44577`
- **CVE:** `CVE-2026-44580`
- **CVE:** `CVE-2026-44581`
- **CVE:** `CVE-2026-44972`
- **CVE:** `CVE-2026-45046`
- **CVE:** `CVE-2026-6420`
- **CVE:** `CVE-2026-44474`
- **CVE:** `CVE-2026-44572`
- **CVE:** `CVE-2026-44582`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — [GHSA / DIGEST] 30 medium/low advisories published 2026-05-11

`UC_100_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / DIGEST] 30 medium/low advisories published 2026-05-11 ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("pdf_service.py","next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("pdf_service.py","next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / DIGEST] 30 medium/low advisories published 2026-05-11
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("pdf_service.py", "next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("pdf_service.py", "next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33052`, `CVE-2026-34390`, `CVE-2026-34579`, `CVE-2026-34744`, `CVE-2026-34754`, `CVE-2026-34970`, `CVE-2026-39960`, `CVE-2026-40598` _(+20 more)_


## Why this matters

Severity classified as **MED** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
