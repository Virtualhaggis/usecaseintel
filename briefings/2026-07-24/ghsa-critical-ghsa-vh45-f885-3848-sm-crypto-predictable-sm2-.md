# [CRIT] [GHSA / CRITICAL] GHSA-vh45-f885-3848: sm-crypto: Predictable SM2 key generation in Node.js: default RNG uses Math.random + wall clock

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-vh45-f885-3848

## Threat Profile

sm-crypto: Predictable SM2 key generation in Node.js: default RNG uses Math.random + wall clock

## Summary

`sm-crypto` (npm package **0.4.0**, the latest release, published 2026-01-20)
generates SM2 private keys and signing ephemeral scalars from a single
module-wide RNG instance (`src/sm2/utils.js`: `const rng = new SecureRandom()`).
`SecureRandom` is jsbn's PRNG, which seeds an **ARC4** stream from
`window.crypto.getRandomValues` when available. **In Node.js — sm-crypto's
primary runtime — `…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `6072e45733a4187791ec28ce906fef18c7d33c8529969e1a852833c4349cfc38`
- **SHA256:** `143268fa0939b4da09eab8c9a2e027a04555b6c433fef4f54fc5edd517c0a6b1`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-vh45-f885-3848: sm-crypto: Predictable SM2 key generation

`UC_14_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-vh45-f885-3848: sm-crypto: Predictable SM2 key generation ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","index.js","poc.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("node.js","index.js","poc.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-vh45-f885-3848: sm-crypto: Predictable SM2 key generation
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "index.js", "poc.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/null") or FileName in~ ("node.js", "index.js", "poc.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `6072e45733a4187791ec28ce906fef18c7d33c8529969e1a852833c4349cfc38`, `143268fa0939b4da09eab8c9a2e027a04555b6c433fef4f54fc5edd517c0a6b1`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
