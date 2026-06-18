# [CRIT] [GHSA / CRITICAL] GHSA-fq2m-6wqh-x44g: PraisonAI: Jobs API exposes agent-execution endpoints with no authentication

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-fq2m-6wqh-x44g

## Threat Profile

PraisonAI: Jobs API exposes agent-execution endpoints with no authentication

# praisonai: Jobs API exposes agent-execution endpoints with no authentication

**Researcher:** Kai Aizen — SnailSploit (@SnailSploit), Adversarial & Offensive Security Research 
**Target:** https://github.com/MervinPraison/PraisonAI

---

**Package:** `praisonai` on PyPI
**Affected version (empirically tested):** 4.6.48
**Components:**
- `praisonai.jobs.server.create_app` — `praisonai/jobs/server.py`
- `praisonai.jobs…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-40287`
- **CVE:** `CVE-2026-44334`
- **SHA256:** `10b5deab96686f276b8ad71fa4712e1e3d301e4c356812d5d0d595b2b9503ef3`
- **SHA256:** `869564d523c14624afefb211a2e7c6bf8a27b3356bd19a58927fcb5e1ebb014c`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-fq2m-6wqh-x44g: PraisonAI: Jobs API exposes agent-executi

`UC_30_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-fq2m-6wqh-x44g: PraisonAI: Jobs API exposes agent-executi ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("server.py","router.py","executor.py","poc.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("server.py","router.py","executor.py","poc.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-fq2m-6wqh-x44g: PraisonAI: Jobs API exposes agent-executi
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("server.py", "router.py", "executor.py", "poc.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("server.py", "router.py", "executor.py", "poc.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-40287`, `CVE-2026-44334`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `10b5deab96686f276b8ad71fa4712e1e3d301e4c356812d5d0d595b2b9503ef3`, `869564d523c14624afefb211a2e7c6bf8a27b3356bd19a58927fcb5e1ebb014c`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
