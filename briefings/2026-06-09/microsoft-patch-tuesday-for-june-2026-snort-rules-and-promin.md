# [CRIT] Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilities

**Source:** Cisco Talos
**Published:** 2026-06-09
**Article:** https://blog.talosintelligence.com/microsoft-patch-tuesday-for-june-2026-snort-rules-and-prominent-vulnerabilities/

## Threat Profile

Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilities 
By 
Chetan Raghuprasad 
Tuesday, June 9, 2026 17:21
Patch Tuesday
Microsoft has released its monthly security update for June 2026, which includes 206 vulnerabilities affecting a range of products, including 32 that Microsoft marked as “critical”. 
Out of 32 "critical" entries, 28 are remote code execution (RCE) vulnerabilities in Microsoft Windows services and applications including Windows Active Directory, Wind…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-42985`
- **CVE:** `CVE-2026-47291`
- **CVE:** `CVE-2026-44803`
- **CVE:** `CVE-2026-44812`
- **CVE:** `CVE-2026-42992`
- **CVE:** `CVE-2026-44799`
- **CVE:** `CVE-2026-44801`
- **CVE:** `CVE-2026-47289`
- **CVE:** `CVE-2026-48563`
- **CVE:** `CVE-2026-45607`
- **CVE:** `CVE-2026-45641`
- **CVE:** `CVE-2026-47652`
- **CVE:** `CVE-2026-45657`
- **CVE:** `CVE-2026-48574`
- **CVE:** `CVE-2026-42987`
- **CVE:** `CVE-2026-44815`
- **CVE:** `CVE-2026-45456`
- **CVE:** `CVE-2026-45458`
- **CVE:** `CVE-2026-47635`
- **CVE:** `CVE-2026-45461`
- **CVE:** `CVE-2026-45463`
- **CVE:** `CVE-2026-45472`
- **CVE:** `CVE-2026-45474`
- **CVE:** `CVE-2026-45476`
- **CVE:** `CVE-2026-44810`
- **CVE:** `CVE-2026-47644`
- **CVE:** `CVE-2026-26142`
- **CVE:** `CVE-2026-32193`
- **CVE:** `CVE-2026-45648`
- **CVE:** `CVE-2026-47288`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1543.003** — Persistence (article-specific)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilitie

`UC_201_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilitie ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("http.sys"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("http.sys"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilitie
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("http.sys"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("http.sys"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-42985`, `CVE-2026-47291`, `CVE-2026-44803`, `CVE-2026-44812`, `CVE-2026-42992`, `CVE-2026-44799`, `CVE-2026-44801`, `CVE-2026-47289` _(+22 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
