# [HIGH] Microsoft Patch Tuesday for April 2026 - Snort Rule and Prominent Vulnerabilities

**Source:** Cisco Talos
**Published:** 2026-04-14
**Article:** https://blog.talosintelligence.com/microsoft-patch-tuesday-april-2026/

## Threat Profile

Microsoft Patch Tuesday for April 2026 - Snort Rule and Prominent Vulnerabilities 
By 
Nick Biasini 
Tuesday, April 14, 2026 16:27
Patch Tuesday
Microsoft has released its monthly security update for April 2026, which includes 165 vulnerabilities affecting a wide range of products, including eight Microsoft marked as “critical.” 
CVE-2026-23666 is a critical Denial of Service (DoS) vulnerability that affects the .NET framework. Successful exploitation could allow the attacker to deny service ove…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-23666`
- **CVE:** `CVE-2026-32157`
- **CVE:** `CVE-2026-32190`
- **CVE:** `CVE-2026-33114`
- **CVE:** `CVE-2026-33115`
- **CVE:** `CVE-2026-33824`
- **CVE:** `CVE-2026-33826`
- **CVE:** `CVE-2026-33827`
- **CVE:** `CVE-2026-32201`
- **CVE:** `CVE-2026-0390`
- **CVE:** `CVE-2026-26151`
- **CVE:** `CVE-2026-26169`
- **CVE:** `CVE-2026-26173`
- **CVE:** `CVE-2026-26177`
- **CVE:** `CVE-2026-26182`
- **CVE:** `CVE-2026-27906`
- **CVE:** `CVE-2026-27908`
- **CVE:** `CVE-2026-27909`
- **CVE:** `CVE-2026-27913`
- **CVE:** `CVE-2026-27914`
- **CVE:** `CVE-2026-27921`
- **CVE:** `CVE-2026-27922`
- **CVE:** `CVE-2026-32070`
- **CVE:** `CVE-2026-32075`
- **CVE:** `CVE-2026-32093`
- **CVE:** `CVE-2026-32152`
- **CVE:** `CVE-2026-32154`
- **CVE:** `CVE-2026-32155`
- **CVE:** `CVE-2026-32162`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-32225`
- **CVE:** `CVE-2026-33825`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Microsoft Patch Tuesday for April 2026 - Snort Rule and Prominent Vulnerabilitie

`UC_133_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft Patch Tuesday for April 2026 - Snort Rule and Prominent Vulnerabilitie ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("tdx.sys","fdwsd.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("tdx.sys","fdwsd.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Microsoft Patch Tuesday for April 2026 - Snort Rule and Prominent Vulnerabilitie
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("tdx.sys", "fdwsd.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("tdx.sys", "fdwsd.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-23666`, `CVE-2026-32157`, `CVE-2026-32190`, `CVE-2026-33114`, `CVE-2026-33115`, `CVE-2026-33824`, `CVE-2026-33826`, `CVE-2026-33827` _(+24 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
