# [MED] Hackers Abuse Microsoft Fondue.exe to Side-Load APPWIZ.cpl and Execute Malware

**Source:** Cyber Security News
**Published:** 2026-06-18
**Article:** https://cybersecuritynews.com/hackers-abuse-microsoft-fondue-exe/

## Threat Profile

A newly uncovered attack campaign has brought a rarely scrutinized Windows executable into the spotlight. Threat actors are actively abusing Fondue.exe, a legitimate Microsoft utility built into the Windows operating system, to side-load a malicious control panel file named APPWIZ.cpl and silently deploy dangerous malware on victim machines. The technique is deceptively clever because it relies entirely on [&#8230;] The post Hackers Abuse Microsoft Fondue.exe to Side-Load APPWIZ.cpl and Execute …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `chinagreenenergy.org`
- **Domain (defanged):** `gcl-power.org`
- **SHA256:** `a8ecbd9c049044ca4990a0e5960d19ce782a3b42d7763e9693d7c91ead24a0b7`
- **SHA256:** `914da75a4ad6d70db856a2bc318d8828f28894622f017ee78d470b4794faafa6`
- **SHA256:** `a5e448af73b0ff6b6fcfe6ef7808120e1fd7e5c4c9b4edd68e1c980e5ea3406b`
- **SHA256:** `7099c33933716c00c1f4bdb0281c230b981c76b23d7d1c83abc6f58968267d54`
- **SHA256:** `56d656d684077e7b3231393f5464447cdc8eea81b6415c5f010bc52f0c8cb317`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Hackers Abuse Microsoft Fondue.exe to Side-Load APPWIZ.cpl and Execute Malware

`UC_15_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Abuse Microsoft Fondue.exe to Side-Load APPWIZ.cpl and Execute Malware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("fondue.exe","appwiz.cpl"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("fondue.exe","appwiz.cpl"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Abuse Microsoft Fondue.exe to Side-Load APPWIZ.cpl and Execute Malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("fondue.exe", "appwiz.cpl"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("fondue.exe", "appwiz.cpl"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `chinagreenenergy.org`, `gcl-power.org`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `a8ecbd9c049044ca4990a0e5960d19ce782a3b42d7763e9693d7c91ead24a0b7`, `914da75a4ad6d70db856a2bc318d8828f28894622f017ee78d470b4794faafa6`, `a5e448af73b0ff6b6fcfe6ef7808120e1fd7e5c4c9b4edd68e1c980e5ea3406b`, `7099c33933716c00c1f4bdb0281c230b981c76b23d7d1c83abc6f58968267d54`, `56d656d684077e7b3231393f5464447cdc8eea81b6415c5f010bc52f0c8cb317`


## Why this matters

Severity classified as **MED** based on: IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
