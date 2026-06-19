# [MED] Hackers Abuse Microsoft Fondue.exe to Side-Load APPWIZ.cpl and Execute Malware

**Source:** Cyber Security News
**Published:** 2026-06-18
**Article:** https://cybersecuritynews.com/hackers-abuse-microsoft-fondue-exe/

## Threat Profile

A newly uncovered attack campaign has brought a rarely scrutinized Windows executable into the spotlight. Threat actors are actively abusing&#160;Fondue.exe, a legitimate Microsoft utility built into the Windows operating system, to side-load a malicious control panel file named&#160;APPWIZ.cpl&#160;and silently deploy dangerous malware on victim machines. The technique is deceptively clever because it relies entirely on [&#8230;] The post Hackers Abuse Microsoft Fondue.exe to Side-Load APPWIZ.c…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `curtainbeatdisturbance.com`
- **Domain (defanged):** `stardebug.app`
- **Domain (defanged):** `alphafly-drones.com`
- **Domain (defanged):** `newfolder.click`
- **SHA256:** `df1d20e392f7b7c5c408bdda317e0733e5ec27a973e3bf75034c6566343aa67f`
- **SHA256:** `677c5ad47c8feaf6a5c0b084060347bcf48f0ccadcdf951b3d48553f4520feaa`
- **SHA256:** `82254b86590762b2946c6584db35d3872a5d6b85d30e8c07adb95de2126a4f97`
- **SHA256:** `a20870bee771efe1ea01761d7978cc7b68b0a3c32c617675464f9c4dbe0a5d66`
- **SHA256:** `88ebed34ab9ff0e16dc32b789fc25295ea570f86244e89cb68803c517597cfdd`
- **SHA256:** `3d280f5bb4e1eba8c1a65c7d17411286f7b3dbe7db48130f7d5a3be421ffc2ae`
- **SHA256:** `34db59b663c15cd03cdd92bf24bdff25b756dd51f0540fecaac2a0cab47480ae`
- **SHA256:** `996df9ce30ace63c0c516cbacfa4e308b555a2d2c44c9d6550b543b9fccc845d`
- **SHA256:** `09c83fc5f1656cc4be749c64bfc53d2ef612c9b79dc3937b8bb137754c82216a`
- **SHA256:** `688a1dc207ead232cb8ae6f67fcca1cf7892d83a01af024c404e636cb6ba4cb2`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Hackers Abuse Microsoft Fondue.exe to Side-Load APPWIZ.cpl and Execute Malware

`UC_23_2` · phase: **exploit** · confidence: **High**

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
  - IP / domain IOC(s): `curtainbeatdisturbance.com`, `stardebug.app`, `alphafly-drones.com`, `newfolder.click`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `df1d20e392f7b7c5c408bdda317e0733e5ec27a973e3bf75034c6566343aa67f`, `677c5ad47c8feaf6a5c0b084060347bcf48f0ccadcdf951b3d48553f4520feaa`, `82254b86590762b2946c6584db35d3872a5d6b85d30e8c07adb95de2126a4f97`, `a20870bee771efe1ea01761d7978cc7b68b0a3c32c617675464f9c4dbe0a5d66`, `88ebed34ab9ff0e16dc32b789fc25295ea570f86244e89cb68803c517597cfdd`, `3d280f5bb4e1eba8c1a65c7d17411286f7b3dbe7db48130f7d5a3be421ffc2ae`, `34db59b663c15cd03cdd92bf24bdff25b756dd51f0540fecaac2a0cab47480ae`, `996df9ce30ace63c0c516cbacfa4e308b555a2d2c44c9d6550b543b9fccc845d` _(+2 more)_


## Why this matters

Severity classified as **MED** based on: IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
