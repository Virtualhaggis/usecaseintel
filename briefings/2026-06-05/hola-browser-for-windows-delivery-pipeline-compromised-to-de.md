# [HIGH] Hola Browser for Windows Delivery Pipeline Compromised to Deliver Cryptominer

**Source:** Cyber Security News
**Published:** 2026-06-05
**Article:** https://cybersecuritynews.com/hola-browser-for-windows-delivery-pipeline-compromised/

## Threat Profile

A trusted browser application has landed at the center of a supply chain security incident after researchers discovered that its official delivery pipeline had been quietly compromised. Hola Browser for Windows, used by millions of users around the world, was found distributing an unexpected executable file alongside its legitimate installer. The file, named me.exe, was [&#8230;] The post Hola Browser for Windows Delivery Pipeline Compromised to Deliver Cryptominer appeared first on Cyber Securi…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `174086534a2de730058465a4a4e231ce3778ab17ebebfd7f62b3bf9750bc7bdb`
- **SHA256:** `e3541caf708c075f0bb22fc68b03acd8457fea7cf0732ea935b1eb016d1c7721`
- **SHA1:** `8046735d354814bf9ef9a053cb9cad8cfec261f2`
- **MD5:** `8462f61e68b37d220eab2462b3cbcec8`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — Hola Browser for Windows Delivery Pipeline Compromised to Deliver Cryptominer

`UC_15_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hola Browser for Windows Delivery Pipeline Compromised to Deliver Cryptominer ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("me.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("me.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hola Browser for Windows Delivery Pipeline Compromised to Deliver Cryptominer
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("me.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("me.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `174086534a2de730058465a4a4e231ce3778ab17ebebfd7f62b3bf9750bc7bdb`, `e3541caf708c075f0bb22fc68b03acd8457fea7cf0732ea935b1eb016d1c7721`, `8046735d354814bf9ef9a053cb9cad8cfec261f2`, `8462f61e68b37d220eab2462b3cbcec8`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
