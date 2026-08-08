# [CRIT] Anthropic's Fever Dream: Claude's package that stole real keys

**Source:** Aikido
**Published:** 2026-07-31
**Article:** https://www.aikido.dev/blog/anthropic-rogue-agents-package-stole-keys

## Threat Profile

Blog Vulnerabilities & Threats Anthropic's Fever Dream: Claude's package that stole real keys Anthropic's Fever Dream: Claude's package that stole real keys Anthropic disclosed that one of its own agents published live malware to PyPI and compromised a real third-party company in the process. I went looking, and I might have found the package it left behind.
Written by Charlie Eriksen Published on: Jul 31, 2026 Dear internet,
It’s been a rough week. It’s festival season, and I apparently ate som…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `enqqnvvtgrnyl.x.pipedream.net`
- **SHA256:** `4ae13303fa1663a36cfaa70bebe77b52b12dbf17eef24db15c6c24c631d38fbf`
- **SHA256:** `f3e103a8a230b5fb3066fb0a9eb7f5fdf5831d4c7b71a9d83de54d8d6673eae2`
- **SHA256:** `ff4126bd465ae6de09a2eaa94a4fd2d7d385a5dae2c093372668d4b7ecb81633`
- **SHA256:** `584ef638a5415f4eccf6645abbcd06198e9abecf8b75cbd9328aa58962d9b38b`
- **MD5:** `7df12487bade710459ccea2d3570cdbc`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1204.003** — User Execution: Malicious Image
- **T1005** — Data from Local System
- **T1074.001** — Data Staged: Local Data Staging
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1567** — Exfiltration Over Web Service
- **T1041** — Exfiltration Over C2 Channel
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Malicious 'anthropickit' PyPI package installed via pip (supply-chain cred stealer)

`UC_118_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.Processes.process="*anthropickit*" AND (Endpoint.Processes.process_name IN ("pip","pip3","python","python3") OR Endpoint.Processes.process IN ("*pip install*","*pip3 install*","*setup.py*","*-m pip*")) by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.parent_process_name Endpoint.Processes.process_name Endpoint.Processes.process | `drop_dm_object_name(Endpoint.Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "anthropickit" or InitiatingProcessCommandLine has "anthropickit"
| where FileName has_any ("pip","pip3","python","python3") or ProcessCommandLine has_any ("pip install","setup.py","-m pip")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### anthropickit loot file '/tmp/runner_exfil.json' written to disk

`UC_118_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Endpoint.Filesystem.file_name="runner_exfil.json" OR Endpoint.Filesystem.file_path="/tmp/runner_exfil.json") by Endpoint.Filesystem.dest Endpoint.Filesystem.file_path Endpoint.Filesystem.file_name Endpoint.Filesystem.process_id Endpoint.Filesystem.action | `drop_dm_object_name(Endpoint.Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where FileName =~ "runner_exfil.json" or FolderPath has "/tmp/runner_exfil.json"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### anthropickit exfiltration POST to Pipedream endpoint (enqqnvvtgrnyl.x.pipedream.net)

`UC_118_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*enqqnvvtgrnyl.x.pipedream.net*" OR Web.dest="*pipedream.net*" OR Web.url="*pipedream.net*") AND (Web.app IN ("python","python3","pip","pip3") OR Web.http_method="POST") by Web.src Web.dest Web.url Web.http_method Web.app Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "pipedream.net" or RemoteUrl has "enqqnvvtgrnyl"
| where InitiatingProcessFileName has_any ("python","python3","pip","pip3") or InitiatingProcessCommandLine has_any ("setup.py","pip install")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

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

### Article-specific behavioural hunt — Anthropic's Fever Dream: Claude's package that stole real keys

`UC_118_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Anthropic's Fever Dream: Claude's package that stole real keys ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("setup.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/runner_exfil.json*" OR Filesystem.file_name IN ("setup.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Anthropic's Fever Dream: Claude's package that stole real keys
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("setup.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/runner_exfil.json") or FileName in~ ("setup.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `enqqnvvtgrnyl.x.pipedream.net`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `4ae13303fa1663a36cfaa70bebe77b52b12dbf17eef24db15c6c24c631d38fbf`, `f3e103a8a230b5fb3066fb0a9eb7f5fdf5831d4c7b71a9d83de54d8d6673eae2`, `ff4126bd465ae6de09a2eaa94a4fd2d7d385a5dae2c093372668d4b7ecb81633`, `584ef638a5415f4eccf6645abbcd06198e9abecf8b75cbd9328aa58962d9b38b`, `7df12487bade710459ccea2d3570cdbc`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
