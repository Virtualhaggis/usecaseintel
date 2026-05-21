# [HIGH] Ultralytics AI Pwn Request Supply Chain Attack

**Source:** Snyk
**Published:** 2024-12-11
**Article:** https://snyk.io/blog/ultralytics-ai-pwn-request-supply-chain-attack/

## Threat Profile

Snyk Blog In this article
Written by Stephen Thoemmes 
December 11, 2024
0 mins read The ultralytics supply chain attack occurred in two distinct phases between December 4-7, 2024. In the first phase, two malicious versions were published to PyPI: version 8.3.41 was released on December 4 at 20:51 UTC and remained available for approximately 12 hours until its removal on December 5 at 09:15 UTC. Version 8.3.42 was published shortly after on December 5 at 12:47 UTC and was available for about one…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `d8daa0b26ae0c221aa4a8c20834c4dbfef2a9a14`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1203** — Exploitation for Client Execution
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Installation of poisoned Ultralytics PyPI package (v8.3.41 / 8.3.42 / 8.3.45 / 8.3.46)

`UC_1009_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip.exe","pip3.exe","python.exe","python3.exe","pip","pip3","python","python3") OR Processes.process IN ("*pip install*","*pip3 install*","*python -m pip install*")) AND Processes.process="*ultralytics*" AND (Processes.process="*8.3.41*" OR Processes.process="*8.3.42*" OR Processes.process="*8.3.45*" OR Processes.process="*8.3.46*") by Processes.user Processes.dest Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("pip.exe","pip3.exe","python.exe","python3.exe","pip","pip3","python","python3")
      or InitiatingProcessFileName in~ ("pip.exe","pip3.exe","python.exe","python3.exe"))
| where ProcessCommandLine has "ultralytics"
| where ProcessCommandLine has "install" or InitiatingProcessCommandLine has "install"
| where ProcessCommandLine matches regex @"(?i)ultralytics[^A-Za-z0-9]{0,40}8\.3\.(41|42|45|46)\b"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] GitHub Actions branch-name template injection — bash brace-expansion shell signature

`UC_1009_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*$({curl*" OR Processes.process="*${IFS}|${IFS}bash*" OR Processes.process="*${IFS}|${IFS}sh*") AND Processes.process="*${IFS}*" by Processes.user Processes.dest Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (ProcessCommandLine has "$({curl" or ProcessCommandLine has "$({wget" or InitiatingProcessCommandLine has "$({curl" or InitiatingProcessCommandLine has "$({wget")
| where ProcessCommandLine has "${IFS}" or InitiatingProcessCommandLine has "${IFS}"
| where ProcessCommandLine has_any ("|${IFS}bash","|${IFS}sh","${IFS}|${IFS}bash","${IFS}|${IFS}sh") or InitiatingProcessCommandLine has_any ("|${IFS}bash","|${IFS}sh","${IFS}|${IFS}bash","${IFS}|${IFS}sh")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Outbound fetch of file.sh via attacker-controlled commit d8daa0b... on raw.githubusercontent.com

`UC_1009_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
(| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url="*raw.githubusercontent.com*" AND Web.url="*d8daa0b26ae0c221aa4a8c20834c4dbfef2a9a14*" by Web.src Web.user Web.dest Web.url Web.http_method | `drop_dm_object_name(Web)`) | append [| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.process="*d8daa0b26ae0c221aa4a8c20834c4dbfef2a9a14*" by Processes.user Processes.dest Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let bad_commit = "d8daa0b26ae0c221aa4a8c20834c4dbfef2a9a14";
union isfuzzy=true
(DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "raw.githubusercontent.com"
| where RemoteUrl has bad_commit
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort),
(DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has bad_commit or InitiatingProcessCommandLine has bad_commit
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine)
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

### Article-specific behavioural hunt — Ultralytics AI Pwn Request Supply Chain Attack

`UC_1009_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Ultralytics AI Pwn Request Supply Chain Attack ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("run.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("run.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Ultralytics AI Pwn Request Supply Chain Attack
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("run.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("run.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `d8daa0b26ae0c221aa4a8c20834c4dbfef2a9a14`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
