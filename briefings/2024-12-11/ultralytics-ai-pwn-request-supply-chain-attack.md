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

- **Domain (defanged):** `connect.consrensys.com`
- **Domain (defanged):** `webhook.site/ecd706a0-f207-4df2-b639-d326ef3c2fe1`
- **Domain (defanged):** `webhook.site/1e6c12e8-aaeb-4349-98ad-a7196e632c5a`
- **SHA256:** `b6ea1681855ec2f73c643ea2acfcf7ae084a9648f888d4bd1e3e119ec15c3495`
- **SHA256:** `15bcffd83cda47082acb081eaf7270a38c497b3a2bc6e917582bda8a5b0f7bab`
- **SHA256:** `f08d47cb3e1e848b5607ac44baedf1754b201b6b90dfc527d6cefab1dd2d2c23`
- **SHA256:** `e9d538203ac43e9df11b68803470c116b7bb02881cd06175b0edfc4438d4d1a2`
- **SHA256:** `6a9d121f538cad60cabd9369a951ec4405a081c664311a90537f0a7a61b0f3e5`
- **SHA256:** `c9c3401536fd9a0b6012aec9169d2c1fc1368b7073503384cfc0b38c47b1d7e1`
- **SHA256:** `4347625838a5cb0e9d29f3ec76ed8365b31b281103b716952bf64d37cf309785`
- **SHA256:** `ec12cd32729e8abea5258478731e70ccc5a7c6c4847dde78488b8dd0b91b8555`
- **SHA256:** `b0e1ae6d73d656b203514f498b59cbcf29f067edf6fbd3803a3de7d21960848d`
- **SHA1:** `ee304a92a9e68e7923d7a37a370c7556ac596250`
- **SHA1:** `7c6136cf4e857582c2f086673359be94e7e4b702`
- **SHA1:** `dd0577b10e73792f2b2315af63b872fe4123ec9c`
- **SHA1:** `bea3060707e6f3fec47aa2af64ea2e774b56e9f5`
- **SHA1:** `059beed5bcdfea16c05b4d45560c97abfd4af3de`
- **SHA1:** `a1f1e3ede7c7e6ae650a294630214ce7fa596255`
- **SHA1:** `62b6532384bdd9b96af5ac684d87f52efb48f7de`
- **SHA1:** `96f496ac5c64f3c884676dd99d6edbe7fa596255`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
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

### Installation of poisoned Ultralytics PyPI package (v8.3.41 / 8.3.42 / 8.3.45 / 8.3.46)

`UC_1094_4` · phase: **install** · confidence: **High** · AI-generated for this article

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

### GitHub Actions branch-name template injection — bash brace-expansion shell signature

`UC_1094_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

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

### Outbound fetch of file.sh via attacker-controlled commit d8daa0b... on raw.githubusercontent.com

`UC_1094_6` · phase: **c2** · confidence: **High** · AI-generated for this article

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

`UC_1094_3` · phase: **exploit** · confidence: **High**

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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `connect.consrensys.com`, `webhook.site/ecd706a0-f207-4df2-b639-d326ef3c2fe1`, `webhook.site/1e6c12e8-aaeb-4349-98ad-a7196e632c5a`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `b6ea1681855ec2f73c643ea2acfcf7ae084a9648f888d4bd1e3e119ec15c3495`, `15bcffd83cda47082acb081eaf7270a38c497b3a2bc6e917582bda8a5b0f7bab`, `f08d47cb3e1e848b5607ac44baedf1754b201b6b90dfc527d6cefab1dd2d2c23`, `e9d538203ac43e9df11b68803470c116b7bb02881cd06175b0edfc4438d4d1a2`, `6a9d121f538cad60cabd9369a951ec4405a081c664311a90537f0a7a61b0f3e5`, `c9c3401536fd9a0b6012aec9169d2c1fc1368b7073503384cfc0b38c47b1d7e1`, `4347625838a5cb0e9d29f3ec76ed8365b31b281103b716952bf64d37cf309785`, `ec12cd32729e8abea5258478731e70ccc5a7c6c4847dde78488b8dd0b91b8555` _(+9 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
