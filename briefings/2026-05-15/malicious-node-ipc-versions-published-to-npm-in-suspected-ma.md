# [CRIT] Malicious node-ipc versions published to npm in suspected maintainer account compromise

**Source:** Snyk
**Published:** 2026-05-15
**Article:** https://snyk.io/blog/malicious-node-ipc-versions-published-npm/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
May 15, 2026
0 mins read On May 14, 2026, multiple malicious versions of the popular npm package node-ipc were published to the npm registry. Current public reporting identifies node-ipc@9.1.6 , node-ipc@9.2.3 , and node-ipc@12.0.1 as compromised versions containing an obfuscated credential-stealing payload. The malicious code was added to the CommonJS bundle, node-ipc.cjs, and is triggered when the package is loaded through require("node-ipc")…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `37.16.75.69`
- **Domain (defanged):** `azurestaticprovider.net`
- **Domain (defanged):** `sh.azurestaticprovider.net`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1071.004** — Application Layer Protocol: DNS
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1074.001** — Data Staged: Local Data Staging
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1560.001** — Archive Collected Data: Archive via Utility

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound egress to node-ipc stealer infrastructure (azurestaticprovider[.]net / 37.16.75.69)

`UC_318_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app values(All_Traffic.process) as process values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic where (All_Traffic.dest="37.16.75.69" OR All_Traffic.dest_host="azurestaticprovider.net" OR All_Traffic.dest_host="sh.azurestaticprovider.net" OR All_Traffic.dest_host="*.azurestaticprovider.net") by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "37.16.75.69"
   or RemoteUrl has_any ("azurestaticprovider.net","sh.azurestaticprovider.net")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessParentFileName,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### DNS lookup for azurestaticprovider[.]net node-ipc exfil domain

`UC_318_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.query_type) as qtype values(DNS.answer) as answer from datamodel=Network_Resolution where DNS.query="azurestaticprovider.net" OR DNS.query="*.azurestaticprovider.net" by DNS.src DNS.query DNS.dest | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "azurestaticprovider.net"
   or RemoteUrl endswith ".azurestaticprovider.net"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count(),
            SampleProc=any(InitiatingProcessFileName),
            SampleCmd=any(InitiatingProcessCommandLine),
            SampleUser=any(InitiatingProcessAccountName)
            by DeviceName, RemoteUrl
| order by FirstSeen asc
```

### node-ipc stealer __ntw=1 environment marker in process command line

`UC_318_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process) as parent_cmd values(Processes.process_path) as proc_path from datamodel=Endpoint.Processes where Processes.process="*__ntw=1*" OR Processes.parent_process="*__ntw=1*" by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "__ntw=1"
   or InitiatingProcessCommandLine has "__ntw=1"
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Malicious node-ipc package landed on disk under node_modules

`UC_318_7` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_name="node-ipc.cjs" AND Filesystem.file_path="*node_modules*node-ipc*" AND Filesystem.action="created" by Filesystem.dest Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where firstTime >= relative_time(now(),"-30d@d") AND firstTime >= strptime("2026-05-14T00:00:00","%Y-%m-%dT%H:%M:%S") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp >= datetime(2026-05-14T00:00:00Z)
| where ActionType in ("FileCreated","FileModified")
| where FileName =~ "node-ipc.cjs"
| where FolderPath has "node_modules" and FolderPath has "node-ipc"
| project Timestamp, DeviceName, FolderPath, FileName, FileSize, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp asc
```

### node.js process staging credential dump in nt-* temp directory

`UC_318_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files dc(Filesystem.file_name) as file_count from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\Temp\\nt-*" OR Filesystem.file_path="*/tmp/nt-*" OR Filesystem.file_path="*/var/folders/*/T/nt-*") AND Filesystem.process_name IN ("node.exe","node") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where file_count >= 3 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath matches regex @"(?i)([\\/]Temp[\\/]nt-|/tmp/nt-|/var/folders/.+?/T/nt-)"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            DistinctFiles=dcount(FileName), SampleFiles=make_set(FileName, 25),
            TotalBytes=sum(FileSize)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, FolderPath
| where DistinctFiles >= 3
| order by FirstSeen asc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Malicious node-ipc versions published to npm in suspected maintainer account com

`UC_318_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Malicious node-ipc versions published to npm in suspected maintainer account com ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Malicious node-ipc versions published to npm in suspected maintainer account com
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/null") or FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `37.16.75.69`, `azurestaticprovider.net`, `sh.azurestaticprovider.net`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
