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
- **T1071.004** — Application Layer Protocol: DNS
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1041** — Exfiltration Over C2 Channel
- **T1074.001** — Data Staged: Local Data Staging
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1106** — Native API
- **T1048.003** — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] node-ipc stealer C2 beacon — DNS/HTTPS to azurestaticprovider[.]net

`UC_49_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where Network_Resolution.DNS.query="*azurestaticprovider.net*" by Network_Resolution.DNS.src Network_Resolution.DNS.query Network_Resolution.DNS.answer Network_Resolution.DNS.dest 
| `drop_dm_object_name(DNS)`
| append [ | tstats summariesonly=t count from datamodel=Network_Traffic where Network_Traffic.All_Traffic.dest_ip="37.16.75.69" OR Network_Traffic.All_Traffic.dest="*azurestaticprovider.net*" by Network_Traffic.All_Traffic.src Network_Traffic.All_Traffic.dest Network_Traffic.All_Traffic.dest_ip Network_Traffic.All_Traffic.app Network_Traffic.All_Traffic.user 
| `drop_dm_object_name(All_Traffic)` ]
| sort - firstTime
```

**Defender KQL:**
```kql
let _ioc_domains = dynamic(["azurestaticprovider.net","sh.azurestaticprovider.net"]);
union isfuzzy=true
  (DeviceNetworkEvents
     | where Timestamp > ago(30d)
     | where RemoteUrl has "azurestaticprovider.net" or RemoteUrl has_any (_ioc_domains)
     | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol, ActionType),
  (DeviceEvents
     | where Timestamp > ago(30d)
     | where ActionType == "DnsQueryResponse"
     | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
     | where QueryName has "azurestaticprovider.net"
     | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, QueryName, ActionType)
| order by Timestamp desc
```

### [LLM] node-ipc stealer C2 — outbound connection to 37.16.75.69

`UC_49_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Network_Traffic.All_Traffic.dest_port) as ports values(Network_Traffic.All_Traffic.transport) as protocols values(Network_Traffic.All_Traffic.app) as apps values(Network_Traffic.All_Traffic.user) as users from datamodel=Network_Traffic where Network_Traffic.All_Traffic.dest_ip="37.16.75.69" by Network_Traffic.All_Traffic.src Network_Traffic.All_Traffic.src_ip Network_Traffic.All_Traffic.dest_ip
| `drop_dm_object_name(All_Traffic)`
| sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "37.16.75.69"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemotePort, Protocol, ActionType, LocalIP, LocalPort
| order by Timestamp desc
```

### [LLM] node-ipc stealer staging — files written to $TMPDIR/nt-* by node process

`UC_49_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as filenames from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/tmp/nt-*" OR Filesystem.file_path="*\\Temp\\nt-*" OR Filesystem.file_path="*\\AppData\\Local\\Temp\\nt-*") (Filesystem.process_name="node" OR Filesystem.process_name="node.exe" OR Filesystem.process_name="npm*" OR Filesystem.process_name="yarn*" OR Filesystem.process_name="pnpm*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where (FolderPath matches regex @"(?i)[\\/]tmp[\\/]nt-" 
      or FolderPath matches regex @"(?i)\\Temp\\nt-"
      or FolderPath matches regex @"(?i)\\AppData\\Local\\Temp\\nt-")
| where InitiatingProcessFileName in~ ("node.exe","node","npm.exe","yarn.exe","pnpm.exe","npx.exe","electron.exe")
   or InitiatingProcessParentFileName in~ ("node.exe","node")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA256, FileSize, ActionType
| order by Timestamp desc
```

### [LLM] node-ipc malicious payload marker — process or child launched with __ntw=1 environment flag

`UC_49_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process) as parent values(Processes.process_path) as path from datamodel=Endpoint.Processes where (Processes.process="*__ntw=1*" OR Processes.process="*__ntw =1*" OR Processes.parent_process="*__ntw=1*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "__ntw=1" 
   or ProcessCommandLine has "__ntw =1"
   or InitiatingProcessCommandLine has "__ntw=1"
   or InitiatingProcessCommandLine has "__ntw =1"
| project Timestamp, DeviceName, AccountName, ProcessId, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] node-ipc stealer DNS-port exfil — UDP/53 traffic originating from node process

`UC_49_8` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Network_Traffic.All_Traffic.dest_ip) as dest_ips values(Network_Traffic.All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic where Network_Traffic.All_Traffic.dest_port=53 Network_Traffic.All_Traffic.transport="udp" (Network_Traffic.All_Traffic.app="node" OR Network_Traffic.All_Traffic.app="node.exe" OR Network_Traffic.All_Traffic.process_name="node" OR Network_Traffic.All_Traffic.process_name="node.exe") by Network_Traffic.All_Traffic.src Network_Traffic.All_Traffic.user Network_Traffic.All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| where count > 5
| sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 53 and Protocol == "Udp"
| where InitiatingProcessFileName in~ ("node.exe","node","electron.exe")
   or InitiatingProcessParentFileName in~ ("node.exe","node")
| where RemoteIPType == "Public"
| summarize ConnCount = count(), 
            DistinctIPs = dcount(RemoteIP),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            SampleRemoteIPs = make_set(RemoteIP, 10),
            Cmd = any(InitiatingProcessCommandLine)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName
| where ConnCount > 5 or DistinctIPs > 2
| order by ConnCount desc
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

`UC_49_3` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
