# [CRIT] DAEMON Tools Supply Chain Attack Compromises Official Installers with Malware

**Source:** The Hacker News
**Published:** 2026-05-05
**Article:** https://thehackernews.com/2026/05/daemon-tools-supply-chain-attack.html

## Threat Profile

DAEMON Tools Supply Chain Attack Compromises Official Installers with Malware 
 Ravie Lakshmanan  May 05, 2026 Endpoint Security / Software Security 
A newly identified supply chain attack targeting DAEMON Tools software has compromised its installers to serve a malicious payload, according to findings from Kaspersky.
"These installers are distributed from the legitimate website of DAEMON Tools and are signed with digital certificates belonging to DAEMON Tools developers," Kaspersky researcher…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33626`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-3854`
- **Domain (defanged):** `env-check.daemontools.cc`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1218** — System Binary Proxy Execution
- **T1105** — Ingress Tool Transfer
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] DAEMON Tools trojanized binary beacons to env-check.daemontools.cc / 38.180.107.76

`UC_49_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest_host values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app IN ("DTHelper.exe","DiscSoftBusServiceLite.exe","DTShellHlp.exe") OR All_Traffic.process_name IN ("DTHelper.exe","DiscSoftBusServiceLite.exe","DTShellHlp.exe")) AND (All_Traffic.dest_ip="38.180.107.76" OR All_Traffic.dest="env-check.daemontools.cc" OR All_Traffic.dest="*.daemontools.cc") by All_Traffic.src All_Traffic.user host All_Traffic.app | `drop_dm_object_name(All_Traffic)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as query values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where DNS.query="env-check.daemontools.cc" OR DNS.query="*.daemontools.cc" by DNS.src host | `drop_dm_object_name(DNS)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _badDomain = "env-check.daemontools.cc";
let _badIP = "38.180.107.76";
let _daemonBins = dynamic(["DTHelper.exe","DiscSoftBusServiceLite.exe","DTShellHlp.exe"]);
union isfuzzy=true
  (DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where (RemoteUrl has _badDomain or RemoteIP == _badIP)
        or (InitiatingProcessFileName in~ (_daemonBins) and not(ipv4_is_private(RemoteIP)))
    | where InitiatingProcessFileName in~ (_daemonBins) or RemoteIP == _badIP or RemoteUrl has _badDomain
    | project Timestamp, DeviceName, EvidenceTable="DeviceNetworkEvents",
              InitiatingProcessFileName, InitiatingProcessSHA256,
              ParentVersion=InitiatingProcessVersionInfoProductVersion,
              RemoteIP, RemoteUrl, RemotePort, Protocol, ActionType),
  (DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tostring(parse_json(AdditionalFields).QueryName)
    | where Q has "daemontools.cc"
    | project Timestamp, DeviceName, EvidenceTable="DnsQueryResponse",
              InitiatingProcessFileName, InitiatingProcessSHA256,
              ParentVersion="", RemoteIP="", RemoteUrl=Q, RemotePort=int(0), Protocol="DNS", ActionType)
| order by Timestamp desc
```

### [LLM] DAEMON Tools binary spawns cmd.exe / PowerShell (implant shell-command stage)

`UC_49_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_hash) as child_hash values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("DTHelper.exe","DiscSoftBusServiceLite.exe","DTShellHlp.exe") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","conhost.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("DTHelper.exe","DiscSoftBusServiceLite.exe","DTShellHlp.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe")
| project Timestamp, DeviceName, AccountName,
          ParentProcess = InitiatingProcessFileName,
          ParentVersion = InitiatingProcessVersionInfoProductVersion,
          ParentSHA256  = InitiatingProcessSHA256,
          ParentCmd     = InitiatingProcessCommandLine,
          ChildProcess  = FileName,
          ChildCmd      = ProcessCommandLine,
          ChildSHA256   = SHA256
| order by Timestamp desc
```

### [LLM] DAEMON Tools second-stage payload drop: envchk.exe / cdg.exe / cdg.tmp by name or SHA1

`UC_49_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where (Processes.process_name IN ("envchk.exe","cdg.exe") OR Processes.process_hash="2d4eb55b01f59c62c6de9aacba9b47267d398fe4") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.file_hash) as hash from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("envchk.exe","cdg.exe","cdg.tmp") OR Filesystem.file_hash="2d4eb55b01f59c62c6de9aacba9b47267d398fe4") by Filesystem.dest Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _envchk_sha1 = "2d4eb55b01f59c62c6de9aacba9b47267d398fe4";
let _names = dynamic(["envchk.exe","cdg.exe","cdg.tmp"]);
let _daemonBins = dynamic(["DTHelper.exe","DiscSoftBusServiceLite.exe","DTShellHlp.exe","cmd.exe"]);
union isfuzzy=true
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ (_names) or SHA1 =~ _envchk_sha1
    | project Timestamp, DeviceName, AccountName, EvidenceTable="Process",
              FileName, FolderPath, SHA1, SHA256, ProcessCommandLine,
              ParentName=InitiatingProcessFileName,
              ParentCmd=InitiatingProcessCommandLine,
              GrandparentName=InitiatingProcessParentFileName),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("FileCreated","FileModified","FileRenamed")
    | where FileName in~ (_names) or SHA1 =~ _envchk_sha1
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, EvidenceTable="File",
              FileName, FolderPath, SHA1, SHA256,
              ProcessCommandLine=InitiatingProcessCommandLine,
              ParentName=InitiatingProcessFileName,
              ParentCmd=InitiatingProcessCommandLine,
              GrandparentName=InitiatingProcessParentFileName)
| extend ChainConfidence = iff(ParentName in~ (_daemonBins) or GrandparentName in~ (_daemonBins), "High - chained from DAEMON Tools", "Medium - name/hash hit only")
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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

### Article-specific behavioural hunt — DAEMON Tools Supply Chain Attack Compromises Official Installers with Malware

`UC_49_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — DAEMON Tools Supply Chain Attack Compromises Official Installers with Malware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("dthelper.exe","discsoftbusservicelite.exe","dtshellhlp.exe","envchk.exe","cdg.exe","conhost.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("dthelper.exe","discsoftbusservicelite.exe","dtshellhlp.exe","envchk.exe","cdg.exe","conhost.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — DAEMON Tools Supply Chain Attack Compromises Official Installers with Malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("dthelper.exe", "discsoftbusservicelite.exe", "dtshellhlp.exe", "envchk.exe", "cdg.exe", "conhost.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("dthelper.exe", "discsoftbusservicelite.exe", "dtshellhlp.exe", "envchk.exe", "cdg.exe", "conhost.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `env-check.daemontools.cc`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
