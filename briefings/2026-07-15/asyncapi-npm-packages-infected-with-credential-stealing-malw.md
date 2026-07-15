# [HIGH] ​    ​AsyncAPI npm packages infected with credential-stealing malware

**Source:** BleepingComputer
**Published:** 2026-07-15
**Article:** https://www.bleepingcomputer.com/news/security/-asyncapi-npm-packages-infected-with-credential-stealing-malware/

## Threat Profile

​ ​AsyncAPI npm packages infected with credential-stealing malware 
By Bill Toulas 
July 15, 2026
11:37 AM
0 


Five malicious versions of AsyncAPI packages were published to the Node Package Manager (npm) in a supply-chain attack that delivered a remote access trojan with info-stealing capabilities.


The threat actor exploited a misconfigured GitHub Actions workflow and pushed trojanized packages in the @asyncapi namespace that had a cummulative weekly download count of more than 2.25 mill…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `85.137.53.71`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1105** — Ingress Tool Transfer
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1564.003** — Hide Artifacts: Hidden Window
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Malicious @asyncapi npm package versions installed (supply-chain compromise)

`UC_1_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*@asyncapi/specs@6.11.2*" OR Processes.process="*@asyncapi/generator@3.3.1*" OR Processes.process="*@asyncapi/generator-helpers@1.1.1*" OR Processes.process="*@asyncapi/generator-components@0.7.1*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "@asyncapi/"
| where ProcessCommandLine has_any ("@asyncapi/specs@6.11.2","@asyncapi/generator@3.3.1","@asyncapi/generator-helpers@1.1.1","@asyncapi/generator-components@0.7.1")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```

### Miasma second-stage 'NodeJS/sync.js' payload written to disk

`UC_1_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="sync.js" AND Filesystem.file_path="*NodeJS*") OR (Filesystem.file_name=".diag.enc" AND Filesystem.file_path="*.sys_cache*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FileName =~ "sync.js" and FolderPath has "NodeJS")
    or (FileName =~ ".diag.enc" and FolderPath has ".sys_cache")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Node.js spawns detached hidden 'node -e' child (AsyncAPI stager)

`UC_1_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node.exe","npm.exe") AND Processes.process_name="node.exe" AND (Processes.process="* -e *" OR Processes.process="*--eval*") by Processes.dest Processes.user Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | eval cmd_len=len(process) | where cmd_len>350 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe")
| where FileName =~ "node.exe"
| where ProcessCommandLine has " -e " or ProcessCommandLine has "--eval"
| extend CmdLen = strlen(ProcessCommandLine)
| where CmdLen > 350   // inline eval second-stage blob, not a short one-liner
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCommandLine, CmdLen
| order by Timestamp desc
```

### AsyncAPI Miasma C2 egress to 85.137.53.71 / IPFS / Ethereum fallback

`UC_1_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="85.137.53.71" AND All_Traffic.dest_port IN (8080,8081,8091) by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "85.137.53.71"
    or RemoteUrl has "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9"
    or RemoteUrl has "ethereum-rpc.publicnode.com"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `85.137.53.71`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
