# [CRIT] Compromised AsyncAPI npm Packages Deliver Multi-Stage Botnet Malware

**Source:** The Hacker News
**Published:** 2026-07-15
**Article:** https://thehackernews.com/2026/07/compromised-asyncapi-npm-packages.html

## Threat Profile

Compromised AsyncAPI npm Packages Deliver Multi-Stage Botnet Malware 
 Ravie Lakshmanan  Jul 15, 2026 Malware / Software Security 
Four compromised npm packages in the @asyncapi namespace have been observed distributing a multi-stage botnet loader, according to findings from OX Security , SafeDep , Socket , and StepSecurity .
The affected packages are listed below -
@asyncapi/generator-helpers@1.1.1
@asyncapi/generator-components@0.7.1
@asyncapi/generator@3.3.1
@asyncapi/specs(v6.11.2, v6.11.2…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `85.137.53.71`
- **SHA256:** `34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1`
- **SHA256:** `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab`
- **SHA256:** `bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4`
- **SHA256:** `9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b`
- **SHA256:** `d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7`
- **SHA256:** `6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71`
- **SHA256:** `9e214f38537e69bf51c7fa1ddd35ae495e9cb897231ec010baf9e4f29407ee9a`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059.007** — JavaScript
- **T1105** — Ingress Tool Transfer
- **T1140** — Deobfuscate/Decode Files or Information
- **T1571** — Non-Standard Port
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1543.003** — Windows Service
- **T1204.002** — Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Install of compromised @asyncapi npm package versions (generator/helpers/components/specs)

`UC_93_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.exe","npm-cli.js","node.exe","yarn.exe","pnpm.exe","npm","yarn","pnpm")) AND (Processes.process IN ("*@asyncapi/generator-helpers@1.1.1*","*@asyncapi/generator-components@0.7.1*","*@asyncapi/generator@3.3.1*","*@asyncapi/specs@6.11.2*","*@asyncapi/specs@6.11.2-alpha.1*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe") or InitiatingProcessFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe")
| where ProcessCommandLine has_any ("@asyncapi/generator-helpers@1.1.1","@asyncapi/generator-components@0.7.1","@asyncapi/generator@3.3.1","@asyncapi/specs@6.11.2","@asyncapi/specs@6.11.2-alpha.1")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Node.js spawns detached background node fetching Miasma stage-2 from IPFS gatewa

`UC_93_9` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","npm.exe","node","npm")) AND Processes.process_name IN ("node.exe","node") AND (Processes.process="*ipfs.io/ipfs/*" OR Processes.process="*QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9*" OR Processes.process="*sync.js*") by Processes.dest Processes.user Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe")
| where FileName =~ "node.exe"
| where ProcessCommandLine has_any ("ipfs.io/ipfs/","QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9","sync.js")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### IPFS gateway fetch of Miasma stage-2 CID (ipfs.io/ipfs/QmQobZSp...)

`UC_93_10` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9*") by Web.src Web.dest Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9"
   or (RemoteUrl has "ipfs.io" and InitiatingProcessFileName in~ ("node.exe","npm.exe"))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Miasma sync.js loader dropped to OS-specific path by node and executed

`UC_93_11` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="sync.js" AND (Filesystem.file_path="*\\Temp\\*" OR Filesystem.file_path="*\\AppData\\*" OR Filesystem.file_path="*/.config/*" OR Filesystem.file_path="*/.cache/*" OR Filesystem.file_path="*/tmp/*" OR Filesystem.file_path="*node_modules*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where FileName =~ "sync.js"
| where InitiatingProcessFileName in~ ("node.exe","npm.exe")
| where FolderPath has_any (@"\Temp\", @"\AppData\", @"\node_modules\", @"\ProgramData\")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Miasma botnet C2 beacon to 85.137.53.71 on ports 8080/8081/8091

`UC_93_12` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="85.137.53.71" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.transport | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "85.137.53.71"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Conns=count(), Ports=make_set(RemotePort) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP
| order by FirstSeen desc
```

### Miasma persistence via Windows Run key or startup written by node/npm process

`UC_93_13` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\CurrentVersion\\Run*") AND (Registry.registry_value_data="*node*" OR Registry.registry_value_data="*sync.js*" OR Registry.registry_value_data="*\\Temp\\*" OR Registry.registry_value_data="*\\AppData\\*" OR Registry.registry_value_data="*ProgramData*") by Registry.dest Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.user | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\CurrentVersion\Run"
| where InitiatingProcessFileName in~ ("node.exe","npm.exe")
   or RegistryValueData has_any ("node","sync.js", @"\Temp\", @"\AppData\", "ProgramData")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Suspicious downloader child (powershell/cmd/curl) spawned by npm/node_modules

`UC_93_14` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","npm.exe","yarn.exe","pnpm.exe") OR Processes.parent_process="*node_modules*") AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","curl.exe","wget.exe","bash.exe","bitsadmin.exe","certutil.exe") AND (Processes.process="*http://*" OR Processes.process="*https://*" OR Processes.process="*ipfs.io*" OR Processes.process="*DownloadString*" OR Processes.process="*Invoke-WebRequest*" OR Processes.process="*FromBase64String*" OR Processes.process="*-enc*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe") or InitiatingProcessFolderPath has @"\node_modules\"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","curl.exe","wget.exe","bash.exe","bitsadmin.exe","certutil.exe")
| where ProcessCommandLine has_any ("http://","https://","ipfs.io","DownloadString","Invoke-WebRequest","FromBase64String","-enc","QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, ProcessCommandLine
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

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
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

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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

### Article-specific behavioural hunt — Compromised AsyncAPI npm Packages Deliver Multi-Stage Botnet Malware

`UC_93_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Compromised AsyncAPI npm Packages Deliver Multi-Stage Botnet Malware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","sync.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","sync.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Compromised AsyncAPI npm Packages Deliver Multi-Stage Botnet Malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "sync.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "sync.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `85.137.53.71`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1`, `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab`, `bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4`, `9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b`, `d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7`, `6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71`, `9e214f38537e69bf51c7fa1ddd35ae495e9cb897231ec010baf9e4f29407ee9a`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 15 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
