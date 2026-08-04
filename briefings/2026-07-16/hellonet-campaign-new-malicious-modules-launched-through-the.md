# [CRIT] HelloNet campaign: new malicious modules launched through the ViPNet update system

**Source:** Securelist (Kaspersky)
**Published:** 2026-07-16
**Article:** https://securelist.com/tr/hellonet-vipnet/120700/

## Threat Profile

Threat Response 
Table of Contents
Persistence via the update system 
HelloInjector — a loader for additional malicious components 
HelloProxy — a tool for traffic proxying and launching new malicious payloads 
HelloBackdoor — a Rust-based backdoor for file system manipulations 
Attribution 
Recommendations 
Detection by Kaspersky solutions 
Indicators of Compromise 
UPD 16.07.2026: Added detection of the malicious activity using Kaspersky Managed Detection and Response.
UPD 16.07.2026: Added de…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `5.39.253.206`
- **IPv4 (defanged):** `176.32.34.135`
- **MD5:** `16c211c96735f2fae9361b89bd7a31bf`
- **MD5:** `1bfe2b9493128574907a8279256a8bcc`
- **MD5:** `f9eed2f0158dc98e7012fb809152209c`
- **MD5:** `6001829a128fe264b4403138700c11a8`
- **MD5:** `ee4ff46ddd8489e81447962f927bc3f6`
- **MD5:** `41c938b3cd7e55d4077e34976929b140`
- **MD5:** `b103cd21280b4061f88b2bcc51394894`
- **MD5:** `9f5606a0755bc633b9bd7db6d179c09e`
- **MD5:** `0cfdffc56f0fa325d0c4d24780b46597`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1027** — Obfuscated Files or Information
- **T1543.003** — Persistence (article-specific)
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1572** — Protocol Tunneling
- **T1021.004** — Remote Services: SSH
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1083** — File and Directory Discovery
- **T1005** — Data from Local System
- **T1571** — Non-Standard Port
- **T1090.001** — Proxy: Internal Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### HelloInjector DLL side-load: wtsapi32.dll dropped into ViPNet Update System dir

`UC_194_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="wtsapi32.dll" Filesystem.file_path="*InfoTeCS*VIPNet Update System*" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "wtsapi32.dll"
| where FolderPath has @"\InfoTeCS\VIPNet Update System\"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### HelloNet renamed-PuTTY reverse SSH tunnel to 5.39.253.206

`UC_194_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.process="* -R *" AND Processes.process="*5.39.253.206*") OR (Processes.process_name="frontpage.exe" AND Processes.process_path="*users*public*music*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where (ProcessCommandLine has "-R" and ProcessCommandLine has "5.39.253.206")
    or (FileName =~ "frontpage.exe" and FolderPath has @"\users\public\music\")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### HelloProxy C2-handler artifact: tesh4RPC.txt written to C:\Users\Public

`UC_194_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="tesh4RPC.txt" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "tesh4RPC.txt"
| project Timestamp, DeviceName, ActionType, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### HelloExecutor recon enumerating ViPNet Client/Administrator Export key stores

`UC_194_8` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*ViPNet Client\\Export*" OR Processes.process="*ViPNet Administrator\\kc\\Export*" OR Processes.process="*infotecs*Export*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where ProcessCommandLine contains @"ViPNet Client\Export"
    or ProcessCommandLine contains @"ViPNet Administrator\kc\Export"
    or (ProcessCommandLine has "infotecs" and ProcessCommandLine has "Export")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### HelloNet C2 egress to 5.39.253.206 / 176.32.34.135

`UC_194_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("5.39.253.206","176.32.34.135") by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("5.39.253.206", "176.32.34.135")
| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### HelloProxy listener: svchost.exe binding TCP 5003/5060

`UC_194_10` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (5003,5060) All_Traffic.process_name="svchost.exe" by All_Traffic.src All_Traffic.dest_port All_Traffic.process_name All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "ListeningConnectionCreated"
| where LocalPort in (5003, 5060)
| where InitiatingProcessFileName =~ "svchost.exe"
| project Timestamp, DeviceName, LocalPort, Protocol, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName
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

### Article-specific behavioural hunt — HelloNet campaign: new malicious modules launched through the ViPNet update syst

`UC_194_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — HelloNet campaign: new malicious modules launched through the ViPNet update syst ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("wtsapi32.dll","itcsrvup64.exe","frontpage.exe","itcsrvup.exe","puh.exe","store.exe","amgmt.dll","selfname.dll","amgmt.bat","insru.cmd","7z.exe","autoit3.exe","pagent.exe") OR Processes.process_path="*C:\users\public\tesh4RPC.txt*" OR Processes.process_path="*\ProgramData\Infotecs\ViPNet*" OR Processes.process_path="*C:\Users\Public\music*" OR Processes.process_path="*C:\users\public\music\frontpage.exe*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\users\public\tesh4RPC.txt*" OR Filesystem.file_path="*\ProgramData\Infotecs\ViPNet*" OR Filesystem.file_path="*C:\Users\Public\music*" OR Filesystem.file_path="*C:\users\public\music\frontpage.exe*" OR Filesystem.file_name IN ("wtsapi32.dll","itcsrvup64.exe","frontpage.exe","itcsrvup.exe","puh.exe","store.exe","amgmt.dll","selfname.dll","amgmt.bat","insru.cmd","7z.exe","autoit3.exe","pagent.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\SYSTEM\\CurrentControlSet\\Services\\AppMgmt\\Parameters*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — HelloNet campaign: new malicious modules launched through the ViPNet update syst
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("wtsapi32.dll", "itcsrvup64.exe", "frontpage.exe", "itcsrvup.exe", "puh.exe", "store.exe", "amgmt.dll", "selfname.dll", "amgmt.bat", "insru.cmd", "7z.exe", "autoit3.exe", "pagent.exe") or FolderPath has_any ("C:\users\public\tesh4RPC.txt", "\ProgramData\Infotecs\ViPNet", "C:\Users\Public\music", "C:\users\public\music\frontpage.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\users\public\tesh4RPC.txt", "\ProgramData\Infotecs\ViPNet", "C:\Users\Public\music", "C:\users\public\music\frontpage.exe") or FileName in~ ("wtsapi32.dll", "itcsrvup64.exe", "frontpage.exe", "itcsrvup.exe", "puh.exe", "store.exe", "amgmt.dll", "selfname.dll", "amgmt.bat", "insru.cmd", "7z.exe", "autoit3.exe", "pagent.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\SYSTEM\CurrentControlSet\Services\AppMgmt\Parameters")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `5.39.253.206`, `176.32.34.135`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `16c211c96735f2fae9361b89bd7a31bf`, `1bfe2b9493128574907a8279256a8bcc`, `f9eed2f0158dc98e7012fb809152209c`, `6001829a128fe264b4403138700c11a8`, `ee4ff46ddd8489e81447962f927bc3f6`, `41c938b3cd7e55d4077e34976929b140`, `b103cd21280b4061f88b2bcc51394894`, `9f5606a0755bc633b9bd7db6d179c09e` _(+1 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
