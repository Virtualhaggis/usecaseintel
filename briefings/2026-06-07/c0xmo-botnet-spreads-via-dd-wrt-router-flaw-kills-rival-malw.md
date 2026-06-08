# [HIGH] C0XMO botnet spreads via DD-WRT router flaw, kills rival malware

**Source:** BleepingComputer
**Published:** 2026-06-07
**Article:** https://www.bleepingcomputer.com/news/security/c0xmo-botnet-spreads-via-dd-wrt-router-flaw-kills-rival-malware/

## Threat Profile

C0XMO botnet spreads via DD-WRT router flaw, kills rival malware 
By Bill Toulas 
June 7, 2026
10:17 AM
0 
A new variant of the Gafgyt botnet called C0XMO is targeting DD-WRT router firmware and can move to other device types with various CPU architectures.
The researchers found samples for ARM, MIPS, PowerPC, SuperH, x86, x86_64, and other architectures, featuring exploits for DVRs, routers, video management platforms, and Android-based devices.
The botnet was seen targeting a Japanese technolo…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-27137`
- **CVE:** `CVE-2015-2051`
- **CVE:** `CVE-2022-35914`
- **CVE:** `CVE-2016-15047`
- **CVE:** `CVE-2025-34054`
- **IPv4 (defanged):** `217.160.125.125`
- **IPv4 (defanged):** `176.100.37.91`
- **IPv4 (defanged):** `85.215.131.70`
- **SHA256:** `444a9d34a9f59dc7975dfabefb47d789813a4497bbac9127c4806dd816e85211`
- **SHA256:** `9394666007fac4014a4641fdae150c1b969ed2bc4299876318a336fd386abf59`
- **SHA256:** `450ea44da0c9d96a2e8f4d6bad34f1c35cd35743295b8cd2defa9f7a9884685d`
- **SHA256:** `d452f22dacab9785539484245c13e9cce58df23fc82eeef205684fcd196da20b`
- **SHA256:** `20042f1efb59c99e3addf822a3e9e5a496f0b701362df038a50a32a9f504a136`
- **SHA256:** `7413cbb6eab4d6b10346f71be5dd76d7cf2f4817f7776367b162f83755aefa1f`
- **SHA256:** `b6f835ced11059d341222eba11fff3a4672f4de47a3a4d791fad86059a2b06d4`
- **SHA256:** `b61a5508847a2167b737d31193dc393e92c5be2aa5141bbe4b7ea6f440fd4799`
- **SHA256:** `dff0edae6e8854ddd3e617054ee0bd74c696c91411f704dff60aabaec839bec9`
- **SHA256:** `ea44138b9701fce1b2fe13de8f9e00681c007c9adc625edc9f507f177704c2e8`
- **SHA256:** `3ddb67ab079509dd1e7ac77fc4cfed25a271526668c68f8a2221e96a4cc21812`
- **SHA256:** `f02b1d8010dac35b007796def0cbd5d0c9414df790e2b55b105c95df2f2ffa91`
- **SHA256:** `8fc2d35b66c692d37a85ae9d30dc5c7f06f0b3eaf01112a5a6398a1a0feb3aee`
- **SHA256:** `eead44c0af7ddb12cece1a6125cf213bab3c22511cd59aff9d63dcfddb7d4386`
- **SHA256:** `41e8e327abbf2ba721be677ad8a416a7295708257b39688a0af03275fb199cec`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1095** — Non-Application Layer Protocol
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1053.003** — Scheduled Task/Job: Cron
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1105** — Ingress Tool Transfer
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1489** — Service Stop

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] C0XMO botnet C2 beacon to hardcoded Fortinet-attributed IPs

`UC_29_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("217.160.125.125","176.100.37.91","85.215.131.70") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.action | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let C2IPs = dynamic(["217.160.125.125","176.100.37.91","85.215.131.70"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (C2IPs)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemotePort, Protocol, ActionType
| order by Timestamp desc
```

### [LLM] C0XMO Gafgyt persistence binary drop to hidden /tmp/.sys paths

`UC_29_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/tmp/.sys","/var/tmp/.sys","/dev/shm/.sys") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath in~ ("/tmp/.sys","/var/tmp/.sys","/dev/shm/.sys")
   or (FileName == ".sys" and FolderPath in~ ("/tmp","/var/tmp","/dev/shm"))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] C0XMO cron persistence relaunching binary every 15 minutes

`UC_29_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/var/spool/cron/*","/var/spool/cron/crontabs/*","/etc/cron.d/*","/etc/crontab","/etc/cron.hourly/*","/etc/cron.daily/*")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let CronPaths = dynamic(["/var/spool/cron/","/etc/cron.d/","/etc/crontab","/etc/cron.hourly/","/etc/cron.daily/","/etc/cron.weekly/","/etc/cron.monthly/"]);
let TmpPaths = dynamic(["/tmp/","/var/tmp/","/dev/shm/"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any (CronPaths)
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has "crontab" or InitiatingProcessFileName has "crontab"
) on DeviceId
| where FolderPath has_any (CronPaths)
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### [LLM] C0XMO Python scanner module install (paramiko + beautifulsoup4)

`UC_29_10` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Processes.process) as cmds min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip","pip3","python","python3")) AND (Processes.process="*paramiko*" OR Processes.process="*beautifulsoup4*") by Processes.dest Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(cmds,"(?i)paramiko") AND match(cmds,"(?i)beautifulsoup4")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("pip","pip3","python","python3")
| where ProcessCommandLine has_all ("paramiko","beautifulsoup4") and ProcessCommandLine has "install"
   or ProcessCommandLine has_all ("paramiko","requests","install")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] C0XMO rival botnet and red-team process termination spree

`UC_29_11` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Processes.process) as cmds min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("kill","pkill","killall") AND (Processes.process="*mirai*" OR Processes.process="*gafgyt*" OR Processes.process="*tsunami*" OR Processes.process="*mozi*" OR Processes.process="*hajime*" OR Processes.process="*lucifer*" OR Processes.process="*moobot*" OR Processes.process="*xmrig*" OR Processes.process="*kinsing*" OR Processes.process="*sliver*" OR Processes.process="*meterpreter*") by Processes.dest Processes.user Processes.parent_process_name _time | `drop_dm_object_name(Processes)` | bin _time span=2m | stats dc(cmds) as variantsKilled count by dest user parent_process_name _time | where variantsKilled >= 3
```

**Defender KQL:**
```kql
let RivalTokens = dynamic(["mirai","gafgyt","tsunami","mozi","hajime","lucifer","moobot","satori","xmrig","kinsing","sliver","meterpreter","chisel","frp","merlin"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("kill","pkill","killall")
| extend MatchedRivals = set_intersect(RivalTokens, extract_all(@"(?i)([a-z0-9_-]+)", tostring(ProcessCommandLine)))
| where array_length(MatchedRivals) >= 3
| summarize KillCount = count(), Rivals = make_set(MatchedRivals,50), AnyCmd = any(ProcessCommandLine), AnyParent = any(InitiatingProcessCommandLine) by DeviceName, AccountName, bin(Timestamp, 2m)
| where KillCount >= 3
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

### Article-specific behavioural hunt — C0XMO botnet spreads via DD-WRT router flaw, kills rival malware

`UC_29_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — C0XMO botnet spreads via DD-WRT router flaw, kills rival malware ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/.sys*" OR Filesystem.file_path="*/var/tmp/.sys*" OR Filesystem.file_path="*/dev/shm/.sys*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — C0XMO botnet spreads via DD-WRT router flaw, kills rival malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/.sys", "/var/tmp/.sys", "/dev/shm/.sys"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `217.160.125.125`, `176.100.37.91`, `85.215.131.70`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-27137`, `CVE-2015-2051`, `CVE-2022-35914`, `CVE-2016-15047`, `CVE-2025-34054`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `444a9d34a9f59dc7975dfabefb47d789813a4497bbac9127c4806dd816e85211`, `9394666007fac4014a4641fdae150c1b969ed2bc4299876318a336fd386abf59`, `450ea44da0c9d96a2e8f4d6bad34f1c35cd35743295b8cd2defa9f7a9884685d`, `d452f22dacab9785539484245c13e9cce58df23fc82eeef205684fcd196da20b`, `20042f1efb59c99e3addf822a3e9e5a496f0b701362df038a50a32a9f504a136`, `7413cbb6eab4d6b10346f71be5dd76d7cf2f4817f7776367b162f83755aefa1f`, `b6f835ced11059d341222eba11fff3a4672f4de47a3a4d791fad86059a2b06d4`, `b61a5508847a2167b737d31193dc393e92c5be2aa5141bbe4b7ea6f440fd4799` _(+7 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 12 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
