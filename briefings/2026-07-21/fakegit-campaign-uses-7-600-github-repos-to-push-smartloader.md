# [HIGH] FakeGit campaign uses 7,600 GitHub repos to push SmartLoader malware

**Source:** BleepingComputer
**Published:** 2026-07-21
**Article:** https://www.bleepingcomputer.com/news/security/fakegit-campaign-uses-7-600-github-repos-to-push-smartloader-malware/

## Threat Profile

FakeGit campaign uses 7,600 GitHub repos to push SmartLoader malware 
By Bill Toulas 
July 21, 2026
06:34 PM
0 
A large-scale operation dubbed ‘FakeGit’ is pushing SmartLoader and StealC malware through 7,600 malicious GitHub repositories that accumulated more than 14 million downloads.
Over 800 repositories pretended to be AI skills or MCP servers and appeared more than 600 times in public AI registries and catalogs. This increased the likelihood of being discovered by AI agents and developers,…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `144.31.57.65`
- **IPv4 (defanged):** `144.31.57.67`
- **IPv4 (defanged):** `213.176.73.149`
- **Domain (defanged):** `https://raw.githubusercontent.com/deepanshugoel99/long/refs/heads/main/long/long/message1.txt`
- **Domain (defanged):** `https://raw.githubusercontent.com/deepanshugoel99/long/refs/heads/main/long/long/message2.txt`
- **SHA256:** `87de3e5a8ef669589c421220cd392ae8027a8f8d3cd97d35ac339f87dcff12c8`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1053.005** — Scheduled Task
- **T1027** — Obfuscated Files or Information
- **T1059** — Command and Scripting Interpreter
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1204.002** — User Execution: Malicious File
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1036.004** — Masquerading: Masquerade Task or Service
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1555** — Credentials from Password Stores
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SmartLoader: renamed LuaJIT interpreter launched with .txt/.log data-file stage

`UC_28_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("luajit.exe","lua.exe","vm_s390x.exe","init.exe","luad.exe","gcc.exe")) AND (Processes.process IN ("*tcp.log*","*uix.txt*","*lib_bit.txt*","*icon.txt*","*rsp.json*","*ptd.txt*")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where FileName in~ ("luajit.exe","lua.exe","vm_s390x.exe","init.exe","luad.exe","gcc.exe")
| where ProcessCommandLine has_any ("tcp.log","uix.txt","lib_bit.txt","icon.txt","rsp.json","ptd.txt")
   or (InitiatingProcessFileName =~ "cmd.exe" and InitiatingProcessCommandLine has_any ("LaunchTool.cmd","LaunchApp.bat","Launch.bat","Launcher.cmd"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### SmartLoader persistence: scheduled task running a LuaJIT stage or FakeGit task names

`UC_28_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="schtasks.exe" AND Processes.process="*/create*" AND (Processes.process IN ("*luajit.exe*","*vm_s390x.exe*","*init.exe*","*luad.exe*","*tcp.log*","*lib_bit.txt*","*icon.txt*","*uix.txt*","*ptd.txt*","*rsp.json*","*AudioManager_ODM3*","*OfficeClickToRunTask_7d7757*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("luajit.exe","vm_s390x.exe","init.exe","luad.exe","tcp.log","lib_bit.txt","icon.txt","uix.txt","ptd.txt","rsp.json","AudioManager_ODM3","OfficeClickToRunTask_7d7757")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### SmartLoader Polygon smart-contract C2 resolution / hardcoded C2 IP callback

`UC_28_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("89.169.12.173","89.169.12.241") OR All_Traffic.dest="polygon.drpc.org" OR All_Traffic.url="*polygon.drpc.org*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.app All_Traffic.url | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in ("89.169.12.173","89.169.12.241") or RemoteUrl has "polygon.drpc.org"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
| order by Timestamp desc
```

### StealC exfiltration to hardcoded FakeGit gate IPs / PHP endpoint

`UC_28_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("217.119.129.110","213.176.72.200") OR All_Traffic.url="*3d9c1a1d0dc9436eb7b7.php*") by All_Traffic.src All_Traffic.dest_ip All_Traffic.app All_Traffic.url | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in ("217.119.129.110","213.176.72.200") or RemoteUrl has "3d9c1a1d0dc9436eb7b7.php"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
| order by Timestamp desc
```

### FakeGit GitHub dead-drop stage download by LuaJIT/LOLBin process

`UC_28_9` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.url="*rd898/package*" OR All_Traffic.url="*Mahmudul-Riad/www*" OR All_Traffic.url="*/json/1.json*" OR All_Traffic.url="*/json/2.json*" OR All_Traffic.url="*/index/7.txt*" OR All_Traffic.url="*/index/8.txt*") AND All_Traffic.app IN ("luajit.exe","vm_s390x.exe","init.exe","luad.exe","curl.exe","powershell.exe") by All_Traffic.src All_Traffic.app All_Traffic.url | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any ("rd898/package","Mahmudul-Riad/www","/json/1.json","/json/2.json","/index/7.txt","/index/8.txt")
| where InitiatingProcessFileName in~ ("luajit.exe","lua.exe","vm_s390x.exe","init.exe","luad.exe","gcc.exe","curl.exe","powershell.exe","pwsh.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, InitiatingProcessAccountName
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

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `144.31.57.65`, `144.31.57.67`, `213.176.73.149`, `https://raw.githubusercontent.com/deepanshugoel99/long/refs/heads/main/long/long/message1.txt`, `https://raw.githubusercontent.com/deepanshugoel99/long/refs/heads/main/long/long/message2.txt`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `87de3e5a8ef669589c421220cd392ae8027a8f8d3cd97d35ac339f87dcff12c8`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
