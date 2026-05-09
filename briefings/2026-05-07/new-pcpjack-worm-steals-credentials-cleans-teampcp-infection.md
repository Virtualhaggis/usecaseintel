# [HIGH] New PCPJack worm steals credentials, cleans TeamPCP infections

**Source:** BleepingComputer
**Published:** 2026-05-07
**Article:** https://www.bleepingcomputer.com/news/security/new-pcpjack-worm-steals-credentials-cleans-teampcp-infections/

## Threat Profile

New PCPJack worm steals credentials, cleans TeamPCP infections 
By Bill Toulas 
May 7, 2026
02:35 PM
0 
A new malware framework called PCPJack is stealing credentials from exposed cloud infrastructure while actively removing TeamPCP's access to the systems.
Among the targeted services are Docker, Kubernetes, Redis, MongoDB, RayML, and vulnerable web applications. In many cases, the threat actor moves laterally on the network.
SentinelLabs researchers say that PCPJack appears designed for large-s…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-29927`
- **CVE:** `CVE-2025-55182`
- **CVE:** `CVE-2026-1357`
- **CVE:** `CVE-2025-9501`
- **CVE:** `CVE-2025-48703`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1105** — Ingress Tool Transfer
- **T1567** — Exfiltration Over Web Service
- **T1102.002** — Web Service: Bidirectional Communication
- **T1041** — Exfiltration Over C2 Channel
- **T1053.003** — Scheduled Task/Job: Cron
- **T1505** — Server Software Component

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PCPJack Linux orchestrator: bootstrap.sh launching python monitor.py

`UC_33_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.os=Linux ((Processes.parent_process_name=bash AND Processes.parent_process="*bootstrap.sh*") OR (Processes.process_name IN ("python","python3") AND Processes.process="*monitor.py*") OR (Processes.process="*bootstrap.sh*" AND Processes.process IN ("*mkdir*","*pip install*","*systemctl*"))) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// PCPJack: bootstrap.sh -> python monitor.py orchestrator chain on Linux
let LinuxHosts = DeviceInfo
    | where OSPlatform =~ "Linux"
    | summarize by DeviceId;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId in (LinuxHosts)
| where AccountName !endswith "$"
| where (FileName in~ ("python","python3") and ProcessCommandLine has "monitor.py")
    or (InitiatingProcessCommandLine has "bootstrap.sh" and FileName in~ ("python","python3","curl","wget","pip","pip3","mkdir","systemctl","crontab"))
    or (FileName =~ "bash" and ProcessCommandLine has "bootstrap.sh")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] PCPJack credential exfiltration to api.telegram.org from Linux server workload

`UC_33_7` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user values(Web.bytes_out) as bytes_out from datamodel=Web.Web where (Web.url="*api.telegram.org*" OR Web.url="*telegram.org/bot*" OR Web.dest="api.telegram.org") by Web.src Web.dest Web.http_user_agent | `drop_dm_object_name(Web)` | join type=outer src [ search index=* sourcetype=*linux* | stats count by host | rename host as src ] | where isnotnull(count) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// PCPJack: Telegram exfiltration from Linux server
let LinuxHosts = DeviceInfo
    | where OSPlatform =~ "Linux"
    | summarize by DeviceId, DeviceName;
let TelegramTraffic = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has "telegram.org" or RemoteUrl has "api.telegram.org"
    | where DeviceId in ((LinuxHosts | project DeviceId));
let TelegramDns = DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tolower(tostring(parse_json(AdditionalFields).QueryName))
    | where Q has "telegram.org"
    | where DeviceId in ((LinuxHosts | project DeviceId))
    | project Timestamp, DeviceId, DeviceName, RemoteUrl=Q,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName;
union isfuzzy=true
    (TelegramTraffic | project Timestamp, DeviceId, DeviceName, RemoteUrl, RemoteIP,
                              InitiatingProcessFileName, InitiatingProcessCommandLine,
                              InitiatingProcessAccountName=InitiatingProcessAccountName),
    (TelegramDns)
| where InitiatingProcessFileName !in~ ("telegram-cli","telegram-desktop")
| order by Timestamp desc
```

### [LLM] Redis-server writing to crontab paths (PCPJack Redis cron-rewrite persistence)

`UC_33_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file_name from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("redis-server","redis-sentinel") (Filesystem.file_path="/var/spool/cron/*" OR Filesystem.file_path="/etc/cron.d/*" OR Filesystem.file_path="/etc/crontab*" OR Filesystem.file_path="/etc/cron.hourly/*" OR Filesystem.file_path="/etc/cron.daily/*" OR Filesystem.file_path="/var/spool/anacron/*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// PCPJack: redis-server writing into cron persistence paths via CONFIG SET dir + BGSAVE
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("redis-server","redis-sentinel")
| where FolderPath has_any (
    "/var/spool/cron/",
    "/etc/cron.d/",
    "/etc/crontab",
    "/etc/cron.hourly/",
    "/etc/cron.daily/",
    "/etc/cron.weekly/",
    "/var/spool/anacron/")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, SHA256
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

### Article-specific behavioural hunt — New PCPJack worm steals credentials, cleans TeamPCP infections

`UC_33_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New PCPJack worm steals credentials, cleans TeamPCP infections ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("bootstrap.sh","monitor.py","next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("bootstrap.sh","monitor.py","next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New PCPJack worm steals credentials, cleans TeamPCP infections
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("bootstrap.sh", "monitor.py", "next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("bootstrap.sh", "monitor.py", "next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-29927`, `CVE-2025-55182`, `CVE-2026-1357`, `CVE-2025-9501`, `CVE-2025-48703`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 9 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
