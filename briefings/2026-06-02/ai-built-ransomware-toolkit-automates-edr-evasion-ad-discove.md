# [HIGH] AI-built ransomware toolkit automates EDR evasion, AD discovery

**Source:** BleepingComputer
**Published:** 2026-06-02
**Article:** https://www.bleepingcomputer.com/news/security/ai-built-ransomware-toolkit-automates-edr-evasion-ad-discovery/

## Threat Profile

AI-built ransomware toolkit automates EDR evasion, AD discovery 
By Bill Toulas 
June 2, 2026
04:01 PM
0 
A threat actor is using an AI-built ransomware attack toolkit that automates Active Directory discovery and helps evade endpoint detection and response (EDR) solutions.
Tool and payload development was assisted by Cursor and Claude Opus agents in various stages, including initial coding, analysis, and revisioning. Additionally, some agents were tasked with checking security research posts fo…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1090.002** — Proxy: External Proxy
- **T1102.002** — Web Service: Bidirectional Communication
- **T1105** — Ingress Tool Transfer
- **T1074.001** — Data Staged: Local Data Staging

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Telegram Bot API C2 channel used by AI-built ransomware toolkit (non-IM/non-browser egress)

`UC_44_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process="*api.telegram.org*" OR Processes.process="*api.telegram.org/bot*") by Processes.dest Processes.process_name | `drop_dm_object_name(Processes)` | where NOT match(process_name, "(?i)^(chrome|msedge|firefox|telegram|brave|slack|discord|opera|iexplore|teams)\.exe$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "api.telegram.org" or RemoteUrl matches regex @"(?i)api\.telegram\.org/bot[A-Za-z0-9:_\-]+"
| where InitiatingProcessFileName !in~ ("telegram.exe","telegramdesktop.exe","updater.exe","chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","slack.exe","discord.exe","teams.exe")
| where InitiatingProcessAccountName !endswith "$"
| where isempty(InitiatingProcessVersionInfoCompanyName)
   or InitiatingProcessVersionInfoCompanyName !in~ ("Microsoft Corporation","Google LLC","Mozilla Corporation","Telegram Messenger LLP","Slack Technologies, Inc.","Discord Inc.")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine,
          InitiatingProcessVersionInfoCompanyName,
          InitiatingProcessVersionInfoProductName,
          RemoteUrl, RemoteIP
| order by Timestamp desc
```

### [LLM] First-time egress to *.workers.dev (Cloudflare Worker C2 redirector) from non-browser process

`UC_44_5` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.user) as user from datamodel=Web where Web.site="*.workers.dev" by Web.src Web.app Web.site | `drop_dm_object_name(Web)` | where NOT match(app, "(?i)^(chrome|msedge|firefox|brave|opera|iexplore|safari|slack|teams|outlook)") | eventstats earliest(firstTime) as orgFirstSeen by site | where firstTime = orgFirstSeen | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let Lookback = 30d;
let Recent = 1h;
let Known = DeviceNetworkEvents
    | where Timestamp between (ago(Lookback) .. ago(Recent))
    | where RemoteUrl endswith ".workers.dev"
    | summarize by RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(Recent)
| where RemoteUrl endswith ".workers.dev"
| join kind=leftanti Known on RemoteUrl
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","slack.exe","teams.exe","outlook.exe","webex.exe","safari.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine,
          InitiatingProcessVersionInfoCompanyName,
          RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] Payload staging in user 'Documents\test' folder — AI-built ransomware toolkit drop path

`UC_44_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\Users\\*\\Documents\\test\\*" (Filesystem.file_name="*.exe" OR Filesystem.file_name="*.dll" OR Filesystem.file_name="*.ps1" OR Filesystem.file_name="*.py" OR Filesystem.file_name="*.bat" OR Filesystem.file_name="*.cmd" OR Filesystem.file_name="*.js" OR Filesystem.file_name="*.vbs" OR Filesystem.file_name="*.hta") by Filesystem.dest Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath matches regex @"(?i)\\Users\\[^\\]+\\Documents\\test\\"
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1"
   or FileName endswith ".py"  or FileName endswith ".bat" or FileName endswith ".cmd"
   or FileName endswith ".js"  or FileName endswith ".vbs" or FileName endswith ".hta"
   or FileName endswith ".rs"  or FileName endswith ".go"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine,
          FolderPath, FileName, SHA256, FileSize
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
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


## Why this matters

Severity classified as **HIGH** based on: 7 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
