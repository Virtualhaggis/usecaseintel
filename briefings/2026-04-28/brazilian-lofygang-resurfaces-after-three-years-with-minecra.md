# [MED] Brazilian LofyGang Resurfaces After Three Years With Minecraft LofyStealer Campaign

**Source:** The Hacker News
**Published:** 2026-04-28
**Article:** https://thehackernews.com/2026/04/brazilian-lofygang-resurfaces-after.html

## Threat Profile

A cybercrime group of Brazilian origin has resurfaced after more than three years to orchestrate a campaign that targets Minecraft players with a new stealer called LofyStealer (aka GrabBot). "The malware disguises itself as a Minecraft hack called 'Slinky,'" Brazil-based cybersecurity company ZenoX said in a technical report. "It uses the official game icon to induce voluntary execution,

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1204.002** — User Execution: Malicious File
- **T1106** — Native API
- **T1555.003** — Credentials from Web Browsers
- **T1539** — Steal Web Session Cookie
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] LofyStealer/GrabBot C2 beacon to 24.152.36.241:8080 with GrabBot/1.0 User-Agent

`UC_20_0` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.dest="24.152.36.241" AND Web.dest_port=8080) OR Web.user_agent="GrabBot/1.0" OR (Web.url IN ("*/upload","*/time") AND Web.http_method IN ("POST","GET")) by Web.src, Web.user, Web.dest, Web.dest_port, Web.http_method, Web.url, Web.user_agent, Web.http_content_type | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
  (DeviceNetworkEvents
   | where RemoteIP == "24.152.36.241" and RemotePort == 8080
   | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl),
  (DeviceEvents
   | where ActionType == "ConnectionSuccess" or ActionType startswith "Network"
   | where AdditionalFields has "GrabBot/1.0" or RemoteUrl has_any ("/upload","/time")
   | project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, AdditionalFields)
```

### [LLM] Slinky Minecraft hack loader (load.exe pkg-Node) spawning chromeleveler/chromelevator stealer

`UC_20_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="load.exe" AND Processes.process_name IN ("chromeleveler.exe","chromelevator.exe")) OR (Processes.process_name IN ("chromeleveler.exe","chromelevator.exe")) OR (Processes.process_name="load.exe" AND Processes.process_path IN ("*\\Downloads\\*","*\\Temp\\*","*\\AppData\\*") AND Processes.process_path LIKE "%Slinky%") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process, Processes.process_path, Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where (InitiatingProcessFileName =~ "load.exe" and FileName in~ ("chromeleveler.exe","chromelevator.exe"))
   or FileName in~ ("chromeleveler.exe","chromelevator.exe")
   or (FileName =~ "load.exe" and (FolderPath has_any ("\\Downloads\\","\\Temp\\","\\AppData\\") and (ProcessCommandLine has "Slinky" or InitiatingProcessCommandLine has "Slinky")))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
```

### [LLM] GrabBot multi-browser credential harvest (Chrome/Edge/Brave/Opera/Firefox/Avast)

`UC_20_2` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Filesystem.file_path) as paths dc(Filesystem.file_path) as path_count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("chromeleveler.exe","chromelevator.exe","load.exe") AND (Filesystem.file_name IN ("Login Data","Cookies","Web Data","logins.json","cookies.sqlite","key4.db") OR Filesystem.file_path IN ("*\\Google\\Chrome\\*","*\\Microsoft\\Edge\\*","*\\BraveSoftware\\*","*\\Opera Software\\*","*\\Mozilla\\Firefox\\Profiles\\*","*\\AVAST Software\\Browser\\*")) by Filesystem.dest, Filesystem.user, Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where path_count >= 2 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where InitiatingProcessFileName in~ ("chromeleveler.exe","chromelevator.exe","load.exe")
| where FileName in~ ("Login Data","Cookies","Web Data","logins.json","cookies.sqlite","key4.db")
   or FolderPath has_any ("\\Google\\Chrome\\","\\Microsoft\\Edge\\","\\BraveSoftware\\","\\Opera Software\\","\\Mozilla\\Firefox\\Profiles\\","\\AVAST Software\\Browser\\")
| summarize FileCount=dcount(FolderPath), Files=make_set(FileName,25), Browsers=make_set(FolderPath,25), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, AccountName, InitiatingProcessFileName
| where FileCount >= 2
```


## Why this matters

Severity classified as **MED** based on: 3 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
