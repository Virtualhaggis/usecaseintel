# [HIGH] VS Code Remote-SSH RCE Lets Attackers Pivot From Developer Machines to Cloud Servers

**Source:** Cyber Security News
**Published:** 2026-05-29
**Article:** https://cybersecuritynews.com/vs-code-remote-ssh-rce/

## Threat Profile

Home Cyber Security News 
VS Code Remote-SSH RCE Lets Attackers Pivot From Developer Machines to Cloud Servers 
By Abinaya 
May 29, 2026 
A newly disclosed vulnerability in Visual Studio Code’s Remote-SSH extension exposes a critical post-compromise attack path that allows threat actors to pivot from infected developer machines into cloud and production environments.
Given the extension’s widespread adoption across modern development workflows, the issue poses a significant risk to organizations…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1219** — Remote Access Software
- **T1546** — Event Triggered Execution
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1554** — Compromise Host Software Binary

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] TOCTOU tamper of VS Code Remote-SSH bootstrap script in user temp by non-VS-Code

`UC_8_2` · phase: **weapon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") AND (Filesystem.file_path="*\\AppData\\Local\\Temp\\*" OR Filesystem.file_path="*\\.vscode-server\\*" OR Filesystem.file_path="*vscode-remote-ssh*" OR Filesystem.file_path="*vscode-ssh-askpass*" OR Filesystem.file_path="*/tmp/vscode-ssh*") AND (Filesystem.file_name="*.sh" OR Filesystem.file_name="*bootstrap*" OR Filesystem.file_name="*askpass*") AND NOT Filesystem.process_name IN ("Code.exe","Cursor.exe","ssh.exe","sshd.exe","node.exe") by host Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (@"\AppData\Local\Temp\", @"\.vscode-server\", "vscode-remote-ssh", "vscode-ssh-askpass", "/tmp/vscode-ssh")
| where FileName endswith ".sh" or FileName has_any ("bootstrap","install","askpass")
| where not (InitiatingProcessFileName in~ ("Code.exe","Cursor.exe","ssh.exe","sshd.exe","node.exe"))
| where not (InitiatingProcessFolderPath has_any (@"\Microsoft VS Code\", @"\Cursor\", @"\.vscode\"))
| where not (InitiatingProcessAccountName endswith "$")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName
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


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
