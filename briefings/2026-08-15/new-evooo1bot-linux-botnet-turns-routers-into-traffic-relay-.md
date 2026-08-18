# [CRIT] New Evooo1Bot Linux botnet turns routers into traffic relay nodes

**Source:** BleepingComputer
**Published:** 2026-08-15
**Article:** https://www.bleepingcomputer.com/news/security/new-evooo1bot-linux-botnet-turns-routers-into-traffic-relay-nodes/

## Threat Profile

New Evooo1Bot Linux botnet turns routers into traffic relay nodes 
By Bill Toulas 
August 15, 2026
10:14 AM
0 
A new Mirai-based modular Linux botnet malware called Evooo1Bot has been targeting internet-facing gateway devices, turning them into SOCKS5 traffic relay nodes.
The malware's capabilities extend beyond turning devices into proxy nodes and include credential theft, SSH brute-forcing, and launching distributed denial-of-service (DDoS) attacks.
Since at least July, Evooo1Bot has been targ…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2007-3010`
- **CVE:** `CVE-2016-6277`
- **CVE:** `CVE-2018-14558`
- **CVE:** `CVE-2019-14931`
- **CVE:** `CVE-2020-10987`
- **CVE:** `CVE-2021-46422`
- **CVE:** `CVE-2022-37055`
- **CVE:** `CVE-2024-29269`
- **CVE:** `CVE-2025-10123`
- **CVE:** `CVE-2025-55583`
- **CVE:** `CVE-2021-36260`
- **CVE:** `CVE-2022-26134`
- **CVE:** `CVE-2022-29464`
- **CVE:** `CVE-2022-30525`
- **CVE:** `CVE-2023-1389`
- **CVE:** `CVE-2024-4577`
- **CVE:** `CVE-2024-10914`
- **CVE:** `CVE-2025-1974`
- **IPv4 (defanged):** `91.92.40.118`
- **SHA256:** `f13cb360768363d3424e2192c7805b8c8015eb8706dbbbcdead6aed8cf390109`
- **SHA256:** `4c0886349e9d348569fffe1b7a31e474d514508bf0cd6f1e5dd99c2a73525e4d`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1053.003** — Scheduled Task/Job: Cron
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts
- **T1040** — Network Sniffing
- **T1539** — Steal Web Session Cookie
- **T1090** — Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Evooo1Bot C2/loader traffic to relay host 91.92.40.118

`UC_36_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="91.92.40.118" by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "91.92.40.118"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

### Evooo1Bot loader download cradle (wget.sh / wget||curl pipe-to-shell into /tmp)

`UC_36_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("wget","curl","tftp","busybox","sh","bash","dash") AND (Processes.process="*91.92.40.118*" OR Processes.process="*/wget.sh*" OR (Processes.process="*wget -qO-*" AND Processes.process="*curl -sL*"))) by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("sh","bash","dash","ash","wget","curl","tftp","busybox")
| where ProcessCommandLine contains "91.92.40.118"
    or ProcessCommandLine contains "/wget.sh"
    or (ProcessCommandLine contains "wget -qO-" and ProcessCommandLine contains "curl -sL")
    or ((ProcessCommandLine contains "wget " or ProcessCommandLine contains "curl " or ProcessCommandLine contains "tftp ") and ProcessCommandLine contains "/tmp/" and ProcessCommandLine contains "chmod")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Evooo1Bot persistence: 5-min cron re-download & 'Apache HTTPD Cache Manager' systemd masquerade

`UC_36_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Processes.process) as cmds min(_time) as firstTime from datamodel=Endpoint.Processes where ((Processes.parent_process_name IN ("cron","crond","anacron") AND Processes.process="*wget -qO-*" AND Processes.process="*curl -sL*") OR Processes.process="*Apache HTTPD Cache Manager*" OR (Processes.process="*/etc/rc.local*" AND (Processes.process="*wget*" OR Processes.process="*curl*"))) by Processes.dest, Processes.parent_process_name, Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (InitiatingProcessFileName in~ ("cron","crond","crond","anacron") and ProcessCommandLine contains "wget -qO-" and ProcessCommandLine contains "curl -sL")
    or ProcessCommandLine contains "Apache HTTPD Cache Manager"
    or ((ProcessCommandLine contains "/etc/rc.local" or ProcessCommandLine contains "/etc/init.d/" or ProcessCommandLine contains "/etc/profile.d/" or ProcessCommandLine contains "/etc/systemd/system/") and (ProcessCommandLine contains "wget" or ProcessCommandLine contains "curl"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Evooo1Bot credential sniffer artifact (/tmp/.sniff.log capture file)

`UC_36_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name=".sniff.log" OR Filesystem.file_path="/tmp/.sniff.log") by Filesystem.dest, Filesystem.file_path, Filesystem.file_name, Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName =~ ".sniff.log" or FolderPath =~ "/tmp/.sniff.log"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

### Evooo1Bot SOCKS5 relay listener on TCP 1080 from a /tmp-resident binary

`UC_36_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Ports where Ports.dest_port=1080 AND Ports.transport="tcp" by Ports.dest, Ports.dest_port, Ports.transport, Ports.process_guid | `drop_dm_object_name(Ports)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ActionType == "ListeningConnectionCreated"
| where LocalPort == 1080
| where InitiatingProcessFolderPath has_any ("/tmp/","/dev/shm/","/var/tmp/")
| project Timestamp, DeviceName, LocalIP, LocalPort, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `91.92.40.118`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2007-3010`, `CVE-2016-6277`, `CVE-2018-14558`, `CVE-2019-14931`, `CVE-2020-10987`, `CVE-2021-46422`, `CVE-2022-37055`, `CVE-2024-29269` _(+10 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `f13cb360768363d3424e2192c7805b8c8015eb8706dbbbcdead6aed8cf390109`, `4c0886349e9d348569fffe1b7a31e474d514508bf0cd6f1e5dd99c2a73525e4d`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 9 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
