# [HIGH] Snyk Fetch the Flag CTF 2023 writeup: Protect The Environment

**Source:** Snyk
**Published:** 2023-11-30
**Article:** https://snyk.io/blog/snyk-fetch-the-flag-ctf-2023-writeup-protect-the-environment/

## Threat Profile

Snyk Blog In this article
Written by John Hammond 
November 30, 2023
0 mins read Thanks for playing Fetch with us! Congrats to the thousands of players who joined us for Fetch the Flag CTF.   If you were at Snyk’s 2023 Fetch the Flag and are looking for the answer to the Silent Cartographer challenge, you’ve come to the right place. Let’s walk through the solution together!
Silent Cartographer is a point-and-pwn web app exploitation challenge. The web app happens to be the Covenant C2 framework.…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1611** — Escape to Host
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1057** — Process Discovery
- **T1190** — Exploit Public-Facing Application
- **T1078** — Valid Accounts
- **T1505.003** — Server Software Component: Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Suspicious read of /proc/1/environ — container/chroot escape reconnaissance

`UC_1297_1` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=read (Filesystem.file_path="/proc/1/environ" OR Filesystem.file_path="/proc/self/root/proc/1/environ" OR Filesystem.file_path IN ("/proc/2/environ","/proc/3/environ","/proc/4/environ")) by Filesystem.dest Filesystem.process_name Filesystem.process_path Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where NOT match(process_name, "^(systemd|ps|top|htop|node_exporter|prometheus|cadvisor|datadog-agent|filebeat|telegraf)$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileOpened","FileAccessed","FileCreated")
| where FolderPath matches regex @"^/proc/(1|self/root/proc/1|[2-9])/environ$"
| where InitiatingProcessFileName !in ("systemd","ps","top","htop","node_exporter","prometheus","cadvisor","datadog-agent","filebeat")
| where InitiatingProcessAccountName != "root" or InitiatingProcessParentFileName !in ("systemd","init","dockerd","containerd-shim")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath
| order by Timestamp desc
```

### [LLM] Covenant C2 admin-console exposure on TCP/7443 with anonymous JWT-forge probe

`UC_1297_2` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.dest_port=7443 (Web.url="*/api/users*" OR Web.url="*/api/listeners*" OR Web.url="*/api/grunts*" OR Web.url="*/api/users/login*") by Web.src Web.dest Web.dest_port Web.url Web.http_method Web.http_user_agent Web.status | `drop_dm_object_name(Web)` | where NOT cidrmatch("10.0.0.0/8", src) AND NOT cidrmatch("192.168.0.0/16", src) AND NOT cidrmatch("172.16.0.0/12", src) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 7443 or LocalPort == 7443
| where ActionType == "InboundConnectionAccepted" or ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "Covenant.exe" or ProcessCommandLine has_any ("dotnet Covenant.dll","Covenant.API","--CovenantUri")
    | project DeviceId, CovenantProcess = FileName, CovenantCmd = ProcessCommandLine, CovenantTime = Timestamp
) on DeviceId
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine, CovenantProcess, CovenantCmd
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


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
