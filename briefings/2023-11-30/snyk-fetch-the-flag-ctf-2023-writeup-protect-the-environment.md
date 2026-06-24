# [MED] Snyk Fetch the Flag CTF 2023 writeup: Protect The Environment

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
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1083** — File and Directory Discovery
- **T1611** — Escape to Host

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Container PID 1 environment harvest via /proc/1/environ read

`UC_1390_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process="*/proc/1/environ*" OR Processes.process="*/proc/self/environ*" by Processes.dest Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)` | where process_name IN ("cat","head","less","more","strings","xxd","od","tr","grep","awk","sed","hexdump","dd","bash","sh","python","python3","perl","ruby","curl","nc") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("/proc/1/environ", "/proc/self/environ")
| where FileName in~ ("cat","head","less","more","strings","xxd","od","tr","grep","awk","sed","hexdump","dd","python","python3","perl","ruby","curl","nc","bash","sh")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, FolderPath, SHA256
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

Severity classified as **MED** based on: 2 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
