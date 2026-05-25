# [HIGH] Hackers Actives Scanning SonicWall Firewall Interfaces – 597,000 Sessions Observed

**Source:** Cyber Security News
**Published:** 2026-05-25
**Article:** https://cybersecuritynews.com/hackers-scan-sonicwall-firewall-interfaces/

## Threat Profile

Home Cyber Security News 
Hackers Actives Scanning SonicWall Firewall Interfaces – 597,000 Sessions Observed 
By Abinaya 
May 25, 2026 
A sharp rise in internet-wide scanning activity targeting SonicWall firewall management interfaces has been detected, raising concerns about a potential pre-disclosure reconnaissance phase tied to new vulnerabilities.
Threat intelligence firm GreyNoise reported a significant surge in scanning of SonicWall SonicOS management APIs between May 9 and May 18, 2026.
T…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-0400`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1595.002** — Active Scanning: Vulnerability Scanning
- **T1595.001** — Active Scanning: Scanning IP Blocks
- **T1595** — Active Scanning

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SonicWall SonicOS mgmt-interface scanning via uniform Chrome 119 / Linux x86_64 user-agent

`UC_4_3` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.dest_port IN (80,8080) Web.http_user_agent="*Chrome/119*" Web.http_user_agent="*Linux x86_64*" Web.http_user_agent="*X11*" by Web.src Web.dest Web.dest_port Web.http_user_agent
| `drop_dm_object_name(Web)`
| where count > 50
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - count
```

### [LLM] Anomalous volume spike of inbound HTTP sessions to SonicWall management ports (46x baseline)

`UC_4_4` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (80,8080) All_Traffic.direction=inbound by _time span=1d All_Traffic.dest_ip
| `drop_dm_object_name(All_Traffic)`
| eventstats avg(count) as baseline_avg p95(count) as baseline_p95 by dest_ip
| where count > (baseline_avg * 30)   // 30x = conservative trip vs the ~46x peak GreyNoise reported
| sort - count
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-0400`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
