# [HIGH] Popular WordPress redirect plugin hid dormant backdoor for years

**Source:** BleepingComputer
**Published:** 2026-04-29
**Article:** https://www.bleepingcomputer.com/news/security/popular-wordpress-redirect-plugin-hid-dormant-backdoor-for-years/

## Threat Profile

Popular WordPress redirect plugin hid dormant backdoor for years 
By Bill Toulas 
April 29, 2026
06:13 PM
0 
The Quick Page/Post Redirect plugin, installed on more than 70,000 WordPress sites, had a backdoor added five years ago that allows injecting arbitrary code into users’ sites.
The malware was uncovered by Austin Ginder, the founder of WordPress hosting provider Anchor, who found it after 12 infected sites on his fleet triggered a security alert.
Quick Page/Post Redirect plugin, available …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `anadnet.com`
- **Domain (defanged):** `w.anadnet.com`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1505.003** — Server Software Component: Web Shell
- **T1102.002** — Web Service: Bidirectional Communication

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Outbound DNS/Web traffic to anadnet[.]com — Quick Page/Post Redirect WordPress backdoor C2

`UC_31_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as answers from datamodel=Network_Resolution where (DNS.query="anadnet.com" OR DNS.query="w.anadnet.com" OR DNS.query="*.anadnet.com") by DNS.query DNS.src DNS.dest 
| `drop_dm_object_name(DNS)` 
| append 
    [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as ua from datamodel=Web where (Web.url="*anadnet.com*" OR Web.dest="anadnet.com" OR Web.dest="w.anadnet.com") by Web.src Web.dest Web.http_method 
     | `drop_dm_object_name(Web)`] 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let badHosts = dynamic(["anadnet.com","w.anadnet.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (badHosts)
   or tostring(parse_url(RemoteUrl).Host) in~ (badHosts)
   or RemoteUrl endswith ".anadnet.com"
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| union (
    DeviceEvents
    | where ActionType == "DnsQueryResponse" or ActionType == "DnsConnectionInspected"
    | where AdditionalFields has "anadnet.com"
    | project Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessFileName, InitiatingProcessCommandLine
)
```

### [LLM] Trojanised Quick Page/Post Redirect plugin filesystem & PHP-fetch hunt

`UC_31_3` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files values(Filesystem.process_name) as writers from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/wp-content/plugins/quick-pagepost-redirect-plugin/*" OR Filesystem.file_path="*\\wp-content\\plugins\\quick-pagepost-redirect-plugin\\*") AND Filesystem.file_name="*.php" by Filesystem.dest Filesystem.file_path 
| `drop_dm_object_name(Filesystem)` 
| join type=left dest 
    [| tstats `summariesonly` count as net_count values(All_Traffic.dest) as remote_dests from datamodel=Network_Traffic where (All_Traffic.dest="anadnet.com" OR All_Traffic.dest="w.anadnet.com" OR All_Traffic.dest_host="*anadnet.com") by All_Traffic.src 
     | rename All_Traffic.src as dest 
     | fields dest net_count remote_dests] 
| where isnotnull(net_count) OR firstTime>relative_time(now(),"-30d@d") 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let pluginPath = "quick-pagepost-redirect-plugin";
let badDomains = dynamic(["anadnet.com","w.anadnet.com"]);
let pluginHosts = DeviceFileEvents
    | where Timestamp > ago(90d)
    | where FolderPath has pluginPath
    | where FileName endswith ".php"
    | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Files=make_set(FileName,50), Paths=make_set(FolderPath,20) by DeviceId, DeviceName;
let beaconingHosts = DeviceNetworkEvents
    | where Timestamp > ago(90d)
    | where RemoteUrl has_any (badDomains) or RemoteUrl endswith ".anadnet.com"
    | where InitiatingProcessFileName in~ ("php.exe","php-cgi.exe","httpd.exe","nginx.exe","w3wp.exe","php-fpm")
    | summarize Beacons=count(), BeaconUrls=make_set(RemoteUrl,10) by DeviceId, DeviceName;
pluginHosts
| join kind=leftouter beaconingHosts on DeviceId
| project DeviceName, FirstSeen, LastSeen, Files, Paths, Beacons, BeaconUrls
| order by LastSeen desc
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
  - IP / domain IOC(s): `anadnet.com`, `w.anadnet.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
