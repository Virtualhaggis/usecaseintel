# [CRIT] Network Anomaly Detection in KATA

**Source:** Securelist (Kaspersky)
**Published:** 2026-07-31
**Article:** https://securelist.com/tr/network-anomaly-detection-in-kata/120892/

## Threat Profile

Threat Response 
Table of Contents
Introduction 
Kerberoasting attack detection by KATA 
Why standard tools have a hard time detecting Kerberoasting 
Creating a Network Anomaly Detection rule 
Detecting DNS tunneling in KATA 
How DNS tunnels work 
DNS tunneling detection logic 
Prebuilt rules for detecting network anomalies in KATA 
Conclusion 
Introduction 
Once the attacker has breached the corporate network, subsequent stages of the attack often involve leveraging standard domain infrastructu…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `testinglab.ru`
- **Domain (defanged):** `crust.testinglab.ru`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1053.005** — Scheduled Task
- **T1558.003** — Steal or Forge Kerberos Tickets: Kerberoasting
- **T1071.004** — Application Layer Protocol: DNS
- **T1572** — Protocol Tunneling
- **T1048.003** — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Kerberoasting: single account requests TGS tickets for many unique non-system SPNs

`UC_121_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
source="WinEventLog:Security" EventCode=4769 Service_Name!="*$" Account_Name!="*$" TargetUserName!="*$" Service_Name!="krbtgt"
| stats dc(Service_Name) as distinct_spns values(Service_Name) as spns count as tgs_requests min(_time) as firstTime max(_time) as lastTime by Account_Name Client_Address ComputerName
| where distinct_spns>=10
| convert ctime(firstTime) ctime(lastTime)
| sort - distinct_spns
```

### DNS tunneling: high-volume long/high-entropy subdomain queries to a single parent domain

`UC_121_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS by DNS.src DNS.query
| `drop_dm_object_name(DNS)`
| eval qlen=len(query)
| where qlen>50
| rex field=query "(?<parent>[a-z0-9-]+\.[a-z0-9-]+)$"
| stats dc(query) as unique_subqueries sum(count) as total_queries max(qlen) as max_label_len by src parent
| where unique_subqueries>50 AND max_label_len>100
| sort - unique_subqueries
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType == "DnsQueryResponse"
| where isnotempty(RemoteUrl)
| extend qlen = strlen(RemoteUrl)
| where qlen > 50
| extend d = split(tolower(RemoteUrl), ".")
| extend parent = strcat(tostring(d[array_length(d)-2]), ".", tostring(d[array_length(d)-1]))
| summarize UniqueSubQueries = dcount(RemoteUrl), TotalQueries = count(), MaxLen = max(qlen)
         by DeviceName, InitiatingProcessFileName, parent, bin(Timestamp, 10m)
| where UniqueSubQueries > 50 and MaxLen > 100   // sustained many-unique long labels to one parent domain
| order by UniqueSubQueries desc
```

### Endpoint issuing DNS directly to unauthorised/external resolvers (resolver bypass)

`UC_121_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=53 by All_Traffic.src All_Traffic.dest All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| where NOT cidrmatch("10.0.0.0/8",dest) AND NOT cidrmatch("172.16.0.0/12",dest) AND NOT cidrmatch("192.168.0.0/16",dest) AND NOT cidrmatch("127.0.0.0/8",dest)
| stats sum(count) as dns_queries values(dest) as external_resolvers by src app
| sort - dns_queries
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemotePort == 53
| where RemoteIPType == "Public"                 // endpoint talking DNS straight to a public server, bypassing internal resolver
| summarize DnsQueries = count(), Resolvers = make_set(RemoteIP, 20)
         by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by DnsQueries desc
```

### DNS TXT/NULL record C2 & exfiltration: high-volume rare-record-type queries from one host

`UC_121_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS where DNS.record_type IN ("TXT","NULL") by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| rex field=query "(?<parent>[a-z0-9-]+\.[a-z0-9-]+)$"
| stats sum(count) as txt_null_queries dc(query) as unique_names by src parent record_type
| where txt_null_queries>50
| sort - txt_null_queries
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

### DNS tunneling / TXT-heavy domain queries

`UC_DNS_TUNNEL` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
    where DNS.message_type="QUERY"
    by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| eval qlen=len(query)
| where qlen > 50
| rex field=query "(?<second_level_domain>[\w-]+\.[\w-]+)$"
| stats sum(count) AS qcount, dc(query) AS unique_subs, max(qlen) AS max_label
    by src, second_level_domain
| where qcount > 100 AND unique_subs > 20
| sort - qcount
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 53 and isnotempty(RemoteUrl)
| extend qlen = strlen(RemoteUrl)
| where qlen > 50
| extend SecondLevelDomain = extract(@"([\w-]+\.[a-zA-Z]{2,})$", 1, RemoteUrl)
| summarize qcount = count(), uniqueSubs = dcount(RemoteUrl), maxLabel = max(qlen)
    by DeviceName, SecondLevelDomain
| where qcount > 100 and uniqueSubs > 20
| order by qcount desc
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
  - IP / domain IOC(s): `testinglab.ru`, `crust.testinglab.ru`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
