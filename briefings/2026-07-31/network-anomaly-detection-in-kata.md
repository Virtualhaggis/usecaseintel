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
- **T1048.003** — Exfiltration Over Alternative Protocol: Unencrypted Non-C2
- **T1048.003** — Exfiltration Over Alternative Protocol
- **T1572** — Protocol Tunneling

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Kerberoasting: single account receives TGS-REP for many unique non-system SPNs

`UC_103_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* source="WinEventLog:Security" EventCode=4769 Service_Name!="krbtgt" Service_Name!="*$" (Ticket_Encryption_Type="0x17" OR Ticket_Encryption_Type="0x18" OR Ticket_Encryption_Type="0x11" OR Ticket_Encryption_Type="0x12") Failure_Code="0x0"
| eval requester=mvindex(Account_Name,0)
| bucket _time span=10m
| stats dc(Service_Name) as unique_spns values(Service_Name) as spns values(Ticket_Encryption_Type) as enc_types by _time, Client_Address, requester
| where unique_spns >= 10
| sort - unique_spns
```

### Kerberoasting RC4 downgrade: TGS requested with weakened encryption for a non-machine service account

`UC_103_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17" Ticket_Options="0x40810000" Service_Name!="krbtgt" Service_Name!="*$" Failure_Code="0x0"
| eval requester=mvindex(Account_Name,0)
| stats count values(Service_Name) as targeted_spns min(_time) as firstTime max(_time) as lastTime by Client_Address, requester
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

### DNS tunneling to KATA test infrastructure testinglab.ru / crust.testinglab.ru

`UC_103_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*testinglab.ru" OR DNS.query="*crust.testinglab.ru") by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name("DNS")`
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl endswith "testinglab.ru"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName
| order by Timestamp desc
```

### DNS tunneling behavioural: high-volume long/high-entropy subdomains under a single parent domain per host

`UC_103_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Resolution.DNS where DNS.message_type="QUERY" by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name("DNS")`
| eval label=mvindex(split(query,"."),0)
| eval parent=mvindex(split(query,"."),-2).".".mvindex(split(query,"."),-1)
| eval qlen=len(query)
| stats dc(label) as unique_labels avg(qlen) as avg_len max(qlen) as max_len values(record_type) as rtypes count by src parent
| where unique_labels >= 50 AND avg_len >= 50
| sort - unique_labels
```

### DNS queries to unknown/unauthorised resolvers (KATA 'Queries to unknown DNS servers')

`UC_103_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=53 All_Traffic.dest_category!="internal_dns" (All_Traffic.dest!="8.8.8.8" AND All_Traffic.dest!="8.8.4.4" AND All_Traffic.dest!="1.1.1.1") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name("All_Traffic")`
| where NOT cidrmatch("10.0.0.0/8",dest) AND NOT cidrmatch("172.16.0.0/12",dest) AND NOT cidrmatch("192.168.0.0/16",dest)
| sort - count
```

**Defender KQL:**
```kql
// Internal host doing DNS to a public resolver that is not corporate DNS.
// Replace the ApprovedResolvers set with your sanctioned DNS server IPs.
let ApprovedResolvers = dynamic(["8.8.8.8","8.8.4.4","1.1.1.1"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 53
| where RemoteIPType == "Public"
| where RemoteIP !in (ApprovedResolvers)
| summarize ConnCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, InitiatingProcessFileName, RemoteIP
| order by ConnCount desc
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

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
