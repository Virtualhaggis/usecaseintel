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
- **T1078.002** — Valid Accounts: Domain Accounts
- **T1550.003** — Use Alternate Authentication Material: Pass the Ticket
- **T1071.004** — Application Layer Protocol: DNS
- **T1048.003** — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Kerberoasting: single account harvesting TGS tickets for many distinct SPNs

`UC_103_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`comment("Event 4769 is not modelled in a CIM datamodel; DC Security log raw search")`
(source="WinEventLog:Security" OR source="XmlWinEventLog:Security") EventCode=4769 Account_Name!="*$" Service_Name!="*$" Service_Name!="krbtgt"
| bucket _time span=1h
| stats dc(Service_Name) as distinct_spns values(Service_Name) as target_spns min(_time) as firstTime max(_time) as lastTime by _time, Account_Name, Client_Address
| where distinct_spns>=10
| sort - distinct_spns
```

### Kerberoasting RC4 downgrade: TGS-REP with 0x17 encryption for non-system SPN

`UC_103_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
(source="WinEventLog:Security" OR source="XmlWinEventLog:Security") EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt" Account_Name!="*$"
| stats count values(Service_Name) as target_spns min(_time) as firstTime max(_time) as lastTime by Account_Name, Client_Address, host
| where count>=1
| sort - count
```

### Service account performing interactive/RDP logon (post-Kerberoast credential reuse)

`UC_103_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
(source="WinEventLog:Security" OR source="XmlWinEventLog:Security") EventCode=4624 (Logon_Type=2 OR Logon_Type=10) Account_Name!="*$" (Account_Name="*svc*" OR Account_Name="*sql*" OR Account_Name="*iis*" OR Account_Name="*service*" OR Account_Name="*backup*" OR Account_Name="*srv*")
| stats count min(_time) as firstTime max(_time) as lastTime values(Logon_Type) as logon_types values(Source_Network_Address) as src_ips by Account_Name, ComputerName
| sort - count
```

**Defender KQL:**
```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType in ("Interactive", "RemoteInteractive")
| where AccountName !endswith "$"
| where AccountName has_any ("svc", "sql", "iis", "service", "backup", "srv")   // service-account naming; tune to org convention
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP, RemoteDeviceName, InitiatingProcessFileName
| order by Timestamp desc
```

### DNS tunneling: high-volume / long-label queries to testinglab.ru or anomalous domains

`UC_103_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Resolution.DNS by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| eval leftlabel=mvindex(split(query,"."),0), label_len=len(leftlabel), is_ioc=if(match(query,"testinglab\.ru$"),1,0)
| where label_len>50 OR is_ioc=1
| stats sum(count) as query_count dc(query) as distinct_subdomains max(label_len) as max_label_len sum(is_ioc) as ioc_hits by src
| where ioc_hits>0 OR distinct_subdomains>=50 OR max_label_len>50
| sort - query_count
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "DnsQueryResponse"
| where isnotempty(RemoteUrl)
| extend LeftLabel = tostring(split(RemoteUrl, ".")[0])
| summarize QueryCount = count(), DistinctSubdomains = dcount(RemoteUrl), IOCHits = countif(RemoteUrl endswith "testinglab.ru"), MaxLabelLen = max(strlen(LeftLabel)), Samples = make_set(RemoteUrl, 15)
    by DeviceName, InitiatingProcessFileName
| where IOCHits > 0 or DistinctSubdomains >= 50 or MaxLabelLen > 50   // 50-char leftmost label = well above legit norms (~30)
| order by QueryCount desc
```

### DNS exfiltration channel: TXT/NULL queries with many unique encoded subdomains

`UC_103_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Resolution.DNS where (DNS.record_type="TXT" OR DNS.record_type="NULL") by DNS.src, DNS.query, DNS.record_type
| `drop_dm_object_name(DNS)`
| eval is_ioc=if(match(query,"testinglab\.ru$"),1,0)
| stats sum(count) as txt_queries dc(query) as distinct_subdomains sum(is_ioc) as ioc_hits by src, record_type
| where ioc_hits>0 OR distinct_subdomains>=30
| sort - distinct_subdomains
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
