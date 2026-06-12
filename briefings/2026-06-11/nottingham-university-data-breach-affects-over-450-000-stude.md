# [HIGH] Nottingham University data breach affects over 450,000 students

**Source:** BleepingComputer
**Published:** 2026-06-11
**Article:** https://www.bleepingcomputer.com/news/security/nottingham-university-data-breach-affects-over-450-000-students/

## Threat Profile

Nottingham University data breach affects over 450,000 students 
By Sergiu Gatlan 
June 11, 2026
03:27 AM
0 
The University of Nottingham confirmed on Wednesday that a hacking group gained access to its student records system in a breach affecting both current students and alums.
Nottingham University is a public research university with 7,000 staff and over 46,000 students, ranking in the Top 20 in the United Kingdom and the Top 100 worldwide.
The university told BleepingComputer in an emailed …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `142.11.200.186`
- **IPv4 (defanged):** `142.11.200.187`
- **IPv4 (defanged):** `142.11.200.188`
- **IPv4 (defanged):** `142.11.200.189`
- **IPv4 (defanged):** `142.11.200.190`
- **IPv4 (defanged):** `108.174.202.99`
- **IPv4 (defanged):** `176.120.22.24`
- **Domain (defanged):** `azurenetfiles.net`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1203** — Exploitation for Client Execution
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1041** — Exfiltration Over C2 Channel
- **T1005** — Data from Local System
- **T1020** — Automated Exfiltration
- **T1560.001** — Archive via Utility
- **T1074.001** — Local Data Staging

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Oracle PeopleSoft PSEMHUB exploitation (CVE-2026-35273) — inbound RCE traffic

`UC_36_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url="*/psp/*" OR Web.url="*/psc/*" OR Web.url="*/pls/*" OR Web.url="*/psigw/*" OR Web.url="*/PSEMHUB/*" OR Web.url="*/cs/*/integrationGateway*" (Web.src IN ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24") OR Web.http_user_agent IN ("Java/*","python-requests/*","curl/*") AND (Web.http_method=POST AND Web.bytes_in>5000)) by Web.src Web.dest Web.url Web.http_method Web.status Web.http_user_agent | `drop_dm_object_name(Web)` | where firstTime>=relative_time(now(),"-7d")
```

**Defender KQL:**
```kql
let CampaignIPs = dynamic(["142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort in (8000, 8443, 8888, 443, 80)
| where RemoteIP in (CampaignIPs)
   or InitiatingProcessFileName in~ ("PSAESRV.exe","PSAPPSRV.exe","psadmin.exe","java.exe","tuxedo.exe")
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### C2 callback to azurenetfiles.net masquerading as Azure Files

`UC_36_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="azurenetfiles.net" OR DNS.query="*.azurenetfiles.net" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | where firstTime>=relative_time(now(),"-30d")
```

**Defender KQL:**
```kql
union
(DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has "azurenetfiles.net"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort),
(DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | where AdditionalFields has "azurenetfiles.net"
  | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields)
| order by Timestamp desc
```

### Outbound connections to ShinyHunters PeopleSoft campaign IP infrastructure

`UC_36_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count sum(All_Traffic.bytes_out) as total_bytes_out min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24") AND All_Traffic.direction="outbound" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | where firstTime>=relative_time(now(),"-30d")
```

**Defender KQL:**
```kql
let CampaignIPs = dynamic(["142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where RemoteIP in (CampaignIPs)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Connections=count(),
            BytesEstimate=countif(RemotePort in (80,443,8443))
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by FirstSeen desc
```

### Bulk PeopleSoft student/finance table extract followed by external egress

`UC_36_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count sum(All_Traffic.bytes_out) as out_bytes from datamodel=Network_Traffic.All_Traffic where All_Traffic.src_category="peoplesoft" AND All_Traffic.direction="outbound" AND All_Traffic.dest_category!="internal" by All_Traffic.src All_Traffic.dest _time span=15m | `drop_dm_object_name(All_Traffic)` | where out_bytes > 1073741824 | join type=inner src [search index=oracle_audit OR index=peoplesoft sourcetype="oracle:audit" (object_name="PS_PERSON" OR object_name="PS_PERS_DATA_EFFDT" OR object_name="PS_STDNT_CAR_TERM" OR object_name="PS_BI_HDR") action=SELECT | stats sum(rows_returned) as rows by db_user host | where rows > 10000 | rename host as src]
```

**Defender KQL:**
```kql
let WindowMin = 60m;
let BulkEgress = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("ConnectionSuccess","ConnectionAttempt")
    | where RemoteIPType == "Public"
    | summarize TotalConnections=count(),
                EgressBucket=bin(Timestamp, 15m)
                by DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, EgressBucket=bin(Timestamp, 15m)
    | where TotalConnections > 200;
let PSHosts = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("PSAESRV.exe","PSAPPSRV.exe","psadmin.exe","tuxedo.exe","sqlplus.exe")
       or ProcessCommandLine has_any ("PS_PERSON","PS_PERS_DATA_EFFDT","PS_STDNT_CAR_TERM","PSOPRDEFN","PS_BI_HDR","emplid","select * from ps_")
    | distinct DeviceName, BulkActivityTime=Timestamp;
BulkEgress
| join kind=inner PSHosts on DeviceName
| where EgressBucket between (BulkActivityTime - WindowMin .. BulkActivityTime + WindowMin)
| project EgressBucket, DeviceName, RemoteIP, InitiatingProcessFileName, TotalConnections, BulkActivityTime
```

### PeopleSoft host archives student-record directories prior to exfil

`UC_36_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("7z.exe","7za.exe","WinRAR.exe","rar.exe","tar.exe","zip.exe","makecab.exe") OR Processes.process_name="powershell.exe") AND (Processes.process IN ("*Compress-Archive*","*-mx9*","*a -t7z*","*a -tzip*","*tar -czf*")) AND (Processes.process IN ("*student*","*finance*","*billing*","*campus*","*portal*","*ps_person*","*ps_bi*","*passport*")) AND Processes.dest_category="peoplesoft" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("7z.exe","7za.exe","WinRAR.exe","rar.exe","tar.exe","zip.exe","makecab.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("a -t7z","a -tzip","tar -czf","tar -cf","Compress-Archive","-mx9","-r -y")
| where ProcessCommandLine has_any ("student","finance","billing","campus","portal","ps_person","ps_bi","passport","EMPLID","PSOPRDEFN")
| where InitiatingProcessParentFileName in~ ("PSAESRV.exe","PSAPPSRV.exe","tuxedo.exe","java.exe","sqlplus.exe","oracle.exe","cmd.exe","powershell.exe")
   or DeviceName matches regex @"(?i)(ps|peoplesoft|hrms|campus)"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine
| order by Timestamp desc
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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `142.11.200.186`, `142.11.200.187`, `142.11.200.188`, `142.11.200.189`, `142.11.200.190`, `108.174.202.99`, `176.120.22.24`, `azurenetfiles.net`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
