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
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1071.004** — Application Layer Protocol: DNS
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1190** — Exploit Public-Facing Application
- **T1203** — Exploitation for Client Execution
- **T1005** — Data from Local System
- **T1213** — Data from Information Repositories
- **T1020** — Automated Exfiltration
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1074.001** — Local Data Staging

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound connection to ShinyHunters PeopleSoft-campaign egress IPs (142.11.200.186-190 / 108.174.202.99 / 176.120.22.24)

`UC_44_2` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24") by All_Traffic.dest All_Traffic.src_category | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let ShinyHuntersIPs = dynamic(["142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (ShinyHuntersIPs)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### DNS resolution or connection to ShinyHunters staging domain azurenetfiles.net

`UC_44_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where DNS.query="azurenetfiles.net" OR DNS.query="*.azurenetfiles.net" by DNS.query DNS.src | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
(DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl endswith "azurenetfiles.net"
| project Timestamp, DeviceName, EventTable="DeviceNetworkEvents", RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
(DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| where AdditionalFields has "azurenetfiles.net"
| project Timestamp, DeviceName, EventTable="DeviceEvents", RemoteUrl=tostring(parse_json(AdditionalFields).DnsQueryString), RemoteIP=tostring(parse_json(AdditionalFields).IpResponse), InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName)
| order by Timestamp desc
```

### PeopleSoft web-tier exploitation pattern — suspicious POST to /psp/ /psc/ /psigw/ from external IP

`UC_44_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.user_agent) as ua values(Web.status) as status values(Web.bytes_in) as bytes_in from datamodel=Web.Web where Web.http_method="POST" AND (Web.url="*/psp/*" OR Web.url="*/psc/*" OR Web.url="*/psigw/*" OR Web.url="*PSIGW/peoplesoftserviceslistening*" OR Web.url="*/pspc/*") by Web.src Web.dest Web.url | `drop_dm_object_name(Web)` | where bytes_in > 50000 OR like(ua, "%java%") OR like(ua, "%python-requests%") OR like(ua, "%curl%") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe","PSAPPSRV.EXE","PSPRCSRV.EXE","httpd.exe","w3wp.exe","nginx.exe")
| where RemotePort in (443,80,8000,8080,7000,7777,10200)
| where RemoteIPType == "Public"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has_any ("psp","psc","psigw","peoplesoftserviceslistening","PSEMHUB")
) on DeviceId
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, ProcessCommandLine
| order by Timestamp desc
```

### Bulk PeopleSoft student / finance table export — anomalous SELECT volumes from PS_* tables

`UC_44_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name IN ("sqlplus.exe","sqlcmd.exe","psql.exe","mysql.exe","sqldeveloper.exe","sqlplus","sqlcmd","psql") AND (Processes.process="*PS_PERSONAL_DATA*" OR Processes.process="*PS_PERS_NID*" OR Processes.process="*PS_STDNT_ENRL*" OR Processes.process="*PS_ACCOUNT_RCV*" OR Processes.process="*PS_SF_BILLING*" OR Processes.process="*spool*" OR Processes.process="*-o*.csv*" OR Processes.process="*outfile*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let DbClients = dynamic(["sqlplus.exe","sqlcmd.exe","psql.exe","mysql.exe","sqldeveloper.exe","SSMS.exe","bcp.exe"]);
let PSDataTables = dynamic(["PS_PERSONAL_DATA","PS_PERS_NID","PS_NAMES","PS_STDNT_ENRL","PS_ACCOUNT_RCV","PS_SF_BILLING_HDR","PS_SF_PAYMENT","PS_ADDRESSES","PS_PERS_DATA_EFFDT","PS_EMPLOYMENT"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (DbClients)
| where ProcessCommandLine has_any (PSDataTables) or ProcessCommandLine has_any ("spool ","OUTFILE"," -o ","-out=","INTO OUTFILE","bcp out")
| extend HourUTC = datetime_part("hour", Timestamp)
| extend OutOfHours = iff(HourUTC < 6 or HourUTC > 19, "yes", "")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, OutOfHours
| order by Timestamp desc
```

### Archive creation containing PeopleSoft / student-record data — staging for ShinyHunters publication

`UC_44_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name IN ("7z.exe","7za.exe","winrar.exe","rar.exe","tar.exe","makecab.exe") AND (Processes.process="*ps_*" OR Processes.process="*peoplesoft*" OR Processes.process="*student*" OR Processes.process="*finance*" OR Processes.process="*payroll*" OR Processes.process="*export*" OR Processes.process="*billing*" OR Processes.process="*passport*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let Archivers = dynamic(["7z.exe","7za.exe","winrar.exe","rar.exe","tar.exe","makecab.exe","WinZip32.exe","WinZip64.exe"]);
let DataKeywords = dynamic(["PS_","peoplesoft","student","enrol","finance","payroll","billing","passport","campus_portal","PSREPORTS"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (Archivers)
| where ProcessCommandLine has_any (DataKeywords)
| extend HourUTC = datetime_part("hour", Timestamp)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, HourUTC
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

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
