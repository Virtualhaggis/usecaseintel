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
- **T1059** — Command and Scripting Interpreter
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090** — Proxy
- **T1567** — Exfiltration Over Web Service
- **T1041** — Exfiltration Over C2 Channel
- **T1213** — Data from Information Repositories
- **T1005** — Data from Local System
- **T1560** — Archive Collected Data

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### HTTP POST to Oracle PeopleSoft deserialization endpoints (gadget chain initial access)

`UC_9_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.src) as src values(Web.bytes_in) as bytes_in from datamodel=Web.Web where Web.http_method=POST (Web.url="*/psp/*" OR Web.url="*/psc/*" OR Web.url="*/PSIGW/*" OR Web.url="*/peoplesoft/*" OR Web.url="*/cs/ps/*") (Web.bytes_in>50000 OR Web.url="*PeopleSoftServiceListeningConnector*" OR Web.url="*IntegrationGateway*") by Web.dest Web.http_user_agent Web.status | `drop_dm_object_name(Web)` | where status<500
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("PSAPPSRV.exe","PSPRCSRV.exe","tuxedo.exe","java.exe","javaw.exe","w3wp.exe","httpd.exe","nginx.exe")
| where ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public"
| where RemotePort in (80,443,8000,8080,8443,7777)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, LocalPort
| order by Timestamp desc
```

### PeopleSoft Tuxedo / Java app-server spawning shells (post-exploit RCE)

`UC_9_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as path from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("PSAPPSRV.exe","PSPRCSRV.exe","PSADMIN.exe","tuxedo.exe","tmboot.exe","BBL.exe","java.exe","javaw.exe") Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","sh","bash","certutil.exe","bitsadmin.exe","curl.exe","wget.exe","rundll32.exe","regsvr32.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("PSAPPSRV.exe","PSPRCSRV.exe","PSADMIN.exe","tuxedo.exe","tmboot.exe","BBL.exe","java.exe","javaw.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","sh","bash","certutil.exe","bitsadmin.exe","curl.exe","wget.exe","rundll32.exe","regsvr32.exe","net.exe","whoami.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Outbound connection or DNS to ShinyHunters PeopleSoft campaign infrastructure

`UC_9_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24") OR All_Traffic.dest_ip="142.11.200.0/24") by All_Traffic.src All_Traffic.src_ip All_Traffic.app | `drop_dm_object_name(All_Traffic)` | appendcols [| tstats `summariesonly` count from datamodel=Network_Resolution.DNS where DNS.query="*azurenetfiles.net" by DNS.src DNS.query | `drop_dm_object_name(DNS)`]
```

**Defender KQL:**
```kql
let CampaignIPs = dynamic(["142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24"]);
let CampaignDomains = dynamic(["azurenetfiles.net"]);
(DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (CampaignIPs) or RemoteUrl has_any (CampaignDomains)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName)
| union (DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| where AdditionalFields has "azurenetfiles.net"
| project Timestamp, DeviceName, ActionType, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### Large outbound HTTPS upload from PeopleSoft application or database server

`UC_9_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` sum(All_Traffic.bytes_out) as total_bytes_out count from datamodel=Network_Traffic.All_Traffic where All_Traffic.app=ssl OR All_Traffic.dest_port IN (443,80,8443) by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | search src="*psft*" OR src="*peoplesoft*" OR src="*-ps-*" OR src="*-orcl*" OR src="*-tux*" | where total_bytes_out > 1073741824 | eval gb_out=round(total_bytes_out/1073741824,2) | table src dest_ip dest gb_out count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("PSAPPSRV.exe","PSPRCSRV.exe","tuxedo.exe","java.exe","javaw.exe","oracle.exe","tnslsnr.exe","7z.exe","7za.exe","WinRAR.exe","rar.exe","curl.exe","powershell.exe")
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize ConnectionCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Destinations = make_set(RemoteIP, 50), Urls = make_set(RemoteUrl, 50) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where ConnectionCount > 100
| order by ConnectionCount desc
```

### Bulk SELECT or export from PeopleSoft student / finance tables

`UC_9_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=oracle_audit OR sourcetype="oracle:audit" OR sourcetype="db:audit" (action_name=SELECT OR statement=SELECT*) (OBJECT_NAME="PS_STUDENT*" OR OBJECT_NAME="PS_STDNT*" OR OBJECT_NAME="PS_FIN_*" OR OBJECT_NAME="PS_CC_*" OR OBJECT_NAME="PS_PAYMENT*" OR OBJECT_NAME="PS_BILLING*" OR SQL_TEXT="*PS_STUDENT*" OR SQL_TEXT="*PS_STDNT*" OR SQL_TEXT="*PS_FIN_*" OR SQL_TEXT="*PS_CC_*") | stats count dc(OBJECT_NAME) as tables_touched values(OBJECT_NAME) as tables sum(rows_processed) as total_rows by DB_USER OS_USER USERHOST CLIENT_PROGRAM_NAME | where tables_touched > 5 OR total_rows > 100000 | sort - total_rows
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("PSAPPSRV.exe","PSPRCSRV.exe","java.exe","javaw.exe","oracle.exe","sqlplus.exe","expdp.exe","exp.exe","sqlcmd.exe")
| where ActionType == "FileCreated"
| where FileName endswith ".csv" or FileName endswith ".dmp" or FileName endswith ".sql" or FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar" or FileName endswith ".tar" or FileName endswith ".gz" or FileName endswith ".xlsx"
| where FileSize > 50000000
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, FileSize
| order by FileSize desc
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
