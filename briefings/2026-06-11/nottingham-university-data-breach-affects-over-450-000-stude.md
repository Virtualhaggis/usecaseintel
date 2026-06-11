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
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1213** — Data from Information Repositories
- **T1005** — Data from Local System
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1074.001** — Local Data Staging
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1078.002** — Valid Accounts: Domain Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PeopleSoft Internet Architecture gadget-chain deserialization exploitation

`UC_30_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.src) as src values(Web.user_agent) as user_agent from datamodel=Web where Web.http_method=POST (Web.url="*/psp/*" OR Web.url="*/psc/*" OR Web.url="*/psigw/*" OR Web.url="*/pspc/*" OR Web.url="*/PSIGW/HttpListeningConnector*" OR Web.url="*/pls/*") by Web.dest Web.src Web.url | `drop_dm_object_name(Web)` | where match(url, "(?i)(rO0AB|aced0005|XMLDecoder|java\.util\.HashMap|CommonsCollections|InvokerTransformer|TemplatesImpl)")
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (8000, 8080, 443, 80)
| where RemoteUrl has_any ("/psp/", "/psc/", "/psigw/", "/PSIGW/HttpListeningConnector", "/pls/")
| where InitiatingProcessFileName has_any ("PSAPPSRV.exe", "java.exe", "w3wp.exe")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Bulk export of PSOPRDEFN / PERSONAL_DATA rows by PeopleSoft service account

`UC_30_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Processes.process) as cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("sqlplus.exe","sqlplus","sqlcl.exe","datapump","expdp","exp.exe") by Processes.dest Processes.user Processes.process_name _time span=1h | `drop_dm_object_name(Processes)` | where match(cmd, "(?i)(PSOPRDEFN|PERSONAL_DATA|PS_PERS_DATA|PS_STDNT|PS_ACCOUNT|PS_HOME_ADDR|PS_DIVERS_ETHNIC|PSBIRTH)") | where count > 1
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("sqlplus.exe","sqlcl.exe","expdp.exe","exp.exe","sqlcmd.exe","bcp.exe")
   or InitiatingProcessFileName in~ ("sqlplus.exe","sqlcl.exe","expdp.exe")
| where ProcessCommandLine has_any ("PSOPRDEFN","PERSONAL_DATA","PS_PERS_DATA","PS_STDNT_AID","PS_ACCOUNT","PS_HOME_ADDR","PS_DIVERS_ETHNIC","PSBIRTHDATE","PSBIRTHCOUNTRY","PS_EMPLOYEES")
   or ProcessCommandLine matches regex @"(?i)(SELECT\s+\*\s+FROM\s+PS|spool\s+\S+\.csv|@\S+\.sql)"
| extend BulkHint = iff(ProcessCommandLine has_any ("spool","expdp","exp ","-c ","BULK COLLECT"), "bulk", "single")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, BulkHint
| order by Timestamp desc
```

### Outbound C2 / staging to ShinyHunters PeopleSoft campaign IOC infrastructure

`UC_30_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24")) by All_Traffic.dest All_Traffic.src | `drop_dm_object_name(All_Traffic)` | appendcols [| tstats `summariesonly` count from datamodel=Network_Resolution.DNS where DNS.query="azurenetfiles.net" OR DNS.query="*.azurenetfiles.net" by DNS.src DNS.query | `drop_dm_object_name(DNS)`]
```

**Defender KQL:**
```kql
let IOCIPs = dynamic(["142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24"]);
let IOCDomain = "azurenetfiles.net";
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (IOCIPs) or RemoteUrl has IOCDomain
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Suspicious archiving of PeopleSoft data on DB / app tier prior to exfiltration

`UC_30_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Processes.process) as cmd values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name IN ("7z.exe","7za.exe","winrar.exe","rar.exe","zip.exe","tar.exe","makecab.exe") by Processes.dest Processes.process_name _time span=10m | `drop_dm_object_name(Processes)` | where match(cmd, "(?i)(PS_HOME|PS_APP_HOME|PS_CFG_HOME|PSAPPSRV|portal|student|finance|payroll|\\.dmp|\\.csv|exp_|spool)")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("7z.exe","7za.exe","WinRAR.exe","rar.exe","zip.exe","tar.exe","makecab.exe","powershell.exe")
| where ProcessCommandLine has_any ("PS_HOME","PS_APP_HOME","PS_CFG_HOME","PSAPPSRV","\\portal\\","student","finance","payroll",".dmp",".csv")
   or ProcessCommandLine matches regex @"(?i)(Compress-Archive|7z\s+a\s+|rar\s+a\s+|tar\s+-?c)"
| join kind=inner (
   DeviceInfo | where Timestamp > ago(14d)
   | summarize arg_max(Timestamp, *) by DeviceId
   | where DeviceName has_any ("psapp","peoplesoft","oraapp","oradb","campus","sis")
) on DeviceId
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### PeopleSoft service account privileged use across federated campus instances

`UC_30_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Authentication.src) as src values(Authentication.dest) as dest dc(Authentication.dest) as dest_count dc(Authentication.src) as src_count from datamodel=Authentication where Authentication.user IN ("PS","PSAPPS","VP1","PSADMIN","psadmin","peoplesoft") by Authentication.user _time span=30m | where dest_count > 2 OR src_count > 2
```

**Defender KQL:**
```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where AccountName in~ ("PS","PSAPPS","VP1","PSADMIN","peoplesoft","PSACCESS")
| where ActionType in ("LogonSuccess","LogonAttempted")
| extend Region = case(
    DeviceName has_any ("-uk","nottingham","jubilee","\\UK\\"), "UK",
    DeviceName has_any ("-my","malaysia","-sgr","\\MY\\"), "MY",
    DeviceName has_any ("-cn","ningbo","china","\\CN\\"), "CN",
    "OTHER")
| summarize Regions = make_set(Region), Devices = make_set(DeviceName), Logons = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountName, bin(Timestamp, 1h)
| where array_length(Regions) >= 2
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

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
