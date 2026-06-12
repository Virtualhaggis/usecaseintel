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
- **T1071.001** — Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1568** — Dynamic Resolution
- **T1190** — Exploit Public-Facing Application
- **T1203** — Exploitation for Client Execution
- **T1005** — Data from Local System
- **T1213** — Data from Information Repositories
- **T1020** — Automated Exfiltration
- **T1560.001** — Archive via Utility
- **T1074.001** — Local Data Staging
- **T1021.004** — SSH
- **T1570** — Lateral Tool Transfer
- **T1491.001** — Internal Defacement
- **T1486** — Data Encrypted for Impact
- **T1021** — Remote Services
- **T1078.004** — Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ShinyHunters PeopleSoft Campaign C2/Exfil Infrastructure Match

`UC_32_2` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app values(All_Traffic.dest_port) as dest_port values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24") by All_Traffic.src_ip All_Traffic.dest_ip | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*azurenetfiles.net" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)`]
```

**Defender KQL:**
```kql
let CampaignIPs = dynamic(["142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (CampaignIPs) or RemoteUrl endswith "azurenetfiles.net"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### Oracle PeopleSoft Gadget Chain Exploitation Detection

`UC_32_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where (Web.uri_path="*/pls/*" OR Web.uri_path="*/psp/*" OR Web.uri_path="*/psigw/*" OR Web.uri_path="*/PSIGW/*" OR Web.uri_path="*/PSEMHUB/*") Web.http_method=POST by Web.src Web.dest Web.uri Web.http_user_agent Web.bytes_in _time | `drop_dm_object_name(Web)` | where bytes_in > 30000 OR like(uri, "%rO0AB%") OR like(uri, "%aced0005%") OR like(uri, "%ysoserial%") OR like(uri, "%CommonsCollections%") OR like(uri, "%javassist%") | stats count min(_time) as firstSeen max(_time) as lastSeen values(uri) as uris values(http_user_agent) as ua by src dest
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("psappsrv.exe","psntsrv.exe","PSAESRV.exe","tuxedo.exe","tmadmin.exe","WSL.exe","java.exe","javaw.exe")
| where InitiatingProcessCommandLine has_any ("PSAPPSRV","PSIGW","weblogic","-Dpeoplesoft")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe","bash.exe","sh.exe","net.exe","whoami.exe","systeminfo.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Bulk Export of Student Records and Financial Data

`UC_32_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("sqlcmd.exe","sqlplus.exe","bcp.exe","mysqldump.exe","pg_dump.exe","exp.exe","expdp.exe","sqlcl.exe")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process, "(?i)(PSPERSDATA|PSBIRTHDATE|PSBIRTHCOUNTRY|PS_PERSONAL_DATA|PS_PERS_NID|PS_PERS_DATA_EFFDT|EMPLID|PS_STDNT_ENRL|PS_STDNT_AID|SF_PAYMENT|SF_INVOICE|PS_SF_PAYMENT|PS_HCR_PERSON)")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("sqlcmd.exe","sqlplus.exe","bcp.exe","mysqldump.exe","pg_dump.exe","exp.exe","expdp.exe","sqlcl.exe","sqldeveloper.exe")
| where ProcessCommandLine has_any ("PSPERSDATA","PSBIRTHDATE","PSBIRTHCOUNTRY","PS_PERSONAL_DATA","PS_PERS_NID","PS_PERS_DATA_EFFDT","EMPLID","PS_STDNT_ENRL","PS_STDNT_AID","SF_PAYMENT","SF_INVOICE","PS_SF_PAYMENT","PS_HCR_PERSON")
   or ProcessCommandLine matches regex @"(?i)SELECT.*FROM\s+PS_"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Data Staging and Archiving for Dark Web Publication

`UC_32_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("7z.exe","7za.exe","WinRAR.exe","Rar.exe","rar.exe","tar.exe","zip.exe","makecab.exe")) OR (Processes.process_name="powershell.exe" AND Processes.process="*Compress-Archive*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process, "(?i)(student|records|payment|financial|portal|peoplesoft|campus|psoft|EMPLID|SF_|PS_)") OR match(parent_process_name, "(?i)(psappsrv|psntsrv|sqlservr|oracle)")
```

**Defender KQL:**
```kql
let ArchiveTools = dynamic(["7z.exe","7za.exe","WinRAR.exe","Rar.exe","rar.exe","tar.exe","zip.exe","makecab.exe"]);
let TargetMarkers = dynamic(["student","records","payment","financial","portal","peoplesoft","campus","psoft","EMPLID","SF_","PS_","export","dump","backup"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (ArchiveTools) or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("Compress-Archive","System.IO.Compression","ZipFile.CreateFromDirectory"))
| where ProcessCommandLine has_any (TargetMarkers)
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType == "FileCreated"
    | where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar" or FileName endswith ".tar" or FileName endswith ".tar.gz" or FileName endswith ".cab"
    | where FileSize > 1073741824
    | project DeviceId, ArchiveFile = FolderPath, ArchiveSize = FileSize, ArchiveTime = Timestamp
) on DeviceId
| where abs(datetime_diff('minute', ArchiveTime, Timestamp)) <= 30
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ArchiveFile, ArchiveSize, InitiatingProcessFileName
| order by Timestamp desc
```

### ShinyHunters uon_fanout.sh SSH Lateral Spread

`UC_32_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process_name IN ("ssh","scp","rsync","sshpass","pssh","clusterssh","ansible")) by Processes.dest Processes.user Processes.process Processes.parent_process_name _time | `drop_dm_object_name(Processes)` | where match(process, "(?i)(uon_fanout|for\s+host\s+in|while\s+read\s+host|pssh\s+-h|sshpass)") | stats count dc(eval(coalesce(replace(process,"^.*@([\w\.-]+).*$","\1"),"")))  as hosts_touched values(process) as samples by dest user | where hosts_touched >= 5
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("ssh","scp","rsync","sshpass","pssh","clusterssh")
| where ProcessCommandLine has_any ("uon_fanout","for host in","while read host","pssh -h","sshpass -p")
   or (InitiatingProcessFileName in~ ("bash","sh","zsh") and InitiatingProcessCommandLine has_any ("fanout","sweep","hosts.txt","targets.txt"))
| summarize HostsHit = dcount(extract(@"@([\w\.-]+)", 1, ProcessCommandLine)), Samples = make_set(ProcessCommandLine, 10), First = min(Timestamp), Last = max(Timestamp)
          by DeviceName, AccountName, bin(Timestamp, 30m)
| where HostsHit >= 5 or array_length(Samples) >= 5
| order by Last desc
```

### ShinyHunters README Defacement Marker File Write

`UC_32_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.action=created by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name _time | `drop_dm_object_name(Filesystem)` | where match(file_name, "(?i)README.*\.(txt|md|html|htm)$") OR match(file_name, "(?i)(shinyhunters|leaked-by|shouted-by|shiny_hunters)") | stats count min(_time) as firstSeen max(_time) as lastSeen values(file_path) as paths values(process_name) as procs by dest user file_name
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where (FileName matches regex @"(?i)^README.*\.(txt|md|html|htm)$")
   or FileName has_any ("ShinyHunters","SHINYHUNTERS","shinyhunters","shiny_hunters","leaked-by","shouted-by")
   or FolderPath has_any ("ShinyHunters","shinyhunters")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### Cross-Campus PeopleSoft Lateral Movement

`UC_32_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Authentication.Authentication where Authentication.action=success by Authentication.user Authentication.src Authentication.dest Authentication.app _time | `drop_dm_object_name(Authentication)` | where match(app, "(?i)peoplesoft") OR match(dest, "(?i)(psoft|psapp|psprd|peoplesoft)") | iplocation src | stats values(Country) as countries dc(Country) as country_count values(src) as src_ips values(dest) as targets min(_time) as firstSeen max(_time) as lastSeen by user | where country_count >= 2 AND mvfind(countries, "(?i)(United Kingdom|Malaysia|China)") >= 0
```

**Defender KQL:**
```kql
let LookbackHours = 6h;
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where ApplicationId !startswith "00000" // exclude Microsoft 1P
| where Application has_any ("PeopleSoft","Campus Solutions","PSOFT","psoft","psprd")
| where Status has "Success"
| summarize CountryCount = dcount(Country), Countries = make_set(Country), Cities = make_set(City), Apps = make_set(ResourceDisplayName), IPs = make_set(IPAddress), First = min(Timestamp), Last = max(Timestamp)
          by AccountUpn, bin(Timestamp, LookbackHours)
| where CountryCount >= 2
| where Countries has_any ("United Kingdom","Malaysia","China")
| order by Last desc
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

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
