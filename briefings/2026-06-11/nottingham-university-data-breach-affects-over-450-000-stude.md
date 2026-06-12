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
- **T1005** — Data from Local System
- **T1213** — Data from Information Repositories
- **T1020** — Automated Exfiltration
- **T1190** — Exploit Public-Facing Application
- **T1203** — Exploitation for Client Execution
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1074.001** — Data Staged: Local Data Staging
- **T1021.002** — Remote Services: SMB/Windows Admin Shares
- **T1078.002** — Valid Accounts: Domain Accounts
- **T1570** — Lateral Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound connection to known ShinyHunters PeopleSoft campaign infrastructure

`UC_43_2` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest in ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24") OR All_Traffic.dest_host="azurenetfiles.net" by All_Traffic.src All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let ShinyIPs = dynamic(["142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (ShinyIPs) or RemoteUrl has "azurenetfiles.net"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### Bulk SELECT against PeopleSoft student / personal-data tables outside business hours

`UC_43_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=oracle_audit OR index=peoplesoft_audit OR sourcetype=oracle:audit:unified
| eval table_lc=lower(coalesce(OBJECT_NAME, object_name, table_name))
| where (action="SELECT" OR ACTION_NAME="SELECT") AND (table_lc IN ("ps_personal_data","ps_names","ps_addresses","ps_phones","ps_email_addresses","ps_stdnt_enrl","ps_acad_prog","ps_stdnt_car_term","ps_payment_tbl","ps_item_sf","ps_account_sf","psoprdefn"))
| eval hour=tonumber(strftime(_time,"%H"))
| where hour<6 OR hour>20
| stats count as queries sum(coalesce(ROWS_PROCESSED,rows_returned,0)) as total_rows values(table_lc) as tables values(CLIENT_IP) as client_ips by DBUSERNAME OS_USERNAME HOST
| where total_rows>10000 OR queries>50
| sort - total_rows
```

**Defender KQL:**
```kql
let MaintenanceStart = 22h; let MaintenanceEnd = 5h;
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("sqlplus.exe","sqlplus","psae.exe","psqry.exe","sqlcmd.exe","oraagent.exe")
   or InitiatingProcessFileName in~ ("sqlplus.exe","psae.exe","psqry.exe")
| where ProcessCommandLine has_any ("PS_PERSONAL_DATA","PS_NAMES","PS_ADDRESSES","PS_PHONES","PS_EMAIL_ADDRESSES","PS_STDNT_ENRL","PS_ACAD_PROG","PS_PAYMENT_TBL","PSOPRDEFN","SELECT * FROM PS_")
| extend hour = datetime_part("hour", Timestamp)
| where hour < 6 or hour > 20
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### PeopleSoft IB/PSIGW gadget-chain deserialization exploitation

`UC_43_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.user_agent) as ua values(Web.status) as status values(Web.dest) as dest values(Web.url) as url from datamodel=Web.Web where Web.http_method=POST AND (Web.url IN ("*/psigw/*","*/pls/*","*/psp/*","*/psc/*","*/PSIGW/HttpListeningConnector*","*/PSIGW/PeopleSoftServiceListeningConnector*","*/psreports/*")) AND (Web.url="*rO0AB*" OR Web.url="*aced0005*" OR Web.http_user_agent="*ysoserial*" OR Web.http_content_type="application/x-java-serialized-object") by Web.src Web.dest Web.url Web.http_user_agent Web.http_method | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Requires PeopleSoft web tier shipping IIS/WebLogic logs to Defender via custom connector
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("w3wp.exe","java.exe","javaw.exe","PSAPPSRV.exe","PSWEBSRV.exe")
| where AdditionalFields has_any ("/psigw/","/pls/","/psp/","/psc/","HttpListeningConnector")
| where AdditionalFields has_any ("rO0AB","aced0005","ysoserial","CommonsCollections","application/x-java-serialized-object")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, AdditionalFields
| order by Timestamp desc
```

### PeopleSoft AppServer or WebLogic spawning shell / LOLBin child

`UC_43_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user values(Processes.parent_process) as parent_cmdline from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("PSAPPSRV.exe","PSWEBSRV.exe","PSPRCSRV.exe","java.exe","javaw.exe","w3wp.exe")) AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","sh","bash","/bin/sh","/bin/bash")) by Processes.dest Processes.parent_process_name Processes.process_name Processes.process Processes.user | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("PSAPPSRV.exe","PSWEBSRV.exe","PSPRCSRV.exe","java.exe","javaw.exe","w3wp.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","sh","bash")
| where InitiatingProcessCommandLine has_any ("PeopleSoft","PS_HOME","weblogic","PIA") or InitiatingProcessFolderPath has_any ("PT8","PeopleSoft","weblogic","PIA")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### PeopleSoft tier archiving / compression preceding outbound transfer

`UC_43_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name IN ("7z.exe","7za.exe","WinRAR.exe","rar.exe","zip.exe","tar.exe","makecab.exe","compact.exe")) AND (Processes.process IN ("*PS_HOME*","*PeopleSoft*","*student*","*finance*","*payment*","*portal*","*PSREPORTS*","*PS_APP_HOME*","*Bursar*","*Registrar*")) by Processes.dest Processes.process_name Processes.process Processes.parent_process_name Processes.user | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("7z.exe","7za.exe","WinRAR.exe","rar.exe","zip.exe","tar.exe","makecab.exe","compact.exe")
| where ProcessCommandLine has_any ("PS_HOME","PeopleSoft","student","finance","payment","portal","PSREPORTS","PS_APP_HOME","Bursar","Registrar","transcript","enrol")
| where AccountName !endswith "$"
| join kind=inner (DeviceInfo | summarize arg_max(Timestamp,*) by DeviceId | where MachineGroup has_any ("PeopleSoft","SIS","Campus","Bursar","Finance")) on DeviceId
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### PeopleSoft service-account cross-campus authentication / lateral movement

`UC_43_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src values(Authentication.dest) as dest values(Authentication.src_nt_domain) as src_domain from datamodel=Authentication.Authentication where (Authentication.user IN ("PS","PSAPPSRV","PSADMIN","PEOPLE","VP1","SAMPLE","PTWEBSERVER","PSEM_AGENT","PSCNVRT") OR Authentication.user="*svc_psft*" OR Authentication.user="*svc_peoplesoft*") by Authentication.user Authentication.src Authentication.dest Authentication.app | `drop_dm_object_name(Authentication)` | stats values(src) as src_ips dc(src) as src_ip_count values(dest) as dest_hosts dc(dest) as dest_host_count by user | where src_ip_count>3 OR dest_host_count>5 | sort - dest_host_count
```

**Defender KQL:**
```kql
let PSAccounts = dynamic(["ps","psappsrv","psadmin","people","vp1","sample","ptwebserver","psem_agent","pscnvrt"]);
let PSSubnets = toscalar(DeviceInfo | where MachineGroup has_any ("PeopleSoft","SIS","Campus") | summarize make_set(PublicIP));
DeviceLogonEvents
| where Timestamp > ago(7d)
| where AccountName has_any (PSAccounts) or AccountName startswith "svc_psft" or AccountName startswith "svc_peoplesoft"
| where ActionType == "LogonSuccess"
| where LogonType in (3,10) // network or RDP
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), DistinctDests=dcount(DeviceName), DistinctSrcs=dcount(RemoteIP), Devices=make_set(DeviceName, 50), SrcIPs=make_set(RemoteIP, 50) by AccountName, AccountDomain
| where DistinctDests > 5 or DistinctSrcs > 3
| order by DistinctDests desc
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

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
