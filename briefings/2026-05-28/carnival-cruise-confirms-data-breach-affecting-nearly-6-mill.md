# [HIGH] Carnival Cruise confirms data breach affecting nearly 6 million people

**Source:** BleepingComputer
**Published:** 2026-05-28
**Article:** https://www.bleepingcomputer.com/news/security/carnival-cruise-confirms-data-breach-affecting-nearly-6-million-people/

## Threat Profile

Carnival Cruise confirms data breach affecting nearly 6 million people 
By Sergiu Gatlan 
May 28, 2026
06:49 AM
0 
Carnival Corporation, the world's largest cruise line operator, has confirmed a data breach affecting nearly 6 million people claimed by the ShinyHunters extortion gang in April 2026.
The cruise line giant has over 160,000 employees and served around 13.5 million guests in 2024 via a fleet of over 90 ships.
Carnival operates nine of the world's leading cruise line brands (Carnival C…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `carnivalcorp.com`

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1567** — Exfiltration Over Web Service
- **T1530** — Data from Cloud Storage
- **T1213** — Data from Information Repositories
- **T1528** — Steal Application Access Token
- **T1550.001** — Application Access Token
- **T1098.003** — Additional Cloud Roles
- **T1556.006** — Multi-Factor Authentication
- **T1078.004** — Cloud Accounts
- **T1098.005** — Device Registration

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Bulk Salesforce record export / report download by single user (UNC6040 data-theft TTP)

`UC_35_4` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count from datamodel=Authentication where Authentication.app="salesforce" Authentication.action="success" by Authentication.user Authentication.src _time span=1h | join type=outer Authentication.user [ search index=salesforce sourcetype=salesforce:eventlogfile EVENT_TYPE IN ("ReportExport","MassTransfer","BulkApi","BulkApi2","ListViewEvent","ContentDistribution","ContentDocumentLink","ApiTotalUsage") | rename USER_ID as user | stats sum(ROWS_PROCESSED) as RowsExported dc(EVENT_TYPE) as DistinctActions values(EVENT_TYPE) as ActionTypes by user ] | where RowsExported > 5000 OR DistinctActions >= 3 | sort - RowsExported
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application =~ "Salesforce"
| where ActionType has_any ("ReportExport", "MassTransfer", "BulkApi", "BulkApi2", "DataExport", "ListViewExport", "ReportRunAsync", "ContentDistributionDownload")
| summarize EventCount = count(), DistinctObjects = dcount(ObjectName), SampleActions = make_set(ActionType, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SrcIPs = make_set(IPAddress, 5), Geos = make_set(CountryCode, 5) by bin(Timestamp, 1h), AccountObjectId, AccountDisplayName
| where EventCount > 50 or DistinctObjects > 20
| order by EventCount desc
```

### [LLM] User consent to non-corporate OAuth app requesting Salesforce or mail-read scope

`UC_35_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count from datamodel=Change where Change.action="created" Change.object_category="oauth_application" by Change.user Change.object Change.object_attrs _time | rename Change.user as user Change.object as AppDisplayName Change.object_attrs as Scopes | search Scopes IN ("*Mail.Read*","*Mail.ReadWrite*","*offline_access*","*Files.Read.All*","*Sites.Read.All*","*full*","*api*","*refresh_token*") AppDisplayName!="Microsoft*" AppDisplayName!="Carnival*" | sort - _time
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in~ ("Consent to application", "Add OAuth2PermissionGrant", "Add delegated permission grant", "Add app role assignment grant to user")
| extend Raw = tostring(RawEventData)
| where Raw has_any ("Mail.Read", "Mail.ReadWrite", "offline_access", "Files.Read.All", "Sites.Read.All", "full_access", "refresh_token")
| extend AppName = tostring(parse_json(Raw).Target[0].Name)
| where isnotempty(AppName)
| where AppName !startswith "Microsoft" and AppName !has "Carnival"
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, ActionType, AppName, Raw
| order by Timestamp desc
```

### [LLM] Helpdesk-impersonation pattern: AAD MFA method registration immediately followed by sign-in from new geo

`UC_35_6` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats min(_time) as MfaTime from datamodel=Change where Change.action="modified" Change.object_category="user" (Change.object_attrs="*StrongAuthenticationMethod*" OR Change.object_attrs="*authenticationPhoneMethod*" OR Change.object_attrs="Update user*") by Change.user | rename Change.user as user | join type=inner user [ tstats min(_time) as LoginTime from datamodel=Authentication where Authentication.action="success" by Authentication.user Authentication.src Authentication.src_country | rename Authentication.user as user Authentication.src as src Authentication.src_country as country ] | where LoginTime > MfaTime AND LoginTime < MfaTime + 3600 | table user MfaTime LoginTime src country
```

**Defender KQL:**
```kql
let MFAEvents = CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in~ ("Update user", "Register security info", "User registered security info", "Admin registered security info on behalf of user", "Reset user password", "Reset password (by admin)")
| extend Raw = tostring(RawEventData)
| where Raw has_any ("StrongAuthenticationMethod", "authenticatorAppMethod", "phoneAuthenticationMethod", "PhoneNumber")
| project MFATime = Timestamp, AccountObjectId, MFAAction = ActionType, MFAIP = IPAddress;
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where IsInteractive == true
| join kind=inner MFAEvents on AccountObjectId
| where Timestamp between (MFATime .. MFATime + 1h)
| extend MinutesAfterMFAChange = datetime_diff('minute', Timestamp, MFATime)
| join kind=leftanti (AADSignInEventsBeta | where Timestamp between (ago(90d) .. ago(7d)) | distinct AccountObjectId, Country) on AccountObjectId, Country
| project MFATime, SignInTime = Timestamp, MinutesAfterMFAChange, AccountUpn, MFAAction, MFAIP, SignInIP = IPAddress, Country, City, IPAddress, UserAgent
| order by SignInTime desc
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `carnivalcorp.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
