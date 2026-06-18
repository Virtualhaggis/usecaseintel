# [HIGH] Klue OAuth breach linked to 'Icarus' Salesforce data theft attacks

**Source:** BleepingComputer
**Published:** 2026-06-18
**Article:** https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/

## Threat Profile

Klue OAuth breach linked to 'Icarus' Salesforce data theft attacks 
By Lawrence Abrams 
June 18, 2026
10:19 AM
0 


Market intelligence platform Klue suffered a OAuth breach that enabled the "Icarus" threat actors to steal Salesforce CRM data from multiple organizations in an ongoing extortion campaign.


Sources told BleepingComputer of the attack yesterday, telling us that numerous organizations had their Salesforce data stolen and were now being extorted by the relatively new extortion gr…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `138.226.246.94`
- **IPv4 (defanged):** `212.86.125.24`
- **IPv4 (defanged):** `213.111.148.90`
- **IPv4 (defanged):** `94.154.32.160`
- **Domain (defanged):** `robinskitchen.com.au`
- **Domain (defanged):** `klue.com`

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090** — Proxy
- **T1199** — Trusted Relationship
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1526** — Cloud Service Discovery
- **T1087.004** — Account Discovery: Cloud Account
- **T1530** — Data from Cloud Storage
- **T1567** — Exfiltration Over Web Service
- **T1119** — Automated Collection

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Network egress to Icarus extortion C2 IPs (Klue OAuth campaign)

`UC_17_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.user) as user values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest in ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160") OR All_Traffic.src in ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160") by All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let IcarusIPs = dynamic(["138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160"]);
union isfuzzy=true
( DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteIP in (IcarusIPs)
  | project Timestamp, Source="Endpoint", DeviceName, AccountName=InitiatingProcessAccountName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine ),
( CloudAppEvents
  | where Timestamp > ago(30d)
  | where IPAddress in (IcarusIPs)
  | project Timestamp, Source="SaaS", DeviceName=ObjectName, AccountName=AccountDisplayName, RemoteIP=IPAddress, RemotePort=int(null), InitiatingProcessFileName=Application, InitiatingProcessCommandLine=tostring(RawEventData) ),
( AADSignInEventsBeta
  | where Timestamp > ago(30d)
  | where IPAddress in (IcarusIPs)
  | project Timestamp, Source="AAD", DeviceName=DeviceName, AccountName=AccountUpn, RemoteIP=IPAddress, RemotePort=int(null), InitiatingProcessFileName=Application, InitiatingProcessCommandLine=UserAgent )
| order by Timestamp desc
```

### Klue Battlecards connected-app activity from Icarus IPs in Salesforce

`UC_17_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`cim_Web_indexes` (sourcetype=salesforce* OR sourcetype=*cloudapps*) (connected_app="Klue*" OR app="Klue*" OR application="Klue*") (src_ip IN ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160") OR uri_path="*klue*") | stats min(_time) as firstTime max(_time) as lastTime count by src_ip user connected_app uri_path | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let IcarusIPs = dynamic(["138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has "Salesforce"
| extend ConnectedApp = tostring(RawEventData.ApplicationName), Uri = tostring(RawEventData.URI)
| where IPAddress in (IcarusIPs)
   or ConnectedApp has "Klue Battlecards"
   or tostring(RawEventData) has_any ("Klue Battlecards","klue.com")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, City, CountryCode, ISP, Application, ActionType, ConnectedApp, Uri, UserAgent, ActivityType, ObjectName
| order by Timestamp desc
```

### Salesforce REST API /sobjects schema enumeration burst per principal

`UC_17_7` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`cim_Web_indexes` sourcetype=salesforce* uri_path="*/services/data/v*/sobjects*" | bucket _time span=1h | stats dc(uri_path) as DistinctObjectPaths count as TotalHits values(connected_app) as ConnectedApps values(src_ip) as SrcIPs by _time user | where DistinctObjectPaths > 30 | sort - _time
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| extend Uri = tostring(RawEventData.URI), ConnectedApp = tostring(RawEventData.ApplicationName)
| where Uri matches regex @"/services/data/v\d+\.\d+/sobjects"
| summarize DistinctObjectPaths = dcount(Uri),
            TotalHits = count(),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            SampleConnectedApps = make_set(ConnectedApp, 10),
            SampleIPs = make_set(IPAddress, 10),
            SampleUris = make_set(Uri, 25)
            by bin(Timestamp, 1h), AccountDisplayName, AccountObjectId
| where DistinctObjectPaths > 30   // legit integrations hit a small fixed set; Icarus walks the catalog
| order by Timestamp desc
```

### Salesforce REST API /query burst — >500 calls in 15-minute window

`UC_17_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`cim_Web_indexes` sourcetype=salesforce* uri_path="*/services/data/v*/query*" | bucket _time span=15m | stats count as QueryCount dc(uri_path) as DistinctQueries values(connected_app) as ConnectedApp values(src_ip) as SrcIPs by _time user | where QueryCount > 500 | sort - QueryCount
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| extend Uri = tostring(RawEventData.URI), ConnectedApp = tostring(RawEventData.ApplicationName)
| where Uri matches regex @"/services/data/v\d+\.\d+/query"
| summarize QueryCount = count(),
            DistinctQueries = dcount(Uri),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            BurstSeconds = datetime_diff('second', max(Timestamp), min(Timestamp)),
            SrcIPs = make_set(IPAddress, 10),
            ConnectedApps = make_set(ConnectedApp, 5)
            by bin(Timestamp, 15m), AccountDisplayName, AccountObjectId
| where QueryCount > 500   // ReliaQuest observed ~1000 queries in a 15-min window from Icarus
| order by QueryCount desc
```

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
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
  - IP / domain IOC(s): `138.226.246.94`, `212.86.125.24`, `213.111.148.90`, `94.154.32.160`, `robinskitchen.com.au`, `klue.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
