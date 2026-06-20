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
Sources told BleepingComputer of the attack yesterday, telling us that numerous organizations had their Salesforce data stolen and were now being extorted by the relatively new extortion group.
Cyb…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `138.226.246.94`
- **IPv4 (defanged):** `212.86.125.24`
- **IPv4 (defanged):** `213.111.148.90`
- **IPv4 (defanged):** `94.154.32.160`
- **Domain (defanged):** `gofile.io`
- **Domain (defanged):** `house.com.au`
- **Domain (defanged):** `robinskitchen.com.au`
- **Domain (defanged):** `baccarat.com.au`

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
- **T1567** — Exfiltration Over Web Service
- **T1199** — Trusted Relationship
- **T1530** — Data from Cloud Storage
- **T1526** — Cloud Service Discovery
- **T1087.004** — Account Discovery: Cloud Account
- **T1213** — Data from Information Repositories

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound/SaaS connections to Icarus extortion group IPs (Klue/Salesforce campaign)

`UC_55_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_ports values(All_Traffic.src) as src values(All_Traffic.dest) as dest from datamodel=Network_Traffic where (All_Traffic.dest in ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160") OR All_Traffic.src in ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160")) by All_Traffic.src All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let IcarusIPs = dynamic(["138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160"]);
union isfuzzy=true
(DeviceNetworkEvents
 | where Timestamp > ago(30d)
 | where RemoteIP in (IcarusIPs)
 | project Timestamp, Source="DeviceNetworkEvents", DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
(CloudAppEvents
 | where Timestamp > ago(30d)
 | where IPAddress in (IcarusIPs)
 | project Timestamp, Source="CloudAppEvents", Application, ActionType, AccountDisplayName, IPAddress, UserAgent, ObjectName, ActivityType),
(AADSignInEventsBeta
 | where Timestamp > ago(30d)
 | where IPAddress in (IcarusIPs)
 | project Timestamp, Source="AADSignIn", AccountUpn, Application, ApplicationId, IPAddress, UserAgent, Country, ErrorCode)
| order by Timestamp desc
```

### Klue Battlecards connected app Salesforce activity from Icarus IPs

`UC_55_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`salesforce_event_monitoring` (CLIENT_NAME="Klue" OR CLIENT_NAME="Battlecards" OR APPLICATION_NAME="Klue Battlecards" OR CONNECTED_APP_NAME="Klue*") AND (CLIENT_IP="138.226.246.94" OR CLIENT_IP="212.86.125.24" OR CLIENT_IP="213.111.148.90" OR CLIENT_IP="94.154.32.160") | stats count min(_time) as firstSeen max(_time) as lastSeen values(URI) as uris values(USER_ID) as users dc(URI) as distinctEndpoints by CLIENT_IP CONNECTED_APP_NAME | convert ctime(firstSeen) ctime(lastSeen) | sort - count
```

**Defender KQL:**
```kql
let IcarusIPs = dynamic(["138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has_any ("Salesforce")
| where IPAddress in (IcarusIPs)
   or tostring(RawEventData) has_any ("Klue","Battlecards")
| extend KlueApp = tostring(RawEventData) has_any ("Klue","Battlecards")
| where KlueApp or IPAddress in (IcarusIPs)
| summarize EventCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            ActionTypes = make_set(ActionType, 20),
            Objects = make_set(ObjectName, 20),
            UserAgents = make_set(UserAgent, 10)
          by AccountDisplayName, IPAddress, Application, City, CountryCode
| order by FirstSeen desc
```

### Salesforce REST API mass /sobjects enumeration via OAuth connected app

`UC_55_7` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`salesforce_event_monitoring` URI="*/services/data/v59.0/sobjects*" | bin _time span=15m | stats count dc(URI) as distinct_sobjects values(URI) as sample_uris min(_time) as firstSeen max(_time) as lastSeen by _time CLIENT_IP USER_ID CONNECTED_APP_NAME | where count > 50 OR distinct_sobjects > 20 | convert ctime(firstSeen) ctime(lastSeen) | sort - count
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| extend Uri = tostring(parse_json(tostring(RawEventData)).URI)
| extend ClientId = tostring(parse_json(tostring(RawEventData)).CLIENT_ID)
| extend ConnectedApp = tostring(parse_json(tostring(RawEventData)).CONNECTED_APP_NAME)
| where Uri has "/services/data/v59.0/sobjects" or ActivityType has "sobjects"
| summarize ApiCalls = count(),
            DistinctEndpoints = dcount(Uri),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            SampleUris = make_set(Uri, 25)
          by bin(Timestamp, 15m), AccountDisplayName, IPAddress, ConnectedApp, ClientId
| where ApiCalls > 50 or DistinctEndpoints > 20
| order by FirstSeen desc
```

### Salesforce /query API burst exfiltration via single OAuth principal

`UC_55_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`salesforce_event_monitoring` URI="*/services/data/v59.0/query*" | bin _time span=15m | stats count as queryCount dc(URI) as distinctQueries sum(ROW_COUNT) as totalRows values(USER_ID) as users by _time CLIENT_IP CONNECTED_APP_NAME USER_ID | where queryCount >= 500 OR totalRows >= 100000 | sort - queryCount
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| extend Uri = tostring(parse_json(tostring(RawEventData)).URI)
| extend ConnectedApp = tostring(parse_json(tostring(RawEventData)).CONNECTED_APP_NAME)
| extend RowsReturned = tolong(parse_json(tostring(RawEventData)).ROW_COUNT)
| where Uri has "/services/data/v59.0/query" or ActivityType has "Query"
| summarize QueryCount = count(),
            DistinctQueries = dcount(Uri),
            TotalRows = sum(RowsReturned),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            UserAgents = make_set(UserAgent, 5)
          by bin(Timestamp, 15m), AccountDisplayName, IPAddress, ConnectedApp
| where QueryCount >= 500 or TotalRows >= 100000
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
  - IP / domain IOC(s): `138.226.246.94`, `212.86.125.24`, `213.111.148.90`, `94.154.32.160`, `gofile.io`, `house.com.au`, `robinskitchen.com.au`, `baccarat.com.au`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
