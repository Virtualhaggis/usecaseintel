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
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1567** — Exfiltration Over Web Service
- **T1213** — Data from Information Repositories
- **T1526** — Cloud Service Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Salesforce REST API access from Icarus/Klue-breach IPs (138.226.246.94 et al.)

`UC_57_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime, values(Web.url) as urls, values(Web.http_method) as methods from datamodel=Web where Web.src IN ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160") AND Web.url="*/services/data/*" by Web.src, Web.dest, Web.user, Web.dest_zone | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - count
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has "Salesforce"
| where IPAddress in ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160")
| summarize EventCount = count(), Actions = make_set(ActionType, 20), Objects = make_set(ObjectType, 20), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountObjectId, AccountDisplayName, IPAddress, ISP, CountryCode, UserAgent
| order by EventCount desc
```

### Salesforce bulk /query exfiltration burst via abused Klue OAuth token

`UC_57_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as QueryCalls, dc(Web.uri_query) as DistinctQueries, min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where Web.url="*/services/data/v59.0/query*" by Web.src, Web.user, _time span=15m | `drop_dm_object_name(Web)` | where QueryCalls > 200 | convert ctime(firstTime) ctime(lastTime) | sort - QueryCalls
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| summarize ApiActivityCount = count(), DistinctObjects = dcount(ObjectName), SampleAction = any(ActionType), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountObjectId, AccountDisplayName, IPAddress, bin(Timestamp, 15m)
| where ApiActivityCount > 200   // ReliaQuest: ~1000 /query calls in a single 15-min burst; 200 = conservative alert floor
| order by ApiActivityCount desc
```

### Salesforce sObject enumeration recon (/services/data/v59.0/sobjects mapping)

`UC_57_7` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, dc(Web.uri_path) as DistinctObjectPaths, min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where Web.url="*/services/data/v59.0/sobjects*" by Web.src, Web.user, _time span=1h | `drop_dm_object_name(Web)` | where DistinctObjectPaths > 25 | convert ctime(firstTime) ctime(lastTime) | sort - DistinctObjectPaths
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| summarize DistinctObjectTypes = dcount(ObjectType), ObjectSample = make_set(ObjectType, 50), TotalReads = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountObjectId, AccountDisplayName, IPAddress, bin(Timestamp, 1h)
| where DistinctObjectTypes > 25   // wide object enumeration = mapping the org before targeted theft
| order by DistinctObjectTypes desc
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

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
