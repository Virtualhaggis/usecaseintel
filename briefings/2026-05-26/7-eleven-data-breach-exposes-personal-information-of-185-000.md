# [HIGH] 7-Eleven data breach exposes personal information of 185,000 people

**Source:** BleepingComputer
**Published:** 2026-05-26
**Article:** https://www.bleepingcomputer.com/news/security/7-eleven-data-breach-exposes-personal-information-of-185-000-people/

## Threat Profile

7-Eleven data breach exposes personal information of 185,000 people 
By Sergiu Gatlan 
May 26, 2026
03:01 AM
0 
The ShinyHunters extortion gang stole the personal information of over 183,000 people after hacking the systems of convenience store chain giant 7-Eleven in April, according to data breach notification service Have I Been Pwned.
Founded in 1927, 7-Eleven now operates, franchises, and licenses more than 86,000 stores worldwide, including 13,000 stores in the U.S. and Canada. 7-Eleven al…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `7-eleven.com`

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1199** — Trusted Relationship
- **T1528** — Steal Application Access Token
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1566.004** — Phishing: Spearphishing Voice
- **T1567** — Exfiltration Over Web Service
- **T1530** — Data from Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Salesforce malicious connected-app (Data Loader) OAuth authorization — ShinyHunters/UNC6040

`UC_53_4` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`comment("Requires Splunk Add-on for Salesforce; sourcetype sfdc:eventlogfile. No CIM datamodel covers Salesforce connected-app auth, so this is a raw TA search.")` index=salesforce sourcetype="sfdc:eventlogfile" (EVENT_TYPE="OAuthToken" OR EVENT_TYPE="ConnectedAppOAuthUsage" OR EVENT_TYPE="Login") | search (APP_NAME="Data Loader" OR APP_NAME="*Loader*" OR APP_NAME="*DataLoader*" OR CONNECTED_APP_ID=*) | stats count AS Auths values(CLIENT_IP) AS src_ips values(LOGIN_KEY) AS login_keys dc(CLIENT_IP) AS ip_count min(_time) AS firstSeen max(_time) AS lastSeen by USER_ID APP_NAME | sort - Auths
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has "Salesforce"
| where ActionType has_any ("Connected","OAuth","Consent","RemoteAccessAuthorization","Approve","Authorize")
    or ActivityType has_any ("OAuth","Connected","Consent")
    or tostring(RawEventData) has_any ("Data Loader","DataLoader","dataloader","oauth_device","device_flow")
| extend AppName = coalesce(tostring(RawEventData.connectedAppName), ObjectName)
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, City, ISP, UserAgent, ActionType, ActivityType, AppName, RawEventData
| order by Timestamp desc
```

### [LLM] Salesforce bulk/Bulk-API mass export burst — Salesforce data theft (ShinyHunters)

`UC_53_5` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`comment("Requires Splunk Add-on for Salesforce; sourcetype sfdc:eventlogfile. Salesforce export volume is not a CIM endpoint datamodel, so this is a raw TA aggregation.")` index=salesforce sourcetype="sfdc:eventlogfile" (EVENT_TYPE="BulkApi" OR EVENT_TYPE="BulkApiV2" OR EVENT_TYPE="ReportExport" OR EVENT_TYPE="Export") | bin _time span=1h | stats count AS ExportEvents sum(ROWS_PROCESSED) AS RowsPulled dc(ENTITY_NAME) AS DistinctObjects values(CLIENT_IP) AS src_ips values(API_TYPE) AS api_types by _time USER_ID | where ExportEvents > 50 OR RowsPulled > 50000 | sort - RowsPulled
```

**Defender KQL:**
```kql
let WindowMin = 60m;
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| where ActionType has_any ("Export","Bulk","ReportExport","Download","BulkApi")
    or ActivityType has_any ("Export","Bulk","Download")
| summarize ExportEvents = count(), DistinctObjects = dcount(ObjectName),
            Countries = make_set(CountryCode, 5), IPs = make_set(IPAddress, 8),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
        by AccountObjectId, AccountDisplayName, bin(Timestamp, WindowMin)
| where ExportEvents > 50   // empirical bulk-export burst threshold; tune to 90-day P99 per org
| order by ExportEvents desc
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
  - IP / domain IOC(s): `7-eleven.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
