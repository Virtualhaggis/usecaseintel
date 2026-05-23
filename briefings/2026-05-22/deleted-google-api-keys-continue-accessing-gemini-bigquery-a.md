# [HIGH] Deleted Google API Keys Continue Accessing Gemini, BigQuery, and Maps APIs

**Source:** Cyber Security News
**Published:** 2026-05-22
**Article:** https://cybersecuritynews.com/deleted-google-api-keys-continue-access/

## Threat Profile

Home Cyber Security News 
Deleted Google API Keys Continue Accessing Gemini, BigQuery, and Maps APIs 
By Abinaya 
May 22, 2026 
A newly disclosed issue with Google Cloud API keys reveals that deleted credentials may remain usable for up to 23 minutes, exposing projects to potential abuse even after revocation.
The finding raises concerns about delayed credential invalidation across Google’s infrastructure, particularly for sensitive services such as Gemini, BigQuery, and Google Maps APIs. Accord…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1110.004** — Brute Force: Credential Stuffing

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Google Cloud API key successfully authenticates within 30 min after DeleteKey on same project

`UC_18_4` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as deleteTime, values(Change.user) as deletedBy, values(Change.src) as deleteSrcIp from datamodel=Change where Change.action=deleted AND Change.vendor_product="Google Cloud" AND (Change.object_category="api_key" OR Change.object="apikeys.googleapis.com") by Change.object_id, Change.dest
| `drop_dm_object_name(Change)`
| eval windowEnd = deleteTime + 1800
| join type=inner object_id [
  | tstats `summariesonly` min(_time) as firstUse, max(_time) as lastUse, count, values(Authentication.app) as services, values(Authentication.src) as callerIps, values(Authentication.user_agent) as ua from datamodel=Authentication where Authentication.vendor_product="Google Cloud" AND Authentication.action=success AND Authentication.authentication_method="api_key" AND Authentication.app IN ("bigquery.googleapis.com","aiplatform.googleapis.com","generativelanguage.googleapis.com","maps-backend.googleapis.com","maps.googleapis.com") by Authentication.user, Authentication.dest
  | `drop_dm_object_name(Authentication)`
  | rename user as object_id
]
| where firstUse >= deleteTime AND firstUse <= windowEnd
| eval secondsAfterDelete = firstUse - deleteTime
| table deleteTime, secondsAfterDelete, object_id, deletedBy, deleteSrcIp, firstUse, lastUse, count, services, callerIps, ua
| sort - secondsAfterDelete
```

### [LLM] Spike in 'apikey:UNKNOWN' failed authentications to Gemini, BigQuery, or Maps APIs

`UC_18_5` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Authentication.src) as callerIps, values(Authentication.user_agent) as userAgents, dc(Authentication.src) as srcIpCount from datamodel=Authentication where Authentication.vendor_product="Google Cloud" AND Authentication.action=failure AND Authentication.user="apikey:UNKNOWN" AND Authentication.app IN ("bigquery.googleapis.com","aiplatform.googleapis.com","generativelanguage.googleapis.com","maps-backend.googleapis.com","maps.googleapis.com") by Authentication.dest, _time span=10m
| `drop_dm_object_name(Authentication)`
| where count >= 25
| sort - count
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


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
