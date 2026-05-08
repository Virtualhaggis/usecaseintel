# [HIGH] Zara data breach exposed personal information of 197,000 people

**Source:** BleepingComputer
**Published:** 2026-05-08
**Article:** https://www.bleepingcomputer.com/news/security/zara-data-breach-exposed-personal-information-of-197-000-people/

## Threat Profile

Zara data breach exposed personal information of 197,000 people 
By Sergiu Gatlan 
May 8, 2026
06:42 AM
0 


Hackers who gained access to the databases of Spanish fast-fashion retailer Zara stole data belonging to more than 197,000 customers, according to data breach notification service Have I Been Pwned.


Zara has over 1,500 company-managed and franchised stores worldwide and is the flagship brand of the Inditex Group, one of the world's largest fashion distribution groups, which also own…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1199** — Trusted Relationship
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1567** — Exfiltration Over Web Service
- **T1528** — Steal Application Access Token
- **T1566.004** — Phishing: Spearphishing Voice
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1098.005** — Account Manipulation: Device Registration

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ShinyHunters Anodot OAuth abuse — BigQuery data extraction by compromised SaaS integrator

`UC_1_3` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Change.object) as objects, values(Change.src) as src_ips, dc(Change.object) as object_count, min(_time) as first_seen, max(_time) as last_seen from datamodel=Change where Change.vendor="google" AND (Change.user="*anodot*" OR Change.user="*Anodot*") AND (Change.object_category="*bigquery*" OR Change.object_path="*bigquery.googleapis.com*") by Change.user, Change.action
| `drop_dm_object_name(Change)`
| where count > 0
| sort - count
```

**Defender KQL:**
```kql
// Defender for Cloud Apps surfaces GCP audit activity via the GCP connector
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has_any ("Google Cloud Platform","GCP","BigQuery")
| where (AccountDisplayName has "anodot" or AccountId has "anodot"
        or tostring(RawEventData) has "anodot" or tostring(AdditionalFields) has "anodot")
| where ActionType has_any ("Run query","Export","Extract","InsertJob","GetTable","ListTables","TableData")
| extend Caller = tostring(parse_json(tostring(RawEventData)).protoPayload.authenticationInfo.principalEmail),
         CallerIP = tostring(parse_json(tostring(RawEventData)).protoPayload.requestMetadata.callerIp),
         Method = tostring(parse_json(tostring(RawEventData)).protoPayload.methodName)
| project Timestamp, Application, ActionType, Caller, CallerIP, Method, ObjectName, IPAddress, CountryCode, RawEventData
| order by Timestamp desc
```

### [LLM] ShinyHunters vishing-to-SaaS chain — new MFA method enrolled then burst of distinct SaaS app sign-ins

`UC_1_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Authentication.app) as apps, dc(Authentication.app) as app_count, values(Authentication.src) as src_ips, dc(Authentication.src) as src_ip_count, min(_time) as first_seen, max(_time) as last_seen from datamodel=Authentication where Authentication.action="success" AND Authentication.app IN ("Salesforce","SAP","Slack","Adobe","Atlassian","Zendesk","Dropbox","Microsoft 365","Office 365","Google Workspace","Workday","ServiceNow","Dropbox Business") by Authentication.user, _time span=1h
| `drop_dm_object_name(Authentication)`
| where app_count >= 4
| join type=inner user [
    | tstats summariesonly=true min(_time) as mfa_reg_time from datamodel=Change where Change.action="created" AND (Change.object_category="mfa_method" OR Change.object="AuthenticationMethod" OR Change.change_type="AAA") by Change.user, _time span=1h
    | `drop_dm_object_name(Change)`
    | rename Change.user as user
  ]
| where first_seen >= mfa_reg_time AND first_seen <= mfa_reg_time + 3600
| sort - app_count
```

**Defender KQL:**
```kql
// Stage 1 — MFA / authentication-method registration in last 7d
let MfaReg = IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("Update user","User registered security info","Forced password reset")
   or AdditionalFields has_any ("AuthenticationMethod","StrongAuthentication","securityInfo","phoneAuthenticationMethod","microsoftAuthenticatorAuthenticationMethod")
| project MfaUpn = tolower(TargetAccountUpn), MfaTime = Timestamp, MfaActor = AccountUpn, MfaIp = IPAddress;
// Stage 2 — same user successfully authenticating to 4+ distinct SaaS apps within 60min of the MFA change
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where Application in~ ("Salesforce","SAP","SAP Concur","Slack","Adobe Creative Cloud","Atlassian","Atlassian Cloud","Zendesk","Dropbox","Dropbox Business","Microsoft 365","Office 365 Exchange Online","Google Workspace","Workday","ServiceNow")
| extend AccountUpnLower = tolower(AccountUpn)
| join kind=inner MfaReg on $left.AccountUpnLower == $right.MfaUpn
| where Timestamp between (MfaTime .. MfaTime + 60m)
| summarize Apps = make_set(Application,32),
            AppCount = dcount(Application),
            SourceIPs = make_set(IPAddress,16),
            Countries = make_set(Country,8),
            FirstAppSignIn = min(Timestamp),
            LastAppSignIn = max(Timestamp)
            by AccountUpn, MfaTime, MfaActor, MfaIp
| where AppCount >= 4
| order by FirstAppSignIn desc
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


## Why this matters

Severity classified as **HIGH** based on: 5 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
