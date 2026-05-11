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
Zara has over 1,500 company-managed and franchised stores worldwide and is the flagship brand of the Inditex Group, one of the world's largest fashion distribution groups, which also owns Bershk…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1098.005** — Account Manipulation: Device Registration
- **T1621** — Multi-Factor Authentication Request Generation
- **T1098.003** — Account Manipulation: Additional Cloud Roles
- **T1564.008** — Hide Artifacts: Email Hiding Rules
- **T1550.001** — Use Alternate Authentication Material: Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ShinyHunters (UNC6661/UNC6671) SSO sign-in from named Mandiant proxy IPs

`UC_30_3` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime, values(Authentication.dest) as dest, values(Authentication.app) as app, values(Authentication.user_agent) as user_agents from datamodel=Authentication where Authentication.action=success Authentication.src IN ("24.242.93.122","149.50.97.144","73.135.228.98","76.64.54.159","142.127.171.133") (Authentication.app IN ("azuread","aad","entra","okta","google_workspace","salesforce") OR Authentication.signature_id IN ("user.session.start","Sign-in activity")) by Authentication.user, Authentication.src, Authentication.app | `drop_dm_object_name(Authentication)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _shAttackerIps = dynamic(["24.242.93.122","149.50.97.144","73.135.228.98","76.64.54.159","142.127.171.133"]);
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where IPAddress in (_shAttackerIps)
| where ErrorCode == 0
| project Timestamp, AccountUpn, AccountObjectId, IPAddress, Country, City,
          Application, AppDisplayName, ClientAppUsed, UserAgent,
          ConditionalAccessStatus, RiskLevelDuringSignIn
| order by Timestamp desc
```

### [LLM] MFA method registered within 60 min of Entra sign-in from ShinyHunters proxy/anonymous IP

`UC_30_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true min(_time) as signin_time, values(Authentication.src) as signin_src from datamodel=Authentication where Authentication.action=success (Authentication.src IN ("24.242.93.122","149.50.97.144","73.135.228.98","76.64.54.159","142.127.171.133") OR Authentication.tag="anonymous" OR Authentication.risk_level IN ("medium","high")) Authentication.app IN ("azuread","aad","entra","okta") by Authentication.user | `drop_dm_object_name(Authentication)` | join type=inner user [ | tstats summariesonly=true min(_time) as mfa_time, values(Change.object) as mfa_object from datamodel=Change where Change.action IN ("created","modified") Change.object_category IN ("user","authentication_method","security_info") (Change.command IN ("Add registered security info","User registered security info","Register security info","Add device registration") OR Change.change_type="*MFA*") by Change.user | `drop_dm_object_name(Change)` | rename Change.user as user ] | where mfa_time >= signin_time AND (mfa_time - signin_time) <= 3600 | eval delay_min=round((mfa_time-signin_time)/60,1) | table user, signin_src, signin_time, mfa_time, delay_min, mfa_object | sort - mfa_time
```

**Defender KQL:**
```kql
let _shAttackerIps = dynamic(["24.242.93.122","149.50.97.144","73.135.228.98","76.64.54.159","142.127.171.133"]);
let _windowMin = 60;
let _suspectSignins = AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode == 0
    | where IPAddress in (_shAttackerIps) or IsAnonymousProxy == true or RiskLevelDuringSignIn in ("medium","high")
    | project SigninTime = Timestamp, AccountUpn, IPAddress, Country, Application, UserAgent;
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("User registered security info","User registered all required security info","Add registered security info","Strong Authentication phone added","Update user")
| join kind=inner _suspectSignins on $left.AccountUpn == $right.AccountUpn
| where Timestamp between (SigninTime .. SigninTime + _windowMin * 1m)
| project SigninTime, MfaChangeTime = Timestamp,
          DelayMin = datetime_diff('minute', Timestamp, SigninTime),
          AccountUpn, IPAddress, Country, Application,
          ActionType, UserAgent, AdditionalFields
| order by MfaChangeTime desc
```

### [LLM] OAuth consent granted to 'ToogleBox Recall' Gmail/M365 add-on (ShinyHunters MFA-notification hide)

`UC_30_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime, values(Change.src) as src, values(Change.user_agent) as user_agents from datamodel=Change where Change.action IN ("created","granted","modified") (Change.object_category IN ("oauth_application","oauth_grant","application") OR Change.command IN ("Consent to application","Add OAuth2PermissionGrant","Add delegated permission grant")) (Change.object="*ToogleBox*" OR Change.object_attrs="*ToogleBox*") by Change.user, Change.object, Change.vendor_product | `drop_dm_object_name(Change)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application in~ ("Microsoft Entra ID","Microsoft 365","Office 365","Google Workspace")
| where ActionType has_any ("Consent to application","Add application","Add OAuth2PermissionGrant","Add delegated permission grant","authorize","oauth2_authorize","AUTHORIZE")
| extend RawData = tostring(RawEventData)
| extend AppName = tostring(parse_json(RawData).TargetResources[0].displayName)
| where AppName has "ToogleBox" or ObjectName has "ToogleBox" or RawData has "ToogleBox Recall" or AdditionalFields has "ToogleBox"
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, City,
          UserAgent, Application, ActionType, ObjectName, AppName, ActivityObjects, AdditionalFields
| order by Timestamp desc
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

Severity classified as **HIGH** based on: 6 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
