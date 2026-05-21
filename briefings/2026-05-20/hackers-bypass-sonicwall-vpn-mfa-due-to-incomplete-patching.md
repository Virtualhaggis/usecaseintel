# [CRIT] Hackers bypass SonicWall VPN MFA due to incomplete patching

**Source:** BleepingComputer
**Published:** 2026-05-20
**Article:** https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/

## Threat Profile

Hackers bypass SonicWall VPN MFA due to incomplete patching 
By Bill Toulas 
May 20, 2026
05:19 PM
0 
Threat actors brute-forced VPN credentials and bypassed multi-factor authentication (MFA) on SonicWall Gen6 SSL-VPN appliances to deploy tools used in ransomware attacks.
During the intrusions, the hacker took between 30 and 60 minutes to log in, do network reconnaissance, test credential reuse on internal systems, and log out.
SonicWall warned in a security advisory for CVE-2024-12802 that inst…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-12802`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1133** — External Remote Services
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1078** — Valid Accounts
- **T1078.003** — Valid Accounts: Local Accounts
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1550.002** — Use Alternate Authentication Material: Pass the Hash
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1055** — Process Injection
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography
- **T1068** — Exploitation for Privilege Escalation
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1014** — Rootkit
- **T1543.003** — Create or Modify System Process: Windows Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SonicWall SSL-VPN sess="CLI" tag — scripted/automated MFA-bypass authentication

`UC_20_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
index=netfw OR index=sonicwall sourcetype="sonicwall*" sess="CLI"
| rex field=_raw "user=(?<vpn_user>[^\s]+)"
| rex field=_raw "src=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats earliest(_time) as first_seen, latest(_time) as last_seen, count by vpn_user, src_ip, host
| eval session_dur_min=round((last_seen-first_seen)/60,1)
| where session_dur_min < 120
| sort - first_seen
```

### [LLM] SonicWall SSL-VPN Event ID 238 / 1080 — CVE-2024-12802 exploitation signal

`UC_20_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
index=netfw OR index=sonicwall sourcetype="sonicwall*" (eventid=238 OR eventid=1080 OR signature_id=238 OR signature_id=1080 OR msg_id=238 OR msg_id=1080)
| rex field=_raw "user=(?<vpn_user>[^\s]+)"
| rex field=_raw "src=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats earliest(_time) as first_seen, latest(_time) as last_seen, count, values(vpn_user) as users, values(src_ip) as srcs by host, eventid
| sort - first_seen
```

### [LLM] SonicWall SSL-VPN UPN-format authentication (user@domain) succeeding without paired MFA challenge

`UC_20_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
index=netfw OR index=sonicwall sourcetype="sonicwall*" action=success user="*@*"
| rex field=user "^(?<vpn_user>[^@]+)@(?<vpn_domain>.+)$"
| rex field=_raw "src=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| join type=left vpn_user, src_ip [
    search index=netfw OR index=sonicwall sourcetype="sonicwall*" (mfa=* OR otp=* OR "MFA challenge" OR "TOTP" OR "second factor") earliest=-5m
    | rex field=user "^(?<vpn_user>[^@]+)"
    | rex field=_raw "src=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
    | stats count as mfa_events by vpn_user, src_ip ]
| where isnull(mfa_events) OR mfa_events=0
| stats earliest(_time) as first_seen, count by vpn_user, vpn_domain, src_ip
| sort - first_seen
```

### [LLM] Post-VPN RDP to domain-joined server using shared local administrator credentials within 30 minutes of SonicWall logon

`UC_20_8` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Authentication where Authentication.action=success Authentication.signature_id=4624 Authentication.authentication_method=RemoteInteractive by _time, Authentication.user, Authentication.src, Authentication.dest, Authentication.user_category
| `drop_dm_object_name("Authentication")`
| where match(user, "(?i)^(administrator|admin|localadmin|sysadmin|backup[-_]?admin)$") OR like(user, "%admin")
| join type=inner src [
    search index=netfw OR index=sonicwall sourcetype="sonicwall*" action=success earliest=-30m
    | rex field=_raw "src=(?<src>\d+\.\d+\.\d+\.\d+)"
    | rex field=_raw "user=(?<vpn_user>[^\s]+)"
    | stats values(vpn_user) as vpn_user, earliest(_time) as vpn_first_seen by src ]
| eval rdp_delay_min=round((_time-vpn_first_seen)/60,1)
| where rdp_delay_min<=30
| stats values(dest) as targets, values(user) as rdp_user, values(vpn_user) as vpn_user, count by src
```

**Defender KQL:**
```kql
let LocalAdminNames = dynamic(["administrator", "admin", "localadmin", "sysadmin", "backup-admin", "backup_admin"]);
DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| where (AccountName in~ (LocalAdminNames)) or (AccountName endswith "admin" and AccountName !endswith "$")
| where IsLocalAdmin == true
| where AccountDomain !in~ ("AzureAD", "NT AUTHORITY", "Window Manager")
| where AccountDomain =~ DeviceName // local account, domain == hostname
| summarize TargetDevices = make_set(DeviceName, 50), LogonTimes = make_list(Timestamp, 50), Sources = make_set(RemoteIP, 50), HostsTouched = dcount(DeviceName) by AccountName, AccountSid
| where HostsTouched >= 1
| order by HostsTouched desc
```

### [LLM] Cobalt Strike beacon deployment attempt on Windows host within 60 minutes of SonicWall VPN ingress

`UC_20_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process_name=rundll32.exe OR Processes.process_name=regsvr32.exe OR Processes.process_name=powershell.exe OR Processes.process_name=pwsh.exe) (Processes.process="*msagent_*" OR Processes.process="*postex_*" OR Processes.process="*status_*" OR Processes.process="*BeaconLoader*" OR Processes.process="*ReflectiveLoader*" OR (Processes.process="*StartW*" AND (Processes.process_name=rundll32.exe OR Processes.process_name=regsvr32.exe))) by _time Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name("Processes")`
```

**Defender KQL:**
```kql
let CSTokens = dynamic(["msagent_", "postex_", "status_", "BeaconLoader", "ReflectiveLoader"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any (CSTokens)
    or InitiatingProcessCommandLine has_any (CSTokens)
    or (InitiatingProcessFileName in~ ("rundll32.exe","regsvr32.exe") and ProcessCommandLine has_any ("StartW", "DllRegisterServer /s"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] BYOVD vulnerable-driver write or load attempt post-VPN intrusion to disable EDR

`UC_20_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\drivers\\*" Filesystem.file_name IN ("gdrv.sys","RTCore64.sys","mhyprot2.sys","kArrayNull.sys","procexp152.sys","dbutil_2_3.sys","truesight.sys","DBUtilDrv2.sys","AsrDrv101.sys","AsrDrv102.sys","GMER64.sys","WinRing0x64.sys","BSdrv.sys") by _time Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash
| `drop_dm_object_name("Filesystem")`
| sort - _time
```

**Defender KQL:**
```kql
let KnownVulnerableDriverNames = dynamic([
    "gdrv.sys","RTCore64.sys","mhyprot2.sys","kArrayNull.sys","procexp152.sys",
    "dbutil_2_3.sys","truesight.sys","DBUtilDrv2.sys","AsrDrv101.sys",
    "AsrDrv102.sys","GMER64.sys","BSdrv.sys","WinRing0x64.sys"
]);
union isfuzzy=true
(DeviceImageLoadEvents
    | where Timestamp > ago(7d)
    | where FileName in~ (KnownVulnerableDriverNames)
    | project Timestamp, DeviceName, ActionType="ImageLoad", FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName),
(DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FileName in~ (KnownVulnerableDriverNames)
    | where ActionType in ("FileCreated","FileRenamed","FileModified")
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName)
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-12802`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 11 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
