# [HIGH] New Spyware Platform Lets Buyers Rebrand and Resell Android Surveillance Malware

**Source:** Cyber Security News
**Published:** 2026-05-01
**Article:** https://cybersecuritynews.com/new-spyware-platform-lets-buyers-rebrand/

## Threat Profile

Home Cyber Security News 
New Spyware Platform Lets Buyers Rebrand and Resell Android Surveillance Malware 
By Tushar Subhra Dutta 
May 1, 2026 
A new Android spyware tool is being sold openly on the internet, and it comes with something far more dangerous than its surveillance features alone. 
For a fee, anyone can buy it, put their own name and logo on it, and start selling it as their own product. 
This is not just a malware story. It is a warning about how the spyware business model is evolv…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `9864db6b5800d9e03b747c46fdef988e035cadde83077a41c5610d5d89f753a0`
- **SHA256:** `1b1d9b260deec0c612ec67579fd36fec7722b2b8446ab32284a08f44f4ea64da`
- **SHA256:** `f4e9733d93ce35ecd3c83f18addf77f8ff49444d09847eaeef9c8e87837d0165`
- **SHA256:** `17817d9e29920493bb20ed626c3026e3c29eb6f1d56ef9462c306066ce2ad171`
- **SHA256:** `f0d01b28ddfdbefe0697994a6b30f2b8a4e39ef1ad6c9427b921b2ccd945a8c5`

## MITRE ATT&CK Techniques

- **T1053.005** — Scheduled Task
- **T1543.003** — Windows Service
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1027** — Obfuscated Files or Information
- **T1660** — Phishing (Mobile)
- **T1404** — Exploitation for Privilege Escalation (Mobile)
- **T1407** — Download New Code at Runtime (Mobile)
- **T1626.001** — Abuse Elevation Control Mechanism: Device Administrator Permissions
- **T1517** — Access Notifications
- **T1437.001** — Application Layer Protocol: Web Protocols
- **T1398** — Boot or Logon Initialization Scripts
- **T1655.001** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] KidsProtect Android stalkerware APK by SHA-256 hash on endpoint filesystem

`UC_6_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file_name values(Filesystem.file_path) as file_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("9864db6b5800d9e03b747c46fdef988e035cadde83077a41c5610d5d89f753a0","1b1d9b260deec0c612ec67579fd36fec7722b2b8446ab32284a08f44f4ea64da","f4e9733d93ce35ecd3c83f18addf77f8ff49444d09847eaeef9c8e87837d0165","17817d9e29920493bb20ed626c3026e3c29eb6f1d56ef9462c306066ce2ad171","f0d01b28ddfdbefe0697994a6b30f2b8a4e39ef1ad6c9427b921b2ccd945a8c5")) OR (Filesystem.file_name="*.apk" AND match(Filesystem.file_name,"(?i)wifi[ ]?service|parentguard|kidsprotect")) by host Filesystem.dest Filesystem.file_hash Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let kidsprotect_hashes = dynamic(["9864db6b5800d9e03b747c46fdef988e035cadde83077a41c5610d5d89f753a0","1b1d9b260deec0c612ec67579fd36fec7722b2b8446ab32284a08f44f4ea64da","f4e9733d93ce35ecd3c83f18addf77f8ff49444d09847eaeef9c8e87837d0165","17817d9e29920493bb20ed626c3026e3c29eb6f1d56ef9462c306066ce2ad171","f0d01b28ddfdbefe0697994a6b30f2b8a4e39ef1ad6c9427b921b2ccd945a8c5"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in (kidsprotect_hashes)
   or (FileName endswith ".apk" and (FileName matches regex @"(?i)wifi[\s]?service|parentguard|kidsprotect"))
| project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, OSPlatform, OSVersion, DeviceType) by DeviceId) on DeviceId
```

### [LLM] KidsProtect package com.example.parentguard installed or active on managed Android device

`UC_6_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.os="Android" AND (Processes.process_name="com.example.parentguard" OR Processes.process_path="*com.example.parentguard*" OR Processes.process="*WiFiService Assistant*" OR Processes.process="*WiFiService Monitor*" OR Processes.process="*WiFiService Installer*" OR Processes.process="*MyDeviceAdminReceiver*") by host Processes.dest Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union isfuzzy=true
(
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath has "com.example.parentguard" or ProcessCommandLine has "com.example.parentguard" or InitiatingProcessFolderPath has "com.example.parentguard"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
),
(
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("AccessibilityServiceEnabled","DeviceAdminEnabled","PackageInstalled","AppInstalled")
| where AdditionalFields has_any ("com.example.parentguard","WiFiService Assistant","WiFiService Monitor","WiFiService Installer","MyDeviceAdminReceiver")
| project Timestamp, DeviceId, DeviceName, ActionType, AdditionalFields
)
| join kind=leftouter (DeviceInfo | where OSPlatform == "Android" | summarize arg_max(Timestamp, OSPlatform, OSVersion, DeviceType, LoggedOnUsers) by DeviceId) on DeviceId
| order by Timestamp desc
```

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### Service install for persistence — sc.exe / new service registry write

`UC_SERVICE_PERSIST` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="sc.exe" AND Processes.process="*create*"
      AND (Processes.process="*\Users\*" OR Processes.process="*\AppData\*"
        OR Processes.process="*\ProgramData\*" OR Processes.process="*\Temp\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Registry
        where Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Services\\*"
          AND Registry.registry_value_name="ImagePath"
          AND (Registry.registry_value_data="*\Users\*"
            OR Registry.registry_value_data="*\AppData\*"
            OR Registry.registry_value_data="*\Temp\*")
        by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.user
     | `drop_dm_object_name(Registry)`]
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "sc.exe" and ProcessCommandLine has "create"
| where ProcessCommandLine matches regex @"(?i)(\Users\|\AppData\|\ProgramData\|\Temp\)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 1m)
| where files > 200
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
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9864db6b5800d9e03b747c46fdef988e035cadde83077a41c5610d5d89f753a0`, `1b1d9b260deec0c612ec67579fd36fec7722b2b8446ab32284a08f44f4ea64da`, `f4e9733d93ce35ecd3c83f18addf77f8ff49444d09847eaeef9c8e87837d0165`, `17817d9e29920493bb20ed626c3026e3c29eb6f1d56ef9462c306066ce2ad171`, `f0d01b28ddfdbefe0697994a6b30f2b8a4e39ef1ad6c9427b921b2ccd945a8c5`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
