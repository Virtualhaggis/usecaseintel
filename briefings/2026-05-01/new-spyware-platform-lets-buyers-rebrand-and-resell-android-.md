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
- **T1626.001** — Abuse Elevation Control Mechanism: Device Administrator Permissions (Mobile)
- **T1417.001** — Input Capture: Keylogging (Mobile)
- **T1429** — Audio Capture (Mobile)
- **T1430** — Location Tracking (Mobile)
- **T1624.001** — Event Triggered Execution: Broadcast Receivers (Mobile)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] KidsProtect Android stalkerware APK SHA256 match (Certo / com.example.parentguard)

`UC_20_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("9864db6b5800d9e03b747c46fdef988e035cadde83077a41c5610d5d89f753a0","1b1d9b260deec0c612ec67579fd36fec7722b2b8446ab32284a08f44f4ea64da","f4e9733d93ce35ecd3c83f18addf77f8ff49444d09847eaeef9c8e87837d0165","17817d9e29920493bb20ed626c3026e3c29eb6f1d56ef9462c306066ce2ad171","f0d01b28ddfdbefe0697994a6b30f2b8a4e39ef1ad6c9427b921b2ccd945a8c5") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | eval source_view="endpoint_file_write" | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Email where Email.file_hash IN ("9864db6b5800d9e03b747c46fdef988e035cadde83077a41c5610d5d89f753a0","1b1d9b260deec0c612ec67579fd36fec7722b2b8446ab32284a08f44f4ea64da","f4e9733d93ce35ecd3c83f18addf77f8ff49444d09847eaeef9c8e87837d0165","17817d9e29920493bb20ed626c3026e3c29eb6f1d56ef9462c306066ce2ad171","f0d01b28ddfdbefe0697994a6b30f2b8a4e39ef1ad6c9427b921b2ccd945a8c5") by Email.src_user Email.recipient Email.file_name Email.file_hash Email.subject | `drop_dm_object_name(Email)` | eval source_view="email_attachment"] | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_content_type="application/vnd.android.package-archive" OR Web.url="*.apk*" by Web.src Web.dest Web.url Web.user Web.http_user_agent | `drop_dm_object_name(Web)` | eval source_view="proxy_apk_download" ] | convert ctime(firstTime) ctime(lastTime) | table source_view firstTime lastTime dest user src recipient file_name file_path file_hash url subject http_user_agent count
```

**Defender KQL:**
```kql
// KidsProtect Android stalkerware APK — SHA256 hits across file events + email attachments
let kidsprotect_sha256 = dynamic([
  "9864db6b5800d9e03b747c46fdef988e035cadde83077a41c5610d5d89f753a0",
  "1b1d9b260deec0c612ec67579fd36fec7722b2b8446ab32284a08f44f4ea64da",
  "f4e9733d93ce35ecd3c83f18addf77f8ff49444d09847eaeef9c8e87837d0165",
  "17817d9e29920493bb20ed626c3026e3c29eb6f1d56ef9462c306066ce2ad171",
  "f0d01b28ddfdbefe0697994a6b30f2b8a4e39ef1ad6c9427b921b2ccd945a8c5"
]);
union isfuzzy=true
  ( DeviceFileEvents
      | where Timestamp > ago(30d)
      | where SHA256 in (kidsprotect_sha256)
      | project Timestamp,
                Source         = "DeviceFileEvents",
                DeviceName,
                FileName,
                FolderPath,
                SHA256,
                FileOriginUrl,
                Initiator      = InitiatingProcessFileName,
                InitiatorCmd   = InitiatingProcessCommandLine,
                InitiatorUser  = InitiatingProcessAccountName,
                Recipient      = "",
                Sender         = "" ),
  ( EmailAttachmentInfo
      | where Timestamp > ago(30d)
      | where SHA256 in (kidsprotect_sha256)
      | project Timestamp,
                Source         = "EmailAttachmentInfo",
                DeviceName     = "",
                FileName,
                FolderPath     = "",
                SHA256,
                FileOriginUrl  = "",
                Initiator      = "",
                InitiatorCmd   = "",
                InitiatorUser  = "",
                Recipient      = RecipientEmailAddress,
                Sender         = SenderFromAddress )
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
| where AccountName !endswith "$"
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
| where AccountName !endswith "$"
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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9864db6b5800d9e03b747c46fdef988e035cadde83077a41c5610d5d89f753a0`, `1b1d9b260deec0c612ec67579fd36fec7722b2b8446ab32284a08f44f4ea64da`, `f4e9733d93ce35ecd3c83f18addf77f8ff49444d09847eaeef9c8e87837d0165`, `17817d9e29920493bb20ed626c3026e3c29eb6f1d56ef9462c306066ce2ad171`, `f0d01b28ddfdbefe0697994a6b30f2b8a4e39ef1ad6c9427b921b2ccd945a8c5`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
