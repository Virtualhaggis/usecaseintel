# [CRIT] Cybercrime service disrupted for abusing Microsoft platform to sign malware

**Source:** BleepingComputer
**Published:** 2026-05-19
**Article:** https://www.bleepingcomputer.com/news/security/cybercrime-service-disrupted-for-abusing-microsoft-platform-to-sign-malware/

## Threat Profile

Cybercrime service disrupted for abusing Microsoft platform to sign malware 
By Lawrence Abrams 
May 19, 2026
05:47 PM
0 
Microsoft says it has disrupted a malware-signing-as-a-service (MSaaS) operation that abused the company's Artifact Signing service to generate fraudulent code-signing certificates used by ransomware gangs and other cybercriminals.
According to a report published today by Microsoft Threat Intelligence, the threat actor tracked as Fox Tempest used the Microsoft Artifact Signin…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `signspace.cloud`
- **SHA256:** `f0668ce925f36ff7f3359b0ea47e3fa243af13cd6ad9661dfccc9ff79fb4f1cc`
- **SHA256:** `11af4566539ad3224e968194c7a9ad7b596460d8f6e423fc62d1ea5fc0724326`
- **SHA256:** `f0a6b89ec7eee83274cd484cea526b970a3ef28038799b0a5774bb33c5793b55`
- **SHA1:** `dc0acb01e3086ea8a9cb144a5f97810d291020ce`
- **SHA1:** `7e6d9dac619c04ae1b3c8c0906123e752ed66d63`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1553.002** — Subvert Trust Controls: Code Signing
- **T1036.001** — Masquerading: Invalid Code Signature
- **T1204.002** — User Execution: Malicious File
- **T1036.005** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Network contact with seized Fox Tempest MSaaS infrastructure (signspace.cloud)

`UC_41_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ips values(All_Traffic.src) as src_hosts values(All_Traffic.user) as users from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="signspace.cloud" OR All_Traffic.dest="*.signspace.cloud" by All_Traffic.src All_Traffic.dest All_Traffic.app | `drop_dm_object_name("All_Traffic")` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Hunt for Defender endpoints contacting the seized Fox Tempest MSaaS domain signspace.cloud
let KnownBad = dynamic(["signspace.cloud", ".signspace.cloud"]);
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteUrl has_any (KnownBad) or RemoteUrl endswith ".signspace.cloud" or RemoteUrl =~ "signspace.cloud"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFolderPath, ReportId
| order by Timestamp desc
```

### [LLM] Execution or write of known Fox Tempest-signed malware samples by SHA256/SHA1

`UC_41_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_hash IN ("f0668ce925f36ff7f3359b0ea47e3fa243af13cd6ad9661dfccc9ff79fb4f1cc","11af4566539ad3224e968194c7a9ad7b596460d8f6e423fc62d1ea5fc0724326","f0a6b89ec7eee83274cd484cea526b970a3ef28038799b0a5774bb33c5793b55","dc0acb01e3086ea8a9cb144a5f97810d291020ce","7e6d9dac619c04ae1b3c8c0906123e752ed66d63")) by Processes.dest Processes.process_name Processes.process_hash | `drop_dm_object_name("Processes")` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Detect execution / filesystem landing of Fox Tempest-signed Oyster malware samples named in Microsoft DCU complaint
let KnownSHA256 = dynamic(["f0668ce925f36ff7f3359b0ea47e3fa243af13cd6ad9661dfccc9ff79fb4f1cc","11af4566539ad3224e968194c7a9ad7b596460d8f6e423fc62d1ea5fc0724326","f0a6b89ec7eee83274cd484cea526b970a3ef28038799b0a5774bb33c5793b55"]);
let KnownSHA1 = dynamic(["dc0acb01e3086ea8a9cb144a5f97810d291020ce","7e6d9dac619c04ae1b3c8c0906123e752ed66d63"]);
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(90d)
    | where SHA256 in (KnownSHA256) or SHA1 in (KnownSHA1)
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, SHA1, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Source="Process"
),
(
    DeviceFileEvents
    | where Timestamp > ago(90d)
    | where SHA256 in (KnownSHA256) or SHA1 in (KnownSHA1)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, SHA1, ProcessCommandLine="", InitiatingProcessFileName, InitiatingProcessCommandLine, Source="FileWrite"
)
| order by Timestamp desc
```

### [LLM] Fake Teams/AnyDesk/PuTTY/Webex installer running from user-writable path

`UC_41_10` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.process_hash) as hashes from datamodel=Endpoint.Processes where (Processes.process_name IN ("Teams_windows_x64.exe","MSTeams.exe","Teams.exe","AnyDesk.exe","AnyDeskSetup.exe","putty.exe","puttygen.exe","webexapp.exe","webex.exe","webexsetup.exe","webex_installer.exe")) AND (Processes.process_path IN ("*\\Users\\*\\Downloads\\*","*\\Users\\*\\AppData\\Local\\Temp\\*","*\\Users\\*\\AppData\\Roaming\\*","*\\ProgramData\\*","*\\PerfLogs\\*")) by Processes.dest Processes.user Processes.process_name Processes.process_path | `drop_dm_object_name("Processes")` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Detect Fox Tempest-style impersonation: Teams/AnyDesk/PuTTY/Webex named installer running from a user-writable path
let ImpersonatedNames = dynamic(["teams_windows_x64.exe","msteams.exe","teams.exe","teamssetup.exe","anydesk.exe","anydesksetup.exe","putty.exe","puttygen.exe","webexapp.exe","webex.exe","webexsetup.exe","webex_installer.exe","webexteams.exe"]);
let SuspiciousPaths = dynamic([@"\users\", @"\appdata\local\temp\", @"\appdata\roaming\", @"\programdata\", @"\perflogs\", @"\downloads\", @"\public\"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$" and AccountName !in~ ("system","local service","network service")
| extend FileNameLower = tolower(FileName), FolderLower = tolower(FolderPath)
| where FileNameLower in (ImpersonatedNames)
| where FolderLower has_any (SuspiciousPaths)
// exclude legit installer staging by Microsoft / Cisco / AnyDesk vendor strings
| where ProcessVersionInfoCompanyName !in~ ("Microsoft Corporation","Cisco Systems, Inc.","Cisco WebEx LLC","AnyDesk Software GmbH","Simon Tatham")
   or isempty(ProcessVersionInfoCompanyName)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileOriginUrl=tostring(parse_json(AdditionalFields).FileOriginUrl)
| order by Timestamp desc
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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
  - IP / domain IOC(s): `signspace.cloud`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `f0668ce925f36ff7f3359b0ea47e3fa243af13cd6ad9661dfccc9ff79fb4f1cc`, `11af4566539ad3224e968194c7a9ad7b596460d8f6e423fc62d1ea5fc0724326`, `f0a6b89ec7eee83274cd484cea526b970a3ef28038799b0a5774bb33c5793b55`, `dc0acb01e3086ea8a9cb144a5f97810d291020ce`, `7e6d9dac619c04ae1b3c8c0906123e752ed66d63`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
