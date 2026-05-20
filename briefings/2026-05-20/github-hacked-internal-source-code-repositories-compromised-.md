# [HIGH] GitHub Hacked – Internal Source Code Repositories Compromised via Employee Device

**Source:** Cyber Security News
**Published:** 2026-05-20
**Article:** https://cybersecuritynews.com/github-data-breach/

## Threat Profile

Home Cyber Attack News 
GitHub Hacked – Internal Source Code Repositories Compromised via Employee Device 
By Guru Baran 
May 20, 2026 
GitHub has confirmed unauthorized access to its internal repositories after detecting a compromised employee device infected through a malicious Visual Studio Code extension, the company disclosed in a series of official statements on May 20, 2026.
The Microsoft-owned code hosting platform said it identified and contained the breach after a poisoned VS Code exte…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `check.git-service.com`
- **Domain (defanged):** `t.m-kosche.com`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1083** — File and Directory Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] TeamPCP GitHub-breach C2 domain callbacks (check.git-service.com / t.m-kosche.com)

`UC_4_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.src) as src values(All_Traffic.user) as user values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest in ("check.git-service.com","t.m-kosche.com") OR All_Traffic.dest_host in ("check.git-service.com","t.m-kosche.com") by All_Traffic.src All_Traffic.dest All_Traffic.user | `drop_dm_object_name(All_Traffic)` | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where DNS.query in ("check.git-service.com","t.m-kosche.com","*.git-service.com","*.m-kosche.com") by DNS.src DNS.query | `drop_dm_object_name(DNS)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let IOCDomains = dynamic(["check.git-service.com","t.m-kosche.com"]);
let IOCSuffix  = dynamic([".git-service.com",".m-kosche.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl has_any (IOCDomains)) or (RemoteUrl endswith ".git-service.com") or (RemoteUrl endswith ".m-kosche.com")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort, ActionType, ReportId
| order by Timestamp desc
```

### [LLM] VS Code (Code.exe / node.exe extension host) egress to TeamPCP C2 domains

`UC_4_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app IN ("Code.exe","code.exe","node.exe") OR All_Traffic.process_name IN ("Code.exe","code.exe","node.exe")) AND (All_Traffic.dest IN ("check.git-service.com","t.m-kosche.com") OR like(All_Traffic.dest,"%.git-service.com") OR like(All_Traffic.dest,"%.m-kosche.com")) by host All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.process_name All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let IOCDomains = dynamic(["check.git-service.com","t.m-kosche.com"]);
let VSCodeImages = dynamic(["code.exe","node.exe","electron.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (VSCodeImages)
      or InitiatingProcessParentFileName in~ (VSCodeImages)
      or InitiatingProcessFolderPath has @"\Microsoft VS Code\"
      or InitiatingProcessFolderPath has @"\.vscode\extensions\"
| where RemoteUrl has_any (IOCDomains) or RemoteUrl endswith ".git-service.com" or RemoteUrl endswith ".m-kosche.com"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort, ActionType, ReportId
| order by Timestamp desc
```

### [LLM] VS Code extension-host child process accessing developer-secret stores

`UC_4_9` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name values(Filesystem.user) as user values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path from datamodel=Endpoint.Filesystem where Filesystem.action IN ("read","opened","accessed","modified") AND (Filesystem.parent_process_name IN ("Code.exe","code.exe") OR Filesystem.process_path="*\\.vscode\\extensions\\*" OR Filesystem.parent_process_path="*\\Microsoft VS Code\\*") AND (Filesystem.file_path="*\\.git-credentials" OR Filesystem.file_path="*\\.npmrc" OR Filesystem.file_path="*\\.aws\\credentials" OR Filesystem.file_path="*\\.aws\\config" OR Filesystem.file_path="*\\.ssh\\id_*" OR Filesystem.file_path="*\\.config\\gh\\hosts.yml" OR Filesystem.file_path="*\\.docker\\config.json" OR Filesystem.file_path="*\\.kube\\config" OR Filesystem.file_path="*\\AppData\\Roaming\\gh\\hosts.yml") by host Filesystem.user Filesystem.process_name Filesystem.parent_process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let SecretPathPatterns = dynamic([
  @"\.git-credentials",
  @"\.npmrc",
  @"\.aws\credentials",
  @"\.aws\config",
  @"\.config\gh\hosts.yml",
  @"\AppData\Roaming\GitHub CLI\hosts.yml",
  @"\.docker\config.json",
  @"\.kube\config",
  @"\.ssh\id_rsa",
  @"\.ssh\id_ed25519",
  @"\.ssh\id_ecdsa",
  @"\AppData\Roaming\Code\User\settings.json"
]);
let VSCodeImages = dynamic(["code.exe","node.exe","electron.exe"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed","FileCopied")
      or ActionType has "Open" or ActionType has "Read"
| where FolderPath has_any (SecretPathPatterns) or strcat(FolderPath, FileName) has_any (SecretPathPatterns)
| where InitiatingProcessFileName in~ (VSCodeImages)
      or InitiatingProcessParentFileName in~ (VSCodeImages)
      or InitiatingProcessFolderPath has @"\Microsoft VS Code\"
      or InitiatingProcessFolderPath has @"\.vscode\extensions\"
      or InitiatingProcessCommandLine has @"\.vscode\extensions\"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, FolderPath, FileName, ActionType, ReportId
| order by Timestamp desc
```

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `check.git-service.com`, `t.m-kosche.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
