# [HIGH] AI Attacks Move in Minutes. Join This Webinar on Building a Defense That Keeps Up

**Source:** The Hacker News
**Published:** 2026-07-09
**Article:** https://thehackernews.com/2026/07/ai-attacks-move-in-minutes-join-this.html

## Threat Profile

AI Attacks Move in Minutes. Join This Webinar on Building a Defense That Keeps Up 
 The Hacker News  Jul 09, 2026 AI Security / Zero Trust 
AI has changed how fast attacks move. Work that once took an attacker days now takes minutes. Using models like Mythos, attackers write tailored bait, pick targets, test what lands, and jump to the next host before your team clears the first alert.
That is the gap, and it is not your fault. The tools and runbooks most teams run on were built for attackers …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1068** — Exploitation for Privilege Escalation
- **T1211** — Exploitation for Defense Evasion
- **T1105** — Ingress Tool Transfer
- **T1588.002** — Obtain Capabilities: Tool

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Microsoft Defender engine (MsMpEng.exe) spawns shell/LOLBin — RoguePlanet CVE-2026-50656 exploitation

`UC_108_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="MsMpEng.exe" AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","net.exe","whoami.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_integrity_level | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "MsMpEng.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","net.exe","whoami.exe")
| project Timestamp, DeviceName, AccountName, ProcessIntegrityLevel, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Hosts running vulnerable Microsoft Malware Protection Engine below 1.1.26060.3008 (RoguePlanet exposure)

`UC_108_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2026-50656" by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.cve | `drop_dm_object_name(Vulnerabilities)` | sort - count
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2026-50656"
| project DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
```

### RoguePlanet PoC (github.com/MSNightmare/RoguePlanet) download or execution

`UC_108_8` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*MSNightmare/RoguePlanet*" OR Processes.process="*RoguePlanet.exe*" OR Processes.process="*RoguePlanet-main*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("MSNightmare/RoguePlanet","RoguePlanet.exe","RoguePlanet-main","RoguePlanet.sln")
    or InitiatingProcessCommandLine has_any ("MSNightmare/RoguePlanet","RoguePlanet.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
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


## Why this matters

Severity classified as **HIGH** based on: 9 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
