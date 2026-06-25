# [CRIT] The Gentlemen RaaS Uses GentleKiller EDR Framework Targeting 400 Security Processes

**Source:** The Hacker News
**Published:** 2026-06-19
**Article:** https://thehackernews.com/2026/06/the-gentlemen-raas-uses-gentlekiller.html

## Threat Profile

The Gentlemen RaaS Uses GentleKiller EDR Framework Targeting 400 Security Processes 
 Ravie Lakshmanan  Jun 19, 2026 Ransomware / Endpoint Security 
The Gentlemen ransomware-as-a-service (RaaS) operation is actively developing and maintaining a suite of endpoint detection and response (EDR) killers that it hands out to affiliates for impairing system defenses before deploying the encryptor.
This mature portfolio of EDR-terminating tools is centered around a framework that's known as GentleKill…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-26125`
- **SHA1:** `8ae6bd18b129061f63642531f1b684cf0383c75d`
- **SHA1:** `ba914fe77b177b45799403b16dd14765c510a074`
- **SHA1:** `d605994fc72a2bb59b5cfb1624a1b9170eca73a2`
- **SHA1:** `b0b912a3fd1c05d72080848ec4c92880004021a1`
- **SHA1:** `5aa3124e5c4921e5edfc60133b5d71da21b07da3`
- **SHA1:** `7556ae58c215b8245a43f764f0676c7a8f0fdd1a`
- **SHA1:** `331879f5eec8892bbd896f90bdbb1bad0bf63bd6`
- **SHA1:** `f11aebccb9a86a7e2e653f90baec697f233c255f`
- **SHA1:** `ef9cd06683159397f099caa244e94e6eaad96eba`
- **SHA1:** `711ef221526997039e804a18db9647c91680bbe2`
- **SHA1:** `68fec379f2ae76c3d2ce913f7be650cea1d06990`
- **SHA1:** `a11ee9cdc59e5caa59aefd27b30d104f3ad68e62`
- **SHA1:** `96f0dbf52aed0afd43e44500116b04b674f7358e`
- **SHA1:** `2f86898528c6cab3540c486a9bfaa0c029b73950`
- **SHA1:** `9ad51ad97c01e97ab59214116740785e0f6320a8`
- **SHA1:** `a19117175dbc9ba4d23b5dce8415e299a2e32192`
- **SHA1:** `12500f6c87ce62712a0ed6652c57468d15c14223`
- **SHA1:** `d29670e684e40ddc89b47010c37cbc96737035b6`
- **SHA1:** `56bee9df5833a637f5c54d5911df98b0812fe643`
- **SHA1:** `cf4d74df17a91b4a36a2911b22afec5d8fa93a01`
- **SHA1:** `ec296f9501ad71e430810cb5cdc38d954d4ba536`
- **SHA1:** `7131b377e96016dc1911020c9f95b1b4d042d7b4`
- **SHA1:** `82ed942a52cdcf120a8919730e00ba37619661a3`
- **SHA1:** `f0537cbb773ae12100b36731e7c39f5a9d852b14`
- **SHA1:** `1fa071303fb846308571e64727501fb98b1c2be6`
- **SHA1:** `a5cf917ec4a7dfbdfa43621398604805d860c718`
- **SHA1:** `d4b19141102015d436321e6f26976e98183cfd27`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

### Article-specific behavioural hunt — The Gentlemen RaaS Uses GentleKiller EDR Framework Targeting 400 Security Proces

`UC_64_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — The Gentlemen RaaS Uses GentleKiller EDR Framework Targeting 400 Security Proces ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("eb.sys","nseckrnl.sys","gamedriverx64.sys","stpm_old.sys","stpm_new.sys","dmx.sys","360netmon_wfp.sys","imfforcedelete.sys","poisonx.sys","hrwfpdrv.sys","googleapiutil64.sys","throttleblood.sys","havoc.sys"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("eb.sys","nseckrnl.sys","gamedriverx64.sys","stpm_old.sys","stpm_new.sys","dmx.sys","360netmon_wfp.sys","imfforcedelete.sys","poisonx.sys","hrwfpdrv.sys","googleapiutil64.sys","throttleblood.sys","havoc.sys"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — The Gentlemen RaaS Uses GentleKiller EDR Framework Targeting 400 Security Proces
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("eb.sys", "nseckrnl.sys", "gamedriverx64.sys", "stpm_old.sys", "stpm_new.sys", "dmx.sys", "360netmon_wfp.sys", "imfforcedelete.sys", "poisonx.sys", "hrwfpdrv.sys", "googleapiutil64.sys", "throttleblood.sys", "havoc.sys"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("eb.sys", "nseckrnl.sys", "gamedriverx64.sys", "stpm_old.sys", "stpm_new.sys", "dmx.sys", "360netmon_wfp.sys", "imfforcedelete.sys", "poisonx.sys", "hrwfpdrv.sys", "googleapiutil64.sys", "throttleblood.sys", "havoc.sys"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-26125`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `8ae6bd18b129061f63642531f1b684cf0383c75d`, `ba914fe77b177b45799403b16dd14765c510a074`, `d605994fc72a2bb59b5cfb1624a1b9170eca73a2`, `b0b912a3fd1c05d72080848ec4c92880004021a1`, `5aa3124e5c4921e5edfc60133b5d71da21b07da3`, `7556ae58c215b8245a43f764f0676c7a8f0fdd1a`, `331879f5eec8892bbd896f90bdbb1bad0bf63bd6`, `f11aebccb9a86a7e2e653f90baec697f233c255f` _(+19 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
