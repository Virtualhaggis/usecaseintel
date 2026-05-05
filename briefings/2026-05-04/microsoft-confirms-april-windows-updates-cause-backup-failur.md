# [HIGH] Microsoft confirms April Windows updates cause backup failures

**Source:** BleepingComputer
**Published:** 2026-05-04
**Article:** https://www.bleepingcomputer.com/news/microsoft/microsoft-confirms-backup-failures-caused-by-vulnerable-driver-block/

## Threat Profile

Microsoft confirms April Windows updates cause backup failures 
By Sergiu Gatlan 
May 4, 2026
06:40 AM
0 
Microsoft has confirmed that the April 2026 security updates are causing failures in third-party backup applications using the psmounterex.sys driver.
As BleepinComputer reported last week , this issue affects software using VSS (Volume Shadow Copy Service) snapshots and causes failures due to a VSS service timeout.
Software impacted by this includes, but is not limited to, products from Mac…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-43896`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1219** — Remote Access Software
- **T1204.002** — User Execution: Malicious File
- **T1068** — Exploitation for Privilege Escalation
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1588.001** — Obtain Capabilities: Malware
- **T1014** — Rootkit

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Microsoft Vulnerable Driver Blocklist hit on psmounterex.sys (CI Event 3077)

`UC_37_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
index=* source="WinEventLog:Microsoft-Windows-CodeIntegrity/Operational" EventCode=3077
| where like(lower(_raw), "%psmounterex.sys%") OR like(lower(FileName), "%psmounterex.sys%")
| rex field=_raw "PolicyGUID=(?<policy_guid>\{[A-F0-9\-]+\})"
| where policy_guid="{D2BDA982-CCF6-4344-AC5B-0B44427B6816}" OR isnull(policy_guid)
| stats count min(_time) as firstTime max(_time) as lastTime values(FileName) as file_name values(SHA256) as sha256 values(User) as user by host
| convert ctime(firstTime) ctime(lastTime)
| rename host as dest
| `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
// Defender surfaces CI vulnerable-driver blocks via DeviceEvents.
// Look for any DeviceEvent referencing psmounterex.sys around the
// April-2026 VDB rollout. Pair with DeviceImageLoadEvents for context.
DeviceEvents
| where Timestamp > ago(30d)
| where FileName =~ "psmounterex.sys"
   or InitiatingProcessFileName =~ "psmounterex.sys"
   or ProcessCommandLine has "psmounterex.sys"
   or AdditionalFields has "psmounterex"
| where ActionType has_any ("Driver","CodeIntegrity","VulnerableDriver","Block")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          AdditionalFields
| order by Timestamp desc
```

### [LLM] BYOVD drop: psmounterex.sys written outside Macrium/Acronis/NinjaOne/UrBackup install paths

`UC_37_4` · phase: **weapon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem WHERE Filesystem.file_name="psmounterex.sys" (Filesystem.action="created" OR Filesystem.action="modified" OR Filesystem.action="write") BY Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| eval lc_path=lower(file_path)
| where NOT match(lc_path, "\\\\program files( \\(x86\\))?\\\\(macrium|acronis|ninjarmm|ninjarmmagent|ninjaone|urbackup)\\\\")
   AND NOT match(lc_path, "\\\\windows\\\\system32\\\\drivers\\\\")
   AND NOT match(lc_path, "\\\\windowsapps\\\\")
| convert ctime(firstTime) ctime(lastTime)
| `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
// BYOVD drop site detection — psmounterex.sys (CVE-2023-43896)
let vendor_paths = dynamic([
    @"\program files\macrium\",
    @"\program files (x86)\macrium\",
    @"\program files\acronis\",
    @"\program files (x86)\acronis\",
    @"\program files\ninjarmmagent\",
    @"\program files\ninjaone\",
    @"\program files (x86)\ninjaone\",
    @"\program files\urbackup\",
    @"\program files (x86)\urbackup\",
    @"\windows\system32\drivers\"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "psmounterex.sys"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| extend lc_path = tolower(FolderPath)
| where not(lc_path has_any (vendor_paths))
| where InitiatingProcessFileName !in~ ("msiexec.exe","trustedinstaller.exe","reflect.exe","reflectmonitor.exe","acronis_agent.exe","ninjarmmagent.exe","urbackupclientbackend.exe")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, FileSize,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] Vulnerable psmounterex.sys image load by non-backup-vendor process (pre-VDB-patch BYOVD)

`UC_37_5` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`sysmon` EventCode=7 ImageLoaded="*\\psmounterex.sys"
| eval lc_image=lower(Image), lc_loaded=lower(ImageLoaded)
| where NOT match(lc_image, "\\\\program files( \\(x86\\))?\\\\(macrium|acronis|ninjarmm|ninjarmmagent|ninjaone|urbackup)\\\\")
   AND NOT match(lc_image, "\\\\windows\\\\system32\\\\(services\\.exe|svchost\\.exe)$")
| stats count min(_time) as firstTime max(_time) as lastTime values(User) as user values(Hashes) as loaded_hashes by Computer Image ImageLoaded
| rename Computer as dest
| convert ctime(firstTime) ctime(lastTime)
| `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
// psmounterex.sys driver load by an unexpected initiator (BYOVD)
let vendor_proc_paths = dynamic([
    @"\program files\macrium\",
    @"\program files (x86)\macrium\",
    @"\program files\acronis\",
    @"\program files (x86)\acronis\",
    @"\program files\ninjarmmagent\",
    @"\program files\ninjaone\",
    @"\program files (x86)\ninjaone\",
    @"\program files\urbackup\",
    @"\program files (x86)\urbackup\"
]);
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName =~ "psmounterex.sys"
| extend lc_init = tolower(InitiatingProcessFolderPath)
| where not(lc_init has_any (vendor_proc_paths))
| where InitiatingProcessFileName !in~ ("services.exe","system")
| project Timestamp, DeviceName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessSHA256,
          InitiatingProcessAccountName
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

### Article-specific behavioural hunt — Microsoft confirms April Windows updates cause backup failures

`UC_37_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft confirms April Windows updates cause backup failures ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("psmounterex.sys"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("psmounterex.sys"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Microsoft confirms April Windows updates cause backup failures
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("psmounterex.sys"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("psmounterex.sys"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-43896`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 6 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
