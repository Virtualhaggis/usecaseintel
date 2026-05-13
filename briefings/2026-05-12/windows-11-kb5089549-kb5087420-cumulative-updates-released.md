# [HIGH] Windows 11 KB5089549 & KB5087420 cumulative updates released

**Source:** BleepingComputer
**Published:** 2026-05-12
**Article:** https://www.bleepingcomputer.com/news/microsoft/windows-11-kb5089549-and-kb5087420-cumulative-updates-released/

## Threat Profile

Windows 11 KB5089549 & KB5087420 cumulative updates released 
By Mayank Parmar 
May 12, 2026
02:09 PM
0 
Microsoft has released Windows 11 KB5089549 and KB5087420 cumulative updates for versions 25H2/24H2 and 23H2 to fix security vulnerabilities, bugs, and add new features.
Today's updates are mandatory as they contain the  May 2026 Patch Tuesday security patches for 120 vulnerabilities discovered in previous months.
You can install today's update by going to  Start  >  Settings  >  Windows Upda…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1203** — Exploitation for Client Execution
- **T1112** — Modify Registry
- **T1562.001** — Impair Defenses: Disable or Modify Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Windows 11 KB5089549 / KB5087420 May 2026 Patch Tuesday deployment gap

`UC_13_1` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, latest(_time) as last_install_time from datamodel=Updates.Updates where (Updates.signature_id="KB5089549" OR Updates.signature_id="KB5087420" OR Updates.signature_id="5089549" OR Updates.signature_id="5087420") Updates.status="Installed" by Updates.dest, Updates.signature_id
| `drop_dm_object_name(Updates)`
| stats values(signature_id) as may_pt_kbs_installed, max(last_install_time) as last_install_time by dest
| appendpipe [ | tstats `summariesonly` count from datamodel=Updates.Updates where Updates.vendor_product="*Windows 11*" by Updates.dest | `drop_dm_object_name(Updates)` | fields dest ]
| stats values(may_pt_kbs_installed) as may_pt_kbs_installed, max(last_install_time) as last_install_time by dest
| eval has_kb5089549 = if(match(mvjoin(may_pt_kbs_installed, ","), "5089549"), "Patched", "Missing")
| eval has_kb5087420 = if(match(mvjoin(may_pt_kbs_installed, ","), "5087420"), "Patched", "Missing")
| where has_kb5089549="Missing" AND has_kb5087420="Missing"
| table dest has_kb5089549 has_kb5087420 last_install_time
| sort 0 - last_install_time
```

**Defender KQL:**
```kql
// Devices still exposed to May 2026 Patch Tuesday CVEs because they haven't installed KB5089549 (24H2/25H2) or KB5087420 (23H2)
let MayPTKbIds = dynamic(["5089549","5087420","KB5089549","KB5087420"]);
let RecentInfo =
    DeviceInfo
    | where Timestamp > ago(2d)
    | where OSPlatform == "Windows11"
    | summarize arg_max(Timestamp, OSVersion, OSBuild, IsInternetFacing, PublicIP) by DeviceId, DeviceName;
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(2d)
| where OSPlatform == "Windows11"
| where RecommendedSecurityUpdateId has_any (MayPTKbIds)
   or RecommendedSecurityUpdate has_any (MayPTKbIds)
| summarize CveCount = dcount(CveId),
            CriticalCves = countif(VulnerabilitySeverityLevel =~ "Critical"),
            HighCves = countif(VulnerabilitySeverityLevel =~ "High"),
            CveSample = make_set(CveId, 20),
            KbsRecommended = make_set(RecommendedSecurityUpdateId, 5)
            by DeviceId, DeviceName, OSVersion
| join kind=leftouter RecentInfo on DeviceId
| project DeviceName, OSVersion, OSBuild, IsInternetFacing, PublicIP,
          CveCount, CriticalCves, HighCves, KbsRecommended, CveSample
| order by IsInternetFacing desc, CriticalCves desc, CveCount desc
```

### [LLM] Tampering with new LockBatchFilesWhenInUse Command Processor hardening registry value

`UC_13_2` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Registry.registry_value_data) as new_value, values(Registry.process_path) as process_path, values(Registry.user) as user, min(_time) as first_seen, max(_time) as last_seen from datamodel=Endpoint.Registry where (Registry.registry_path="*\\Software\\Microsoft\\Command Processor\\LockBatchFilesWhenInUse" OR Registry.registry_value_name="LockBatchFilesWhenInUse") by Registry.dest, Registry.action, Registry.registry_value_name
| `drop_dm_object_name(Registry)`
| eval suspicious = case(action=="deleted", "tamper-delete", new_value=="0" OR new_value=="0x0", "tamper-disable", true(), "change")
| where suspicious!="change" OR NOT match(process_path, "(?i)\\\\(MsiExec|TrustedInstaller|svchost|GPSvc|mmc|services|wuauclt)\\.exe")
| table first_seen last_seen dest action registry_value_name new_value process_path user suspicious
| sort 0 - last_seen
```

**Defender KQL:**
```kql
// Tamper detection on the new LockBatchFilesWhenInUse Command Processor hardening control introduced in KB5089549 / KB5087420
let _known_admin_processes = dynamic(["gpupdate.exe","trustedinstaller.exe","svchost.exe","msiexec.exe","mmc.exe","reg.exe","regedit.exe","intunemanagementextension.exe"]);
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet","RegistryValueDeleted","RegistryKeyDeleted","RegistryKeyCreated")
| where RegistryKey has @"\Software\Microsoft\Command Processor"
   and (RegistryValueName =~ "LockBatchFilesWhenInUse" or PreviousRegistryValueName =~ "LockBatchFilesWhenInUse")
| extend TamperSignal = case(
    ActionType == "RegistryValueDeleted", "value-deleted",
    ActionType == "RegistryKeyDeleted", "key-deleted",
    ActionType == "RegistryValueSet" and tostring(RegistryValueData) in ("0","0x0","00000000"), "control-disabled",
    ActionType == "RegistryValueSet" and tostring(RegistryValueData) in ("1","0x1","00000001"), "control-enabled",
    "other")
| where TamperSignal != "control-enabled"  // exclude initial roll-out / admin enabling
   or InitiatingProcessFileName !in~ (_known_admin_processes)
| project Timestamp, DeviceName,
          ActorUser = strcat(InitiatingProcessAccountDomain, "\\", InitiatingProcessAccountName),
          ActionType, TamperSignal,
          RegistryKey, RegistryValueName, RegistryValueData,
          PreviousValue = PreviousRegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath,
          ParentProcess = InitiatingProcessParentFileName,
          IntegrityLevel = InitiatingProcessIntegrityLevel
| order by Timestamp desc
```

### Article-specific behavioural hunt — Windows 11 KB5089549 & KB5087420 cumulative updates released

`UC_13_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Windows 11 KB5089549 & KB5087420 cumulative updates released ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("midisrv.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("midisrv.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Windows 11 KB5089549 & KB5087420 cumulative updates released
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("midisrv.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("midisrv.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
