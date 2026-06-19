# [HIGH] Killing me gently: Inside Gentlemen’s EDR killer framework

**Source:** ESET WeLiveSecurity
**Published:** 2026-06-18
**Article:** https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/

## Threat Profile

ESET researchers analyzed the robust EDR-killing toolset of the ransomware-as-a-service gang Gentlemen. Since the beginning of 2026, Gentlemen has emerged as one of the most active gangs in the ransomware ecosystem. The group distinguishes itself through a mature, operator-maintained set of endpoint detection and response (EDR) killers, i.e., tools for disrupting security software. Additionally, unlike most top-tier gangs, Gentlemen does not exhibit a strong US-centric victimology, instead targe…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1068** — Exploitation for Privilege Escalation
- **T1014** — Rootkit
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1489** — Service Stop
- **T1555.003** — Credentials from Web Browsers
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Gentlemen BYOVD driver file dropped to disk (eb.sys, nseckrnl.sys, ThrottleBlood.sys, havoc.sys, etc.)

`UC_58_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.process_id) as process_id values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action=created (Filesystem.file_name IN ("eb.sys","nseckrnl.sys","stpm_old.sys","stpm_new.sys","dmx.sys","360netmon_wfp.sys","G11.sys","googleApiUtil64.sys","ThrottleBlood.sys","havoc.sys","IMFForceDelete.sys")) by Filesystem.dest Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where NOT match(file_path, "(?i)\\\\Program Files\\\\(Safetica|Zemana|Qihoo|Baidu|Huawei|TechPowerUp)\\\\") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed")
| where FileName in~ ("eb.sys","nseckrnl.sys","stpm_old.sys","stpm_new.sys","dmx.sys","360netmon_wfp.sys","G11.sys","googleApiUtil64.sys","ThrottleBlood.sys","havoc.sys","IMFForceDelete.sys")
| where InitiatingProcessAccountName !endswith "$"
// Exclude legitimate vendor installer paths — Gentlemen drops to %TEMP%, %APPDATA%, %PUBLIC%, or staging dir
| where not(FolderPath matches regex @"(?i)\\Program Files(?: \(x86\))?\\(Safetica|Zemana|Qihoo 360|Baidu|Huawei|TechPowerUp|NSecsoft)\\")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### GentleKiller dropper executable in staging directory or AV-impersonating filename

`UC_58_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where (Processes.process_name IN ("Kasps.exe","FaceIT1.exe","FaceIT2.exe","EAAntiCheatLight.exe","EASolo2Light.exe","EASOLO1clear.exe","BitD1.exe","BitD2.exe","Deletor.exe","HwAudKiller.exe","Sent.exe","All.exe","buildx64.exe","buildx641.exe") OR Processes.process_path IN ("*\\GentlemenCollection\\*")) Processes.user!="*$" by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | where NOT match(process_path, "(?i)\\\\Program Files\\\\") | sort - lastTime
```

**Defender KQL:**
```kql
let Droppers = dynamic(["kasps.exe","faceit1.exe","faceit2.exe","eaanticheatlight.exe","easolo2light.exe","easolo1clear.exe","bitd1.exe","bitd2.exe","deletor.exe","hwaudkiller.exe","sent.exe","all.exe","buildx64.exe","buildx641.exe"]);
let GentlemenHashes = dynamic([
  "8AE6BD18B129061F63642531F1B684CF0383C75D","D605994FC72A2BB59B5CFB1624A1B9170ECA73A2",
  "5AA3124E5C4921E5EDFC60133B5D71DA21B07DA3","331879F5EEC8892BBD896F90BDBB1BAD0BF63BD6",
  "F11AEBCCB9A86A7E2E653F90BAEC697F233C255F","EF9CD06683159397F099CAA244E94E6EAAD96EBA",
  "A11EE9CDC59E5CAA59AEFD27B30D104F3AD68E62","2F86898528C6CAB3540C486A9BFAA0C029B73950",
  "A19117175DBC9BA4D23B5DCE8415E299A2E32192","D29670E684E40DDC89B47010C37CBC96737035B6",
  "CF4D74DF17A91B4A36A2911B22AFEC5D8FA93A01","7131B377E96016DC1911020C9F95B1B4D042D7B4",
  "F0537CBB773AE12100B36731E7C39F5A9D852B14","A5CF917EC4A7DFBDFA43621398604805D860C718",
  "D4B19141102015D436321E6F26976E98183CFD27"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where SHA1 in (GentlemenHashes)
   or FolderPath has "GentlemenCollection"
   or (tolower(FileName) in (Droppers) and FolderPath matches regex @"(?i)\\(Users\\Public|Temp|AppData|ProgramData|Windows\\Temp|Intel|PerfLogs)\\")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1, SHA256,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath
| order by Timestamp desc
```

### Kernel-mode service registration for Gentlemen BYOVD drivers (Havoc service / %TEMP%\*.sys ImagePath)

`UC_58_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as ImagePath values(Registry.process_name) as process_name from datamodel=Endpoint.Registry where Registry.registry_path="*\\CurrentControlSet\\Services\\*\\ImagePath" (Registry.registry_value_data IN ("*\\eb.sys","*\\nseckrnl.sys","*\\stpm_old.sys","*\\stpm_new.sys","*\\dmx.sys","*\\360netmon_wfp.sys","*\\G11.sys","*\\googleApiUtil64.sys","*\\ThrottleBlood.sys","*\\havoc.sys","*\\IMFForceDelete.sys") OR Registry.registry_key_name="*\\Services\\Havoc\\*") by Registry.dest Registry.registry_path Registry.registry_value_data | `drop_dm_object_name(Registry)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\CurrentControlSet\Services\"
| where (RegistryValueName =~ "ImagePath"
         and RegistryValueData matches regex @"(?i)\\(eb|nseckrnl|stpm_old|stpm_new|dmx|360netmon_wfp|G11|googleApiUtil64|ThrottleBlood|havoc|IMFForceDelete)\.sys")
   or RegistryKey matches regex @"(?i)\\Services\\Havoc($|\\)"
   or (RegistryValueName =~ "ImagePath"
       and RegistryValueData matches regex @"(?i)\\(Temp|AppData|ProgramData|Users\\Public|GentlemenCollection)\\[^\\]+\.sys")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Mass termination of EDR/AV processes by single non-system process (GentleKiller behavioral)

`UC_58_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_name) as killed_processes dc(Processes.process_name) as distinct_killed from datamodel=Endpoint.Processes where Processes.action="terminated" Processes.process_name IN ("MsMpEng.exe","MsSense.exe","SecurityHealthService.exe","CSFalconService.exe","csfalcondaterepair.exe","SentinelAgentWorker.exe","SentinelStaticEngine.exe","SentinelAgent.exe","SophosMTR.exe","SophosHealth.exe","SophosClean.exe","avp.exe","klserver.exe","bdagent.exe","bdservicehost.exe","ekrn.exe","egui.exe","mcshield.exe","masvc.exe","avgsvc.exe","avgui.exe","avastsvc.exe","avastui.exe","HuntressAgent.exe","CarbonBlack.exe","cb.exe","cybereason.exe","darktrace.exe") by Processes.dest Processes.parent_process_name Processes.parent_process_path span=5m | `drop_dm_object_name(Processes)` | where distinct_killed >= 5 AND parent_process_name!="services.exe" AND parent_process_name!="wininit.exe" | sort - lastTime
```

**Defender KQL:**
```kql
let EDRTargets = dynamic([
  "msmpeng.exe","mssense.exe","securityhealthservice.exe","smartscreen.exe",
  "csfalconservice.exe","csfalcondaterepair.exe","csfalconcontainer.exe",
  "sentinelagentworker.exe","sentinelstaticengine.exe","sentinelagent.exe","sentinelhelperservice.exe",
  "sophosmtr.exe","sophoshealth.exe","sophosclean.exe","sophosfilescanner.exe",
  "avp.exe","klserver.exe","klnagent.exe",
  "bdagent.exe","bdservicehost.exe","vsserv.exe",
  "ekrn.exe","egui.exe","ecmd.exe",
  "mcshield.exe","masvc.exe","mfemms.exe",
  "avgsvc.exe","avgui.exe","avastsvc.exe","avastui.exe",
  "huntressagent.exe","huntressrio.exe",
  "carbonblack.exe","cb.exe","cybereason.exe","darktrace.exe",
  "traps.exe","cortex.exe","cyserver.exe",
  "tanium.exe","taniumclient.exe","threatlocker.exe",
  "deepinstinct.exe","diservice.exe","elastic-agent.exe","elastic-endpoint.exe"]);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ActionType == "ProcessTerminated" or ActionType == "ProcessKilled"
| where tolower(FileName) in (EDRTargets)
| where InitiatingProcessFileName !in~ ("services.exe","wininit.exe","system","taskhostw.exe","taskmgr.exe","msiexec.exe","trustedinstaller.exe")
| where InitiatingProcessAccountName !endswith "$" or InitiatingProcessFolderPath has_any (@"\Temp\", @"\AppData\", @"\Public\", @"\ProgramData\", "GentlemenCollection")
| summarize KillCount = dcount(FileName),
            VictimProcesses = make_set(FileName, 50),
            FirstKill = min(Timestamp),
            LastKill = max(Timestamp)
          by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName,
             bin(Timestamp, 5m)
| where KillCount >= 5     // 5 distinct EDR/AV processes terminated in a 5-minute window
| order by FirstKill desc
```

### OxideHarvest credential stealer command-line pattern (-i hosts -u user -p pass -o output)

`UC_58_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent_process_name values(Processes.process_hash) as process_hash from datamodel=Endpoint.Processes where Processes.user!="*$" (Processes.process_name IN ("buildx64.exe","buildx641.exe") OR (Processes.process="*-i *" AND Processes.process="*-u *" AND Processes.process="*-p *" AND Processes.process="*-o *" AND Processes.process="*-t *")) by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
let OxideHashes = dynamic(["A5CF917EC4A7DFBDFA43621398604805D860C718", "D4B19141102015D436321E6F26976E98183CFD27"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where SHA1 in (OxideHashes)
   or FileName in~ ("buildx64.exe","buildx641.exe")
   or (ProcessCommandLine matches regex @"(?i)\s-i\s+\S+\.\S+"
       and ProcessCommandLine matches regex @"(?i)\s-u\s+\S+"
       and ProcessCommandLine matches regex @"(?i)\s-p\s+\S+"
       and ProcessCommandLine matches regex @"(?i)\s-o\s+\S+"
       and ProcessCommandLine matches regex @"(?i)\s-t\s+\d+")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, SHA1, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath
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

Severity classified as **HIGH** based on: 8 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
