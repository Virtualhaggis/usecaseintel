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
- **T1068** — Exploitation for Privilege Escalation
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1489** — Service Stop

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GentleKiller BYOVD vulnerable-driver file drop (Kaspersky/FACEIT/Valorant/Javelin/etc.)

`UC_13_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action="created" Filesystem.file_name IN ("eb.sys","nseckrnl.sys","GameDriverX64.sys","stpm_old.sys","stpm_new.sys","dmx.sys","360netmon_wfp.sys","IMFForceDelete.sys","PoisonX.sys") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.process_path
| `drop_dm_object_name(Filesystem)`
| where NOT match(file_path,"(?i)C:\\\\Windows\\\\System32\\\\DriverStore\\\\")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName in~ ("eb.sys","nseckrnl.sys","GameDriverX64.sys","stpm_old.sys","stpm_new.sys","dmx.sys","360netmon_wfp.sys","IMFForceDelete.sys","PoisonX.sys")
| where InitiatingProcessAccountName !endswith "$"
| where not(FolderPath has @"C:\Windows\System32\DriverStore\")
| project Timestamp, DeviceName, FileName, FolderPath, SHA1, SHA256,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### GentleKiller / EDR-killer driver service registration in CurrentControlSet\Services

`UC_13_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\CurrentControlSet\\Services\\*" Registry.registry_value_data IN ("*eb.sys*","*nseckrnl.sys*","*GameDriverX64.sys*","*stpm_old.sys*","*stpm_new.sys*","*dmx.sys*","*360netmon_wfp.sys*","*IMFForceDelete.sys*","*PoisonX.sys*","*googleApiUtil64.sys*","*ThrottleBlood.sys*","*havoc.sys*","*hrwfpdrv.sys*") by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\CurrentControlSet\Services\"
| where RegistryValueName =~ "ImagePath"
| where RegistryValueData has_any ("eb.sys","nseckrnl.sys","GameDriverX64.sys","stpm_old.sys","stpm_new.sys","dmx.sys","360netmon_wfp.sys","IMFForceDelete.sys","PoisonX.sys","googleApiUtil64.sys","ThrottleBlood.sys","havoc.sys","hrwfpdrv.sys")
| where InitiatingProcessAccountName !endswith "$" or InitiatingProcessFileName !in~ ("services.exe","TrustedInstaller.exe")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Third-party EDR-killer driver image load (HexKiller / ThrottleBlood / HavocKiller / hrwfpdrv)

`UC_13_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("googleApiUtil64.sys","ThrottleBlood.sys","havoc.sys","hrwfpdrv.sys") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(14d)
| where FileName in~ ("googleApiUtil64.sys","ThrottleBlood.sys","havoc.sys","hrwfpdrv.sys")
| project Timestamp, DeviceName, FileName, FolderPath, SHA1, SHA256,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### OxideHarvest stealer reading credential stores across niche browser portfolio (Torch/Comodo/Epic/BlackHawk/IceCat)

`UC_13_10` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.action="read" (Filesystem.file_path="*\\Torch\\User Data\\*" OR Filesystem.file_path="*\\Comodo\\Dragon\\User Data\\*" OR Filesystem.file_path="*\\Epic Privacy Browser\\*" OR Filesystem.file_path="*\\Waterfox\\Profiles\\*" OR Filesystem.file_path="*\\NETGATE Technologies\\BlackHawk\\*" OR Filesystem.file_path="*\\Mozilla\\IceCat\\*" OR Filesystem.file_path="*\\BraveSoftware\\Brave-Browser\\*" OR Filesystem.file_path="*\\Vivaldi\\User Data\\*" OR Filesystem.file_path="*\\Opera Software\\Opera GX Stable\\*") (Filesystem.file_name IN ("Login Data","Cookies","Web Data","logins.json","key4.db","cookies.sqlite")) by Filesystem.dest Filesystem.user Filesystem.process_name _time span=10m
| `drop_dm_object_name(Filesystem)`
| where process_name!="chrome.exe" AND process_name!="msedge.exe" AND process_name!="firefox.exe" AND process_name!="brave.exe" AND process_name!="opera.exe" AND process_name!="vivaldi.exe" AND process_name!="waterfox.exe"
| stats dcount(paths) as PathsTouched values(paths) as paths by dest user process_name _time
| where PathsTouched >= 2
```

**Defender KQL:**
```kql
let NicheBrowserStores = dynamic([@"\Torch\User Data\", @"\Comodo\Dragon\User Data\", @"\Epic Privacy Browser\", @"\Waterfox\Profiles\", @"\NETGATE Technologies\BlackHawk\", @"\Mozilla\IceCat\", @"\BraveSoftware\Brave-Browser\", @"\Vivaldi\User Data\", @"\Opera Software\Opera GX Stable\", @"\Opera Software\Opera Stable\"]);
let CredFiles = dynamic(["Login Data","Cookies","Web Data","logins.json","key4.db","cookies.sqlite","places.sqlite"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ (CredFiles)
| where FolderPath has_any (NicheBrowserStores)
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe","waterfox.exe","icecat.exe","dragon.exe","torch.exe","epic.exe","operagx.exe","blackhawk.exe")
| where InitiatingProcessAccountName !endswith "$"
| summarize StoresTouched = dcount(strcat(tostring(array_index_of(NicheBrowserStores, tostring(extract("(\\\\[^\\\\]+\\\\(?:User Data|Profiles)\\\\)", 1, FolderPath))))),
            PathsTouched = make_set(FolderPath, 25),
            FilesTouched = make_set(FileName, 25),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Reads = count()
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessFolderPath, InitiatingProcessCommandLine, bin(Timestamp, 10m)
| where StoresTouched >= 2 or Reads >= 5
| order by LastSeen desc
```

### Mass termination of EDR/AV processes consistent with GentleKiller's 400-process target list

`UC_13_11` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(Processes.process) as cmds values(Processes.dest) as dest from datamodel=Endpoint.Processes where Processes.process_name IN ("taskkill.exe","powershell.exe","pwsh.exe","net.exe","sc.exe","wmic.exe") (Processes.process="*MsMpEng*" OR Processes.process="*MsSense*" OR Processes.process="*SenseIR*" OR Processes.process="*CSFalcon*" OR Processes.process="*CSAgent*" OR Processes.process="*SentinelAgent*" OR Processes.process="*SentinelHelper*" OR Processes.process="*ekrn*" OR Processes.process="*egui*" OR Processes.process="*avp.exe*" OR Processes.process="*ksde*" OR Processes.process="*mfemms*" OR Processes.process="*mcshield*" OR Processes.process="*ccSvcHst*" OR Processes.process="*SymCorpUI*" OR Processes.process="*xagt*" OR Processes.process="*CylanceSvc*" OR Processes.process="*CarbonBlack*" OR Processes.process="*RepMgr*" OR Processes.process="*cb.exe*" OR Processes.process="*sophos*" OR Processes.process="*HxTsr*" OR Processes.process="*TaniumClient*" OR Processes.process="*ds_agent*" OR Processes.process="*ds_monitor*" OR Processes.process="*BDAgent*" OR Processes.process="*vsserv*" OR Processes.process="*PccNTMon*" OR Processes.process="*tmccsf*" OR Processes.process="*360tray*" OR Processes.process="*QHSafeTray*" OR Processes.process="*RtkAudioService*") by Processes.user Processes.parent_process_id _time span=5m
| `drop_dm_object_name(Processes)`
| stats dc(cmds) as DistinctKills values(cmds) as KillCmds by dest user parent_process_id _time
| where DistinctKills >= 5
```

**Defender KQL:**
```kql
let EdrProcessTargets = dynamic(["MsMpEng.exe","MsSense.exe","SenseIR.exe","SenseCncProxy.exe","CSFalconService.exe","CSFalconContainer.exe","CSAgent.exe","SentinelAgent.exe","SentinelHelperService.exe","SentinelStaticEngine.exe","ekrn.exe","egui.exe","avp.exe","avpui.exe","ksde.exe","klnagent.exe","mfemms.exe","mcshield.exe","ccSvcHst.exe","SymCorpUI.exe","xagt.exe","CylanceSvc.exe","CylanceUI.exe","RepMgr.exe","cb.exe","CarbonBlackK.exe","sophos*","SAVService.exe","HxTsr.exe","TaniumClient.exe","ds_agent.exe","ds_monitor.exe","BDAgent.exe","vsserv.exe","PccNTMon.exe","tmccsf.exe","360tray.exe","QHSafeTray.exe","rphcp.exe","WRSA.exe","WSSecuritySvc.exe","PaloAltoNetworks*","Traps.exe","cyserver.exe"]);
let Window = 5m;
let TerminateCmds = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("taskkill.exe","powershell.exe","pwsh.exe","net.exe","sc.exe","wmic.exe")
    | where ProcessCommandLine has_any ("taskkill","Stop-Process","Stop-Service"," stop ","NtTerminateProcess","TerminateProcess")
    | mv-expand Target = EdrProcessTargets
    | where ProcessCommandLine has tostring(Target)
    | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
              InitiatingProcessId, InitiatingProcessCommandLine,
              KillerCmd = ProcessCommandLine, Target = tostring(Target)
    | summarize DistinctEdrTargets = dcount(Target), TargetSamples = make_set(Target, 50),
                CmdSamples = make_set(KillerCmd, 10),
                FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
                by DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessId,
                   bin(Timestamp, Window)
    | where DistinctEdrTargets >= 5;
let HandleOpens = DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("OpenProcessApiCall","ProcessPrimaryTokenModified")
    | where FileName in~ (EdrProcessTargets)
    | summarize DistinctEdrTargets = dcount(FileName),
                Handles = count(),
                TargetSamples = make_set(FileName, 50),
                FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
                by DeviceName, InitiatingProcessFileName, InitiatingProcessId,
                   InitiatingProcessCommandLine, bin(Timestamp, Window)
    | where DistinctEdrTargets >= 10;
union TerminateCmds, HandleOpens
| order by LastSeen desc
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

### Article-specific behavioural hunt — The Gentlemen RaaS Uses GentleKiller EDR Framework Targeting 400 Security Proces

`UC_13_6` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, IOCs present, 12 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
