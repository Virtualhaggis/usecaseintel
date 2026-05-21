# [HIGH] Microsoft shares mitigation for YellowKey Windows zero-day

**Source:** BleepingComputer
**Published:** 2026-05-20
**Article:** https://www.bleepingcomputer.com/news/microsoft/microsoft-shares-mitigation-for-yellowkey-windows-zero-day/

## Threat Profile

Microsoft shares mitigation for YellowKey Windows zero-day 
By Sergiu Gatlan 
May 20, 2026
03:31 AM
1 
Microsoft has shared mitigations for YellowKey, a recently disclosed Windows BitLocker zero-day vulnerability that grants access to protected drives.
The security flaw was disclosed last week by an anonymous security researcher known as 'Nightmare Eclipse,' who described it as a backdoor and published a proof-of-concept (PoC) exploit.
Nightmare Eclipse said that exploiting this zero-day involve…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45585`
- **CVE:** `CVE-2026-33825`
- **Domain (defanged):** `github.com/Nightmare-Eclipse/YellowKey`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1112** — Modify Registry
- **T1542.003** — Pre-OS Boot: Bootkit
- **T1105** — Ingress Tool Transfer
- **T1562.001** — Impair Defenses: Disable or Modify Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] YellowKey CVE-2026-45585 - autofstx.exe injected into BootExecute registry value

`UC_32_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as registry_value_data values(Registry.process_name) as process_name values(Registry.user) as user from datamodel=Endpoint.Registry where Registry.registry_path="*\\Control\\Session Manager*" Registry.registry_value_name="BootExecute" by Registry.dest Registry.registry_path Registry.registry_value_name | `drop_dm_object_name(Registry)` | search registry_value_data="*autofstx*" OR NOT registry_value_data="autocheck autochk *"
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\Control\Session Manager"
| where RegistryValueName =~ "BootExecute"
// YellowKey IOC: autofstx.exe, or any deviation from the default "autocheck autochk *"
| where RegistryValueData has "autofstx" or (isnotempty(RegistryValueData) and RegistryValueData !startswith "autocheck autochk")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, PreviousRegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFolderPath, ReportId
| order by Timestamp desc
```

### [LLM] YellowKey CVE-2026-45585 - autofstx.exe file artifact on disk or removable media

`UC_32_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_name="autofstx.exe" by Filesystem.dest Filesystem.file_name Filesystem.action | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "autofstx.exe"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5, FileSize,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName, RequestProtocol, RequestSourceIP, ShareName
| order by Timestamp desc
```

### [LLM] YellowKey CVE-2026-45585 - reagentc.exe WinRE image mount or trust re-establishment

`UC_32_6` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name="reagentc.exe" (Processes.process="*/mountre*" OR Processes.process="*/unmountre*" OR Processes.process="*/disable*" OR Processes.process="*/enable*") by Processes.dest Processes.process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "reagentc.exe"
| where ProcessCommandLine has_any ("/mountre","/unmountre","/disable","/enable")
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName !in~ ("TrustedInstaller.exe","wuauclt.exe")
// Bucket per host so the natural mitigation pair (disable -> enable) shows as one alert, not four
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Cmds = make_set(ProcessCommandLine, 16),
            Parents = make_set(InitiatingProcessFileName, 8),
            Users = make_set(AccountName, 8),
            HitCount = count()
          by DeviceName, bin(Timestamp, 1h)
| order by LastSeen desc
```

### [LLM] YellowKey CVE-2026-45585 - reg.exe loading WinRE registry hive offline

`UC_32_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name="reg.exe" Processes.process="*load*" (Processes.process="*WinRE*" OR Processes.process="*winre*" OR Processes.process="*\\mount\\*") by Processes.dest Processes.process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "reg.exe"
| where ProcessCommandLine has "load"
// YellowKey + Microsoft mitigation both reference the WinRE hive or the mounted WinRE path
| where ProcessCommandLine matches regex @"(?i)\b(HKLM\\WinRE|WinREHive|\\mount\\Windows\\System32\\config\\SYSTEM|reagent\.xml)"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          ParentProcessName = InitiatingProcessParentFileName, ReportId
| order by Timestamp desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Article-specific behavioural hunt — Microsoft shares mitigation for YellowKey Windows zero-day

`UC_32_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft shares mitigation for YellowKey Windows zero-day ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("autofstx.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("autofstx.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Microsoft shares mitigation for YellowKey Windows zero-day
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("autofstx.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("autofstx.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-45585`, `CVE-2026-33825`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `github.com/Nightmare-Eclipse/YellowKey`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 8 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
