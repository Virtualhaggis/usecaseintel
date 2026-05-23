# [CRIT] Agent AI is Coming. Are You Ready?

**Source:** The Hacker News
**Published:** 2026-05-20
**Article:** https://thehackernews.com/2026/05/agent-ai-is-coming-are-you-ready.html

## Threat Profile

Microsoft Releases Mitigation for YellowKey BitLocker Bypass CVE-2026-45585 Exploit 
 Ravie Lakshmanan  May 20, 2026 Vulnerability / Encryption 
Microsoft on Tuesday released a mitigation for a BitLocker bypass vulnerability named YellowKey following its public disclosure last week.
The zero-day flaw, now tracked as CVE-2026-45585 , carries a CVSS score of 6.8. It has been described as a BitLocker security feature bypass.
"Microsoft is aware of a security feature bypass vulnerability in Window…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45585`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1204.002** — User Execution: Malicious File
- **T1542.003** — Pre-OS Boot: Bootkit
- **T1112** — Modify Registry
- **T1562.001** — Impair Defenses: Disable or Modify Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] YellowKey CVE-2026-45585 unmitigated state — autofstx.exe still in WinRE BootExecute

`UC_73_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\Control\\Session Manager*" Registry.registry_value_name="BootExecute" Registry.registry_value_data="*autofstx*" by Registry.dest Registry.user Registry.registry_value_data Registry.action | `drop_dm_object_name(Registry)` | stats max(lastTime) as lastTime values(registry_value_data) as latest_values values(action) as actions by dest user | where like(latest_values,"%autofstx%") | convert ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(60d)
| where RegistryKey endswith @"Control\Session Manager"
| where RegistryValueName =~ "BootExecute"
| summarize arg_max(Timestamp, *) by DeviceId
| where RegistryValueData has "autofstx"
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform, OSVersion, OSBuild) by DeviceId
  ) on DeviceId
| project Timestamp, DeviceId, DeviceName, OSPlatform, OSVersion, OSBuild,
          RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] YellowKey mitigation tampered — autofstx.exe re-added to WinRE BootExecute REG_MULTI_SZ

`UC_73_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.action=modified Registry.registry_path="*\\Control\\Session Manager*" Registry.registry_value_name="BootExecute" Registry.registry_value_data="*autofstx*" by Registry.dest Registry.user Registry.process_name Registry.process_id Registry.registry_value_data | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey endswith @"Control\Session Manager"
| where RegistryValueName =~ "BootExecute"
| where RegistryValueData has "autofstx"
| where isnotempty(PreviousRegistryValueData) and not (PreviousRegistryValueData has "autofstx")
| project Timestamp, DeviceId, DeviceName, RegistryKey, RegistryValueName,
          PreviousRegistryValueData, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine,
          InitiatingProcessAccountDomain, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
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

### Article-specific behavioural hunt — Agent AI is Coming. Are You Ready?

`UC_73_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Agent AI is Coming. Are You Ready? ```
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
// Article-specific bespoke detection — Agent AI is Coming. Are You Ready?
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
  - CVE(s): `CVE-2026-45585`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
