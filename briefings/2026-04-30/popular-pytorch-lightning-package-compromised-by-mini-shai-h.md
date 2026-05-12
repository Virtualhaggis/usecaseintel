# [HIGH] Popular PyTorch Lightning Package Compromised by Mini Shai-Hulud

**Source:** Aikido
**Published:** 2026-04-30
**Article:** https://www.aikido.dev/blog/pytorch-lightning-pypi-compromise-mini-shai-hulud

## Threat Profile

Blog Vulnerabilities & Threats Popular PyTorch Lightning Package Compromised by Mini Shai-Hulud Popular PyTorch Lightning Package Compromised by Mini Shai-Hulud Written by Ilyas Makari Published on: Apr 30, 2026 The Mini Shai-Hulud supply chain campaign has spread to PyPI. Versions 2.6.2 and 2.6.3 of the popular lightning Python package, used widely for training PyTorch models, contains malicious code that silently exfiltrates developer credentials, cloud secrets, and cryptocurrency wallets.
Thi…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `5f5852b5f604369945118937b058e49064612ac69826e0adadca39a357dfb5b1`
- **SHA256:** `8046a11187c135da6959862ff3846e99ad15462d2ec8a2f77a30ad53ebd5dcf2`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1129** — Shared Modules
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Mini Shai-Hulud: Python subprocess spawns `_runtime/start.py` from lightning site-packages

`UC_179_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","pythonw.exe","python3.exe","python","python3")) AND Processes.process="*start.py*" AND Processes.process="*_runtime*" AND (Processes.process="*lightning*" OR Processes.parent_process="*lightning*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_path Processes.process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","python3.exe","python","python3")
| where ProcessCommandLine has "start.py"
| where ProcessCommandLine has "_runtime"
| where ProcessCommandLine has "lightning" or InitiatingProcessCommandLine has "lightning" or FolderPath has "lightning" or InitiatingProcessFolderPath has "lightning"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] Mini Shai-Hulud PyPI payload known SHA256 (start.py / router_runtime.js)

`UC_179_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("5f5852b5f604369945118937b058e49064612ac69826e0adadca39a357dfb5b1","8046a11187c135da6959862ff3846e99ad15462d2ec8a2f77a30ad53ebd5dcf2") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | append [| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_hash IN ("5f5852b5f604369945118937b058e49064612ac69826e0adadca39a357dfb5b1","8046a11187c135da6959862ff3846e99ad15462d2ec8a2f77a30ad53ebd5dcf2") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _badHashes = dynamic([
    "5f5852b5f604369945118937b058e49064612ac69826e0adadca39a357dfb5b1",
    "8046a11187c135da6959862ff3846e99ad15462d2ec8a2f77a30ad53ebd5dcf2"]);
union
(DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (_badHashes)
  | project Timestamp, DeviceName, Src="DeviceFileEvents", ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
(DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (_badHashes) or InitiatingProcessSHA256 in (_badHashes)
  | project Timestamp, DeviceName, Src="DeviceProcessEvents", ActionType="ProcessCreated", FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName=AccountName),
(DeviceImageLoadEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (_badHashes)
  | project Timestamp, DeviceName, Src="DeviceImageLoadEvents", ActionType="ImageLoaded", FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName)
| order by Timestamp desc
```

### [LLM] Mini Shai-Hulud: Bun runtime executing `router_runtime.js` (2nd-stage stealer)

`UC_179_7` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("bun","bun.exe") OR Processes.process="*\\bun.exe*" OR Processes.process="*/bun *") AND (Processes.process="*router_runtime.js*" OR Processes.process="*router_init.js*" OR Processes.process="*tanstack_runner.js*" OR Processes.process="*_runtime*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("bun.exe","bun") or InitiatingProcessFileName in~ ("bun.exe","bun")
| where ProcessCommandLine has_any ("router_runtime.js","router_init.js","tanstack_runner.js") or ProcessCommandLine has "_runtime" or InitiatingProcessCommandLine has_any ("router_runtime.js","router_init.js")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FileName, FolderPath, ProcessCommandLine, SHA256
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

### Article-specific behavioural hunt — Popular PyTorch Lightning Package Compromised by Mini Shai-Hulud

`UC_179_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Popular PyTorch Lightning Package Compromised by Mini Shai-Hulud ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("__init__.py","start.py","router_runtime.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("__init__.py","start.py","router_runtime.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Popular PyTorch Lightning Package Compromised by Mini Shai-Hulud
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("__init__.py", "start.py", "router_runtime.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("__init__.py", "start.py", "router_runtime.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `5f5852b5f604369945118937b058e49064612ac69826e0adadca39a357dfb5b1`, `8046a11187c135da6959862ff3846e99ad15462d2ec8a2f77a30ad53ebd5dcf2`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
