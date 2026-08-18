# [HIGH] Top enterprise SCA tools in 2026

**Source:** Aikido
**Published:** 2026-08-14
**Article:** https://www.aikido.dev/blog/top-enterprise-sca-tools

## Threat Profile

Blog DevSec Tools & Comparisons Top enterprise SCA tools in 2026 Top enterprise SCA tools in 2026 Written by Nicholas Thomson Published on: Aug 14, 2026 Last updated on: Aug 15, 2026 2026 saw new software supply chain attacks landing almost every week, and malicious actors are showing no sign of letting up. In August, attackers compromised the maintainer behind keyv , a caching library pulling roughly 127 million weekly downloads, and pushed a credential-stealing worm across the entire package f…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `awqhnjewqjkl.icu`
- **Domain (defanged):** `pypi-get.com`
- **Domain (defanged):** `js-mirror.com`
- **Domain (defanged):** `npm-cache.com`
- **SHA256:** `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc`
- **SHA256:** `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb`
- **SHA256:** `927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f`
- **SHA256:** `14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128`
- **SHA256:** `3f3f42d072bd36860ab7bd7fb5e10ac0d22c741c13c89505ccd6ec0ea572eea7`
- **SHA256:** `29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52287c24e4f1a7`
- **SHA256:** `619c56acf572df75b6004a6fc013c80900316a76099b241d64312da3a44f10b4`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

### Article-specific behavioural hunt — Top enterprise SCA tools in 2026

`UC_39_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Top enterprise SCA tools in 2026 ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Top enterprise SCA tools in 2026
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `awqhnjewqjkl.icu`, `pypi-get.com`, `js-mirror.com`, `npm-cache.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc`, `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb`, `927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f`, `14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128`, `3f3f42d072bd36860ab7bd7fb5e10ac0d22c741c13c89505ccd6ec0ea572eea7`, `29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52287c24e4f1a7`, `619c56acf572df75b6004a6fc013c80900316a76099b241d64312da3a44f10b4`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
