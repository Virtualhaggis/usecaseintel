# [HIGH] Less panic patching, more precision

**Source:** Cisco Talos
**Published:** 2026-05-28
**Article:** https://blog.talosintelligence.com/less-panic-patching-more-precision/

## Threat Profile

Less panic patching, more precision 
By 
Thorsten Rosendahl 
Thursday, May 28, 2026 14:00
Threat Source newsletter
Welcome to this week's edition of the Threat Source newsletter. 
Recently, Martin closed his introduction with a  warning : Ready or not, the time of much patching is coming. I've been chewing on that one for a while because I'm rethinking my own enrichment pipelines along these lines, and the questions Martin raised are the ones I keep running into — with one or two ideas on what p…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`
- **SHA256:** `9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f`
- **SHA256:** `5e6060df7e8114cb7b412260870efd1dc05979454bd907d8750c669ae6fcbcfe`
- **SHA256:** `afc8a00883a4ea07df2dc1d4ed02f8a23b35c9456413b438a2d9ce3ae5076638`
- **MD5:** `2915b3f8b703eb744fc54c81f4a9c67f`
- **MD5:** `38de5b216c33833af710e88f7f64fc98`
- **MD5:** `a2cf85d22a54e26794cbc7be16840bb1`
- **MD5:** `cc4d231df34e57f59eb970353c7d9de2`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
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

### Article-specific behavioural hunt — Less panic patching, more precision

`UC_320_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Less panic patching, more precision ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("vid001.exe","sample.exe","a2cf85d22a54e26794cbc7be16840bb1.exe","autopico.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("vid001.exe","sample.exe","a2cf85d22a54e26794cbc7be16840bb1.exe","autopico.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Less panic patching, more precision
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("vid001.exe", "sample.exe", "a2cf85d22a54e26794cbc7be16840bb1.exe", "autopico.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("vid001.exe", "sample.exe", "a2cf85d22a54e26794cbc7be16840bb1.exe", "autopico.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`, `9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f`, `5e6060df7e8114cb7b412260870efd1dc05979454bd907d8750c669ae6fcbcfe`, `afc8a00883a4ea07df2dc1d4ed02f8a23b35c9456413b438a2d9ce3ae5076638`, `2915b3f8b703eb744fc54c81f4a9c67f`, `38de5b216c33833af710e88f7f64fc98`, `a2cf85d22a54e26794cbc7be16840bb1`, `cc4d231df34e57f59eb970353c7d9de2`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
