# [HIGH] Unplug your way to better code

**Source:** Cisco Talos
**Published:** 2026-05-07
**Article:** https://blog.talosintelligence.com/unplug-your-way-to-better-code/

## Threat Profile

Unplug your way to better code 
By 
Amy Ciminnisi 
Thursday, May 7, 2026 14:00
Threat Source newsletter
Welcome to this week’s edition of the Threat Source newsletter.
Hey, you. Yeah, you! The person endlessly scrolling or typing away at their computer. Did you touch grass today? It's just an expression, but if nature’s your thing, that works just fine.
What I do mean is that due to the nature of the field, cybersecurity is incredibly intangible. You can’t reach out and touch your logs, or the p…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`
- **SHA256:** `96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974`
- **SHA256:** `90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59`
- **SHA256:** `e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba`
- **SHA256:** `a31f222fc283227f5e7988d1ad9c0aecd66d58bb7b4d8518ae23e110308dbf91`
- **MD5:** `2915b3f8b703eb744fc54c81f4a9c67f`
- **MD5:** `aac3165ece2959f39ff98334618d10d9`
- **MD5:** `c2efb2dcacba6d3ccc175b6ce1b7ed0a`
- **MD5:** `dbd8dbecaa80795c135137d69921fdba`
- **MD5:** `7bdbd180c081fa63ca94f9c22c457376`

## MITRE ATT&CK Techniques

- **T1071.004** — DNS
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1496** — Resource Hijacking
- **T1055** — Process Injection
- **T1036.005** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Talos weekly prevalent-malware hash match (Coinminer / Injector / Dropper.Miner)

`UC_35_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name values(Processes.process_name) as process_name from datamodel=Endpoint.Processes where Processes.process_hash IN ("9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507","96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974","90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59","e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba","a31f222fc283227f5e7988d1ad9c0aecd66d58bb7b4d8518ae23e110308dbf91","2915b3f8b703eb744fc54c81f4a9c67f","aac3165ece2959f39ff98334618d10d9","c2efb2dcacba6d3ccc175b6ce1b7ed0a","dbd8dbecaa80795c135137d69921fdba","7bdbd180c081fa63ca94f9c22c457376") by Processes.dest Processes.user Processes.process_hash Processes.process_name | `drop_dm_object_name(Processes)` | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as written_by from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507","96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974","90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59","e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba","a31f222fc283227f5e7988d1ad9c0aecd66d58bb7b4d8518ae23e110308dbf91") by Filesystem.dest Filesystem.file_hash Filesystem.file_name | `drop_dm_object_name(Filesystem)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let SHA256_IOCs = dynamic(["9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507","96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974","90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59","e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba","a31f222fc283227f5e7988d1ad9c0aecd66d58bb7b4d8518ae23e110308dbf91"]);
let MD5_IOCs = dynamic(["2915b3f8b703eb744fc54c81f4a9c67f","aac3165ece2959f39ff98334618d10d9","c2efb2dcacba6d3ccc175b6ce1b7ed0a","dbd8dbecaa80795c135137d69921fdba","7bdbd180c081fa63ca94f9c22c457376"]);
union isfuzzy=true
(DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (SHA256_IOCs) or MD5 in (MD5_IOCs)
  | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, MD5, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Source="DeviceProcessEvents"),
(DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (SHA256_IOCs) or MD5 in (MD5_IOCs)
  | where ActionType in ("FileCreated","FileModified","FileRenamed")
  | project Timestamp, DeviceName, FileName, FolderPath, SHA256, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, Source="DeviceFileEvents"),
(DeviceImageLoadEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (SHA256_IOCs) or MD5 in (MD5_IOCs)
  | project Timestamp, DeviceName, FileName, FolderPath, SHA256, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine, Source="DeviceImageLoadEvents")
| order by Timestamp desc
```

### [LLM] Talos dropper filename pattern d4aa3e7010220ad1b458fac17039c274_<N>_Exe.exe

`UC_35_4` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.parent_process_name) as parent_process_name values(Processes.process) as process values(Processes.process_hash) as process_hash from datamodel=Endpoint.Processes where Processes.process_name="d4aa3e7010220ad1b458fac17039c274_*_Exe.exe" by Processes.dest Processes.process_name | `drop_dm_object_name(Processes)` | rex field=process_name "^d4aa3e7010220ad1b458fac17039c274_(?<seq>\d+)_Exe\.exe$" | where isnotnull(seq) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let DropperPattern = @"(?i)^d4aa3e7010220ad1b458fac17039c274_\d+_Exe\.exe$";
union isfuzzy=true
(DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName matches regex DropperPattern
  | extend Seq = toint(extract(@"_(\d+)_Exe\.exe$", 1, FileName))
  | project Timestamp, DeviceName, AccountName, FileName, Seq, FolderPath, SHA256, MD5, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, Source="ProcessEvents"),
(DeviceFileEvents
  | where Timestamp > ago(30d)
  | where ActionType in ("FileCreated","FileRenamed")
  | where FileName matches regex DropperPattern
  | extend Seq = toint(extract(@"_(\d+)_Exe\.exe$", 1, FileName))
  | project Timestamp, DeviceName, FileName, Seq, FolderPath, SHA256, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, Source="FileEvents")
| order by Timestamp desc
```

### DNS tunneling / TXT-heavy domain queries

`UC_DNS_TUNNEL` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
    where DNS.message_type="QUERY"
    by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| eval qlen=len(query)
| where qlen > 50
| rex field=query "(?<second_level_domain>[\w-]+\.[\w-]+)$"
| stats sum(count) AS qcount, dc(query) AS unique_subs, max(qlen) AS max_label
    by src, second_level_domain
| where qcount > 100 AND unique_subs > 20
| sort - qcount
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 53 and isnotempty(RemoteUrl)
| extend qlen = strlen(RemoteUrl)
| where qlen > 50
| extend SecondLevelDomain = extract(@"([\w-]+\.[a-zA-Z]{2,})$", 1, RemoteUrl)
| summarize qcount = count(), uniqueSubs = dcount(RemoteUrl), maxLabel = max(qlen)
    by DeviceName, SecondLevelDomain
| where qcount > 100 and uniqueSubs > 20
| order by qcount desc
```

### Article-specific behavioural hunt — Unplug your way to better code

`UC_35_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Unplug your way to better code ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("vid001.exe","d4aa3e7010220ad1b458fac17039c274_63_exe.exe","apq9305.dll","d4aa3e7010220ad1b458fac17039c274_62_exe.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("vid001.exe","d4aa3e7010220ad1b458fac17039c274_63_exe.exe","apq9305.dll","d4aa3e7010220ad1b458fac17039c274_62_exe.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Unplug your way to better code
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("vid001.exe", "d4aa3e7010220ad1b458fac17039c274_63_exe.exe", "apq9305.dll", "d4aa3e7010220ad1b458fac17039c274_62_exe.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("vid001.exe", "d4aa3e7010220ad1b458fac17039c274_63_exe.exe", "apq9305.dll", "d4aa3e7010220ad1b458fac17039c274_62_exe.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`, `96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974`, `90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59`, `e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba`, `a31f222fc283227f5e7988d1ad9c0aecd66d58bb7b4d8518ae23e110308dbf91`, `2915b3f8b703eb744fc54c81f4a9c67f`, `aac3165ece2959f39ff98334618d10d9`, `c2efb2dcacba6d3ccc175b6ce1b7ed0a` _(+2 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
