# [HIGH] Close Encounters of the Human Kind

**Source:** Cisco Talos
**Published:** 2026-06-18
**Article:** https://blog.talosintelligence.com/close-encounters-of-the-human-kind/

## Threat Profile

Close Encounters of the Human Kind 
By 
Hazel Burton 
Thursday, June 18, 2026 14:00
Threat Source newsletter
Welcome to this week’s Threat Source newsletter. 
I love a Spielberg summer. His ability to imbue a sense of wonder, awe, curiosity, and connection means he’s in a league of his own. Granted, I haven’t felt that from him in a while, but when he hits? Oof. I feel like I need somebody to reach across and take off my sunglasses. 
So,  Disclosure Day  then. A group of friends and I visited a …

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`
- **SHA256:** `c0ad494457dcd9e964378760fb6aca86a23622045bca851d8f3ab49ec33978fe`
- **SHA256:** `9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f`
- **SHA256:** `e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba`
- **MD5:** `2915b3f8b703eb744fc54c81f4a9c67f`
- **MD5:** `bf9672ec85283fdf002d83662f0b08b7`
- **MD5:** `38de5b216c33833af710e88f7f64fc98`
- **MD5:** `dbd8dbecaa80795c135137d69921fdba`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1496** — Resource Hijacking

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Talos top-prevalence malware hash sweep — VID001.exe coinminer + f_000cd7.html (week of 2026-06-18)

`UC_16_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_hash IN ("9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507", "c0ad494457dcd9e964378760fb6aca86a23622045bca851d8f3ab49ec33978fe") OR Processes.process_name="VID001.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_hash Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507", "c0ad494457dcd9e964378760fb6aca86a23622045bca851d8f3ab49ec33978fe")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`]
| sort - lastTime
```

**Defender KQL:**
```kql
let TalosTopHashes = dynamic(["9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507", "c0ad494457dcd9e964378760fb6aca86a23622045bca851d8f3ab49ec33978fe"]);
let ProcessHits = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where SHA256 in~ (TalosTopHashes) or InitiatingProcessSHA256 in~ (TalosTopHashes)
    | project Timestamp, Source="DeviceProcessEvents", DeviceName, AccountName,
              FileName, FolderPath, SHA256, ProcessCommandLine,
              ParentFileName=InitiatingProcessFileName,
              ParentCmd=InitiatingProcessCommandLine;
let FileHits = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where SHA256 in~ (TalosTopHashes) or InitiatingProcessSHA256 in~ (TalosTopHashes)
    | project Timestamp, Source="DeviceFileEvents", DeviceName,
              AccountName=InitiatingProcessAccountName,
              FileName, FolderPath, SHA256,
              ProcessCommandLine=InitiatingProcessCommandLine,
              ParentFileName=InitiatingProcessParentFileName,
              ParentCmd="";
union ProcessHits, FileHits
| order by Timestamp desc
```

### Article-specific behavioural hunt — Close Encounters of the Human Kind

`UC_16_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Close Encounters of the Human Kind ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("vid001.exe","secoh-qad.exe","u992574.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("vid001.exe","secoh-qad.exe","u992574.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Close Encounters of the Human Kind
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("vid001.exe", "secoh-qad.exe", "u992574.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("vid001.exe", "secoh-qad.exe", "u992574.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`, `c0ad494457dcd9e964378760fb6aca86a23622045bca851d8f3ab49ec33978fe`, `9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f`, `e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba`, `2915b3f8b703eb744fc54c81f4a9c67f`, `bf9672ec85283fdf002d83662f0b08b7`, `38de5b216c33833af710e88f7f64fc98`, `dbd8dbecaa80795c135137d69921fdba`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
