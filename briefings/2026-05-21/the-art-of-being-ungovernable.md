# [HIGH] The art of being ungovernable

**Source:** Cisco Talos
**Published:** 2026-05-21
**Article:** https://blog.talosintelligence.com/the-art-of-being-ungovernable/

## Threat Profile

The art of being ungovernable 
By 
William Largent 
Thursday, May 21, 2026 14:00
Threat Source newsletter
Welcome to this week’s edition of the Threat Source newsletter.  
“It takes very little to govern good people. Very little. And bad people can’t be governed at all. Or if they could, I never heard of it.” ― Cormac McCarthy, No Country for Old Men  
Most of my career has been built on dichotomy: striving to be a supportive teammate while also pushing every boundary in front of me. I've often …

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`
- **SHA256:** `d87e8d9d43758ce67a8052cb2334b99cc24f9b0437ee44815f360be0b22d835a`
- **SHA256:** `9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f`
- **SHA256:** `acd55c44b8b0d66d66defed85ca18082c092f048d3621da827fce593305c11fd`
- **SHA256:** `96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974`
- **MD5:** `2915b3f8b703eb744fc54c81f4a9c67f`
- **MD5:** `362498c3e71eeaa066a67e4a3f981d1c`
- **MD5:** `38de5b216c33833af710e88f7f64fc98`
- **MD5:** `0f03f72a92aef6d63eb74e73f8ac201d`
- **MD5:** `aac3165ece2959f39ff98334618d10d9`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1505.004** — Server Software Component: IIS Components
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1496** — Resource Hijacking
- **T1027.005** — Indicator Removal from Tools
- **T1565.002** — Data Manipulation: Transmitted Data Manipulation
- **T1090** — Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] BadIIS rogue native module drop in IIS folders (demo.pdb / Chinese path heuristic)

`UC_111_2` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash values(Filesystem.process_name) as writer_process from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\inetsrv\\*" OR Filesystem.file_path="*\\inetpub\\wwwroot\\bin\\*" OR Filesystem.file_path="*\\inetpub\\custerr\\*") (Filesystem.file_name="*.dll" OR Filesystem.file_name="*.exe") Filesystem.process_name!="msiexec.exe" Filesystem.process_name!="TrustedInstaller.exe" Filesystem.process_name!="drvinst.exe" Filesystem.process_name!="appcmd.exe" by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where match(file_path, "[\x{4e00}-\x{9fff}]") OR NOT match(file_path, "^[A-Za-z]:\\\\Windows\\\\System32\\\\inetsrv\\\\") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let IISWriters = dynamic(["msiexec.exe","trustedinstaller.exe","drvinst.exe","appcmd.exe","windowsupdatebox.exe","tiworker.exe"]);
let FileDrops = DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName endswith ".dll" or FileName endswith ".exe"
| where FolderPath has @"\inetsrv\" or FolderPath has @"\inetpub\wwwroot\bin\" or FolderPath has @"\inetpub\custerr\"
| where not(tolower(InitiatingProcessFileName) in (IISWriters))
| where FolderPath matches regex @"[\u4e00-\u9fff]" or not(FolderPath startswith_cs @"C:\Windows\System32\inetsrv\")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, Source="FileWrite";
let ModuleLoads = DeviceImageLoadEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName endswith ".dll"
| where FolderPath matches regex @"[\u4e00-\u9fff]"
   or (not(FolderPath startswith_cs @"C:\Windows\System32\inetsrv\") and not(FolderPath startswith_cs @"C:\Windows\Microsoft.NET\") and not(FolderPath startswith_cs @"C:\Program Files\") and not(FolderPath startswith_cs @"C:\Program Files (x86)\") and not(FolderPath startswith_cs @"C:\Windows\WinSxS\") and not(FolderPath startswith_cs @"C:\Windows\assembly\"))
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName="w3wp.exe", InitiatingProcessCommandLine, InitiatingProcessAccountName, Source="ImageLoad";
union FileDrops, ModuleLoads
| order by Timestamp desc
```

### [LLM] Talos weekly prevalent-malware hash hit (Coinminer worm / TunMirror / SECOH-QAD / KMS-Loader)

`UC_111_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_name) as process_name values(Processes.process_path) as process_path values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_hash IN ("9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507","d87e8d9d43758ce67a8052cb2334b99cc24f9b0437ee44815f360be0b22d835a","9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f","acd55c44b8b0d66d66defed85ca18082c092f048d3621da827fce593305c11fd","96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974") OR Processes.process_hash IN ("2915b3f8b703eb744fc54c81f4a9c67f","362498c3e71eeaa066a67e4a3f981d1c","38de5b216c33833af710e88f7f64fc98","0f03f72a92aef6d63eb74e73f8ac201d","aac3165ece2959f39ff98334618d10d9") by Processes.dest Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let TalosSHA256 = dynamic(["9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507","d87e8d9d43758ce67a8052cb2334b99cc24f9b0437ee44815f360be0b22d835a","9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f","acd55c44b8b0d66d66defed85ca18082c092f048d3621da827fce593305c11fd","96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974"]);
let TalosMD5 = dynamic(["2915b3f8b703eb744fc54c81f4a9c67f","362498c3e71eeaa066a67e4a3f981d1c","38de5b216c33833af710e88f7f64fc98","0f03f72a92aef6d63eb74e73f8ac201d","aac3165ece2959f39ff98334618d10d9"]);
let ExecHits = DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 in (TalosSHA256) or MD5 in (TalosMD5) or InitiatingProcessSHA256 in (TalosSHA256) or InitiatingProcessMD5 in (TalosMD5)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, MD5, ProcessCommandLine, InitiatingProcessFileName, Source="ProcessExec";
let FileHits = DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in (TalosSHA256) or MD5 in (TalosMD5)
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, MD5, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, Source="FileWrite";
let ImageHits = DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where SHA256 in (TalosSHA256) or MD5 in (TalosMD5)
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, MD5, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, Source="ImageLoad";
union ExecHits, FileHits, ImageHits
| order by Timestamp desc
```

### [LLM] BadIIS traffic-hijacking: IIS 503 surge + anomalous external redirect ratio per site/hour

`UC_111_4` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as Total, count(eval('Web.status'==503)) as Status503, count(eval(in('Web.status',301,302,303,307,308))) as RedirectCount, dc(Web.dest) as DistinctOriginHosts, values(Web.uri_path) as SampleURIs, values(Web.dest) as Destinations from datamodel=Web.Web where Web.http_method="GET" by Web.src Web.site _time span=1h | `drop_dm_object_name(Web)` | eval PctErr503 = round((Status503*100.0)/Total, 2), PctRedirect = round((RedirectCount*100.0)/Total, 2) | where (Status503 >= 50 AND PctErr503 >= 20) OR (RedirectCount >= 100 AND PctRedirect >= 40) | sort - _time
```

### Article-specific behavioural hunt — The art of being ungovernable

`UC_111_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — The art of being ungovernable ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("vid001.exe","tunmirror.exe","secoh-qad.exe","kmsss.exe","d4aa3e7010220ad1b458fac17039c274_63_exe.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("vid001.exe","tunmirror.exe","secoh-qad.exe","kmsss.exe","d4aa3e7010220ad1b458fac17039c274_63_exe.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — The art of being ungovernable
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("vid001.exe", "tunmirror.exe", "secoh-qad.exe", "kmsss.exe", "d4aa3e7010220ad1b458fac17039c274_63_exe.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("vid001.exe", "tunmirror.exe", "secoh-qad.exe", "kmsss.exe", "d4aa3e7010220ad1b458fac17039c274_63_exe.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`, `d87e8d9d43758ce67a8052cb2334b99cc24f9b0437ee44815f360be0b22d835a`, `9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f`, `acd55c44b8b0d66d66defed85ca18082c092f048d3621da827fce593305c11fd`, `96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974`, `2915b3f8b703eb744fc54c81f4a9c67f`, `362498c3e71eeaa066a67e4a3f981d1c`, `38de5b216c33833af710e88f7f64fc98` _(+2 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
