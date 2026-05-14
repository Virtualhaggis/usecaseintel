# [HIGH] ESET Research: Sandworm behind cyberattack on Poland’s power grid in late 2025

**Source:** ESET WeLiveSecurity
**Published:** 2026-01-23
**Article:** https://www.welivesecurity.com/en/eset-research/eset-research-sandworm-cyberattack-poland-power-grid-late-2025/

## Threat Profile

ESET Research: Sandworm behind cyberattack on Poland’s power grid in late 2025 
ESET Research
ESET Research: Sandworm behind cyberattack on Poland’s power grid in late 2025 The attack involved data-wiping malware that ESET researchers have now analyzed and named DynoWiper
ESET Research 
23 Jan 2026 
 •  
, 
2 min. read 
UPDATE (January 30 th , 2026): For a technical breakdown of the incident affecting a company in Poland’s energy sector, refer to this blogpost . 
In late 2025, Poland’s energy sy…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1485** — Data Destruction
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1021.002** — Remote Services: SMB/Windows Admin Shares
- **T1090.001** — Proxy: Internal Proxy
- **T1090.002** — Proxy: External Proxy
- **T1572** — Protocol Tunneling
- **T1027.009** — Obfuscated Files or Information: Embedded Payloads

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] DynoWiper deployment from shared inetpub\pub directory (Sandworm, Poland Dec 2025)

`UC_459_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_hash IN ("4ec3c90846af6b79ee1a5188eefa3fd21f6d4cf6","86596a5c5b05a8bfbd14876de7404702f7d0d61b","69ede7e341fd26fa0577692b601d80cb44778d93") OR (Processes.process_name IN ("schtask.exe","schtask2.exe") AND NOT Processes.process_path IN ("*\\Windows\\System32\\*","*\\Windows\\SysWOW64\\*")) OR (Processes.process_path="*\\inetpub\\pub\\*" AND Processes.process_name!="w3wp.exe")) by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("4ec3c90846af6b79ee1a5188eefa3fd21f6d4cf6","86596a5c5b05a8bfbd14876de7404702f7d0d61b","69ede7e341fd26fa0577692b601d80cb44778d93") OR (Filesystem.file_path="*\\inetpub\\pub\\*" AND Filesystem.file_name="*.exe") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` ]
```

**Defender KQL:**
```kql
let DynoWiperSHA1 = dynamic(["4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6","86596A5C5B05A8BFBD14876DE7404702F7D0D61B","69EDE7E341FD26FA0577692B601D80CB44778D93"]);
union isfuzzy=true
( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA1 in~ (DynoWiperSHA1)
       or InitiatingProcessSHA1 in~ (DynoWiperSHA1)
       or (FolderPath has @"\inetpub\pub\" and FileName endswith ".exe" and FileName !in~ ("w3wp.exe","appcmd.exe"))
       or (FileName in~ ("schtask.exe","schtask2.exe") and FolderPath !startswith @"C:\Windows\")
       or (FileName endswith "_update.exe" and FolderPath has @"\inetpub\")
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1,
              ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
),
( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA1 in~ (DynoWiperSHA1)
       or (FolderPath has @"\inetpub\pub\" and FileName endswith ".exe" and ActionType in ("FileCreated","FileRenamed","FileModified"))
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA1,
              ProcessCommandLine="(file_event)", InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
)
| order by Timestamp desc
```

### [LLM] rsocx SOCKS5 reverse proxy beacon to 31.172.71.5:8008 (Sandworm Poland C2)

`UC_459_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*31.172.71.5*" OR Processes.process="*-r 31.172.71.5:8008*" OR (Processes.process_path="*\\Downloads\\*" AND Processes.process_name="r.exe" AND Processes.process="*-r *:8008*")) by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="31.172.71.5" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.user | `drop_dm_object_name(All_Traffic)` ]
```

**Defender KQL:**
```kql
let SandwormProxyIP = "31.172.71.5";
let SandwormProxyPort = 8008;
union isfuzzy=true
( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has SandwormProxyIP
       or ProcessCommandLine has "31.172.71.5:8008"
       or (FileName =~ "r.exe" and FolderPath has @"\Downloads\" and ProcessCommandLine matches regex @"(?i)\s-r\s+\d{1,3}(\.\d{1,3}){3}:8008\b")
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
              SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP="", RemotePort=int(null)
),
( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP == SandwormProxyIP
       or (RemotePort == SandwormProxyPort and InitiatingProcessFolderPath has @"\Downloads\")
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              FileName=InitiatingProcessFileName, FolderPath=InitiatingProcessFolderPath,
              ProcessCommandLine=InitiatingProcessCommandLine, SHA1=InitiatingProcessSHA1,
              InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
)
| order by Timestamp desc
```

### [LLM] DynoWiper PDB-string + vagrant build artefact in loaded modules

`UC_459_3` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.exe" OR Filesystem.file_name="*.dll" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | join type=left file_path [ search index=sysmon EventCode=7 OR EventCode=11 ("vagrant\\Documents\\Visual Studio 2013\\Projects\\Source" OR "\\Source.pdb") | rename ImageLoaded as file_path | fields file_path Image CommandLine ] | where isnotnull(Image) OR like(file_path,"%inetpub\\pub\\%")
```

**Defender KQL:**
```kql
let SandwormPdbMarkers = dynamic([
    @"C:\Users\vagrant\Documents\Visual Studio 2013\Projects\Source\Release\Source.pdb",
    @"\vagrant\Documents\Visual Studio 2013\Projects\Source",
    @"\Source\Release\Source.pdb"
]);
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFolderPath has @"\inetpub\pub\"
   or FolderPath has @"\inetpub\pub\"
   or InitiatingProcessFolderPath has @"\Downloads\"
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where AdditionalFields has_any (SandwormPdbMarkers)
       or AdditionalFields has "vagrant"
    | project FileSHA1=SHA1, FileFolderPath=FolderPath, FileName_File=FileName, AddInfo=AdditionalFields
  ) on $left.SHA1 == $right.FileSHA1
| project Timestamp, DeviceName, FileName, FolderPath, SHA1,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          AdditionalFields, FileFolderPath, AddInfo
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
