# [CRIT] The who, where, and how of APT attacks in Q2 2025–Q3 2025

**Source:** ESET WeLiveSecurity
**Published:** 2025-11-07
**Article:** https://www.welivesecurity.com/en/videos/who-where-how-apt-attacks-q2-2025-q3-2025/

## Threat Profile

The who, where, and how of APT attacks in Q2 2025–Q3 2025 
Video
The who, where, and how of APT attacks in Q2 2025–Q3 2025 ESET Chief Security Evangelist Tony Anscombe highlights some of the key findings from the latest issue of the ESET APT Activity Report
Editor 
07 Nov 2025 
Yesterday, the ESET research team released the latest issue of its APT Activity Report  that summarizes and contextualizes the cyber-operations of some of the world's most notorious state-aligned hacking groups from April…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-8088`
- **Domain (defanged):** `esetsmart.com`
- **Domain (defanged):** `esetscanner.com`
- **Domain (defanged):** `esetremover.com`
- **SHA256:** `e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389`
- **SHA256:** `bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1203** — Exploitation for Client Execution
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1564.004** — Hide Artifacts: NTFS File Attributes
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1566.002** — Phishing: Spearphishing Link
- **T1583.001** — Acquire Infrastructure: Domains
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1204.002** — User Execution: Malicious File
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] CVE-2025-8088 WinRAR ADS path traversal — file written to Startup folder by WinRAR

`UC_586_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.process_name IN ("WinRAR.exe","Rar.exe","UnRAR.exe","WinRAR64.exe") OR Filesystem.parent_process_name IN ("WinRAR.exe","Rar.exe","UnRAR.exe","WinRAR64.exe")) (Filesystem.file_path="*\\Start Menu\\Programs\\Startup\\*" OR Filesystem.file_path="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*") by Filesystem.dest Filesystem.process_name Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName in~ ("WinRAR.exe","Rar.exe","UnRAR.exe","WinRAR64.exe","WinRAR32.exe")
   or InitiatingProcessParentFileName in~ ("WinRAR.exe","Rar.exe","UnRAR.exe")
| where FolderPath has @"\Start Menu\Programs\Startup\"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256, MD5
| order by Timestamp desc
```

### [LLM] InedibleOchotense lure — host contacts spoofed ESET domains (esetsmart/esetscanner/esetremover.com)

`UC_586_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where DNS.query IN ("esetsmart.com","esetscanner.com","esetremover.com","*.esetsmart.com","*.esetscanner.com","*.esetremover.com") by DNS.query DNS.src | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=t count from datamodel=Web.Web where Web.dest IN ("esetsmart.com","esetscanner.com","esetremover.com") OR Web.url IN ("*esetsmart.com*","*esetscanner.com*","*esetremover.com*") by Web.src Web.dest Web.url Web.user Web.http_user_agent | `drop_dm_object_name(Web)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _bad_domains = dynamic(["esetsmart.com","esetscanner.com","esetremover.com"]);
union isfuzzy=true
    (DeviceNetworkEvents
     | where Timestamp > ago(30d)
     | where RemoteUrl has_any (_bad_domains)
     | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType),
    (DeviceEvents
     | where Timestamp > ago(30d)
     | where ActionType == "DnsQueryResponse"
     | extend Q = tolower(tostring(parse_json(AdditionalFields).query))
     | where Q has_any (_bad_domains)
     | project Timestamp, DeviceName, InitiatingProcessFileName, Q),
    (DeviceFileEvents
     | where Timestamp > ago(30d)
     | where ActionType == "FileCreated"
     | where FileOriginUrl has_any (_bad_domains) or FileOriginReferrerUrl has_any (_bad_domains)
     | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath, SHA256, FileOriginUrl)
| order by Timestamp desc
```

### [LLM] ESET-confirmed APT IOC SHA256 sweep across file / process / image-load telemetry

`UC_586_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_hash IN ("e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389","bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047") by Processes.dest Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)` | append [| tstats summariesonly=t count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389","bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.user | `drop_dm_object_name(Filesystem)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _bad_sha256 = dynamic([
  "e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389",
  "bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047"
]);
union isfuzzy=true
  (DeviceFileEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (_bad_sha256)
   | project Timestamp, Source="DeviceFileEvents", DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath, SHA256, FileOriginUrl),
  (DeviceProcessEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (_bad_sha256)
   | project Timestamp, Source="DeviceProcessEvents", DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName),
  (DeviceImageLoadEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (_bad_sha256)
   | project Timestamp, Source="DeviceImageLoadEvents", DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (EmailAttachmentInfo
   | where Timestamp > ago(30d)
   | where SHA256 in (_bad_sha256)
   | project Timestamp, Source="EmailAttachmentInfo", FileName, SHA256, SenderFromAddress, RecipientEmailAddress, MalwareFilterVerdict)
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-8088`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `esetsmart.com`, `esetscanner.com`, `esetremover.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389`, `bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 6 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
