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
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1203** — Exploitation for Client Execution
- **T1059** — Command and Scripting Interpreter
- **T1566.002** — Spearphishing Link
- **T1583.001** — Acquire Infrastructure: Domains
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### WinRAR CVE-2025-8088 path traversal — payload dropped to user Startup folder

`UC_805_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("winrar.exe","rar.exe","unrar.exe","WinRAR.exe") AND Filesystem.file_path="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| where NOT match(file_name, "(?i)\\.lnk$")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("winrar.exe","rar.exe","unrar.exe","unrar64.exe")
| where FolderPath has @"\Microsoft\Windows\Start Menu\Programs\Startup\"
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA256, InitiatingProcessFolderPath
| order by Timestamp desc
```

### ESET-impersonating typosquat domain contact (InedibleOchotense / Kalambur delivery)

`UC_805_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.answer) as resolved_ips values(DNS.src) as sources from datamodel=Network_Resolution.DNS where DNS.query IN ("esetsmart.com","esetscanner.com","esetremover.com","*.esetsmart.com","*.esetscanner.com","*.esetremover.com") by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let TyposquatDomains = dynamic(["esetsmart.com","esetscanner.com","esetremover.com"]);
DeviceNetworkEvents
| where Timestamp > ago(60d)
| where isnotempty(RemoteUrl)
| extend lowerUrl = tolower(RemoteUrl)
| where lowerUrl has_any (TyposquatDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### Execution / write of ESET APT Q2-Q3 2025 known-bad SHA256 payload

`UC_805_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_hash IN ("e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389","bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047") by Processes.dest Processes.user Processes.process_name Processes.process_hash
| `drop_dm_object_name(Processes)`
| append
  [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as writer from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389","bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash
  | `drop_dm_object_name(Filesystem)`]
| `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let BadHashes = dynamic(["e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389","bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047"]);
union isfuzzy=true
  (DeviceProcessEvents
    | where Timestamp > ago(90d)
    | where SHA256 in (BadHashes) or InitiatingProcessSHA256 in (BadHashes)
    | extend Source="ProcessExec"
    | project Timestamp, Source, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName),
  (DeviceFileEvents
    | where Timestamp > ago(90d)
    | where SHA256 in (BadHashes)
    | extend Source="FileWrite"
    | project Timestamp, Source, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName),
  (DeviceImageLoadEvents
    | where Timestamp > ago(90d)
    | where SHA256 in (BadHashes)
    | extend Source="ImageLoad"
    | project Timestamp, Source, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName),
  (EmailAttachmentInfo
    | where Timestamp > ago(90d)
    | where SHA256 in (BadHashes)
    | extend Source="EmailAttachment"
    | project Timestamp, Source, DeviceName="", AccountName=RecipientEmailAddress, FileName, FolderPath="", SHA256, ProcessCommandLine=SenderFromAddress, InitiatingProcessFileName=FileType)
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 6 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
