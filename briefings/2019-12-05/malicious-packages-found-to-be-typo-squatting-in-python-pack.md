# [HIGH] Malicious packages found to be typo-squatting in Python Package Index

**Source:** Snyk
**Published:** 2019-12-05
**Article:** https://snyk.io/blog/malicious-packages-found-to-be-typo-squatting-in-pypi/

## Threat Profile

Snyk Blog In this article
Written by Hayley Denbraver 
December 5, 2019
0 mins read Two malicious packages were removed from the Python Package Index ( PyPI ) this week. These packages, jeIlyfish (a misspelling of the package jellyfish only noticeable when using certain fonts) and python3-dateutil (impersonating the popular dateutil package), were taking advantage of something called “typo-squatting”. Typo-squatting occurs when a malicious package is uploaded with a name similar to a common pack…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1041** — Exfiltration Over C2 Channel
- **T1571** — Non-Standard Port
- **T1552.004** — Unsecured Credentials: Private Keys

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Typosquatted PyPI package install: jeIlyfish / python3-dateutil

`UC_3422_0` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*jeilyfish*" OR Filesystem.file_path="*python3_dateutil*" OR Filesystem.file_path="*python3-dateutil*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any ("site-packages","dist-packages")
| where FolderPath contains "jeilyfish" or FolderPath contains "python3_dateutil" or FolderPath contains "python3-dateutil"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Exfil to jeIlyfish C2 68.183.212.246:32258

`UC_3422_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="68.183.212.246" by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "68.183.212.246"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Python interpreter reading SSH/GPG private keys (jeIlyfish key theft)

`UC_3422_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.ssh/*" OR Filesystem.file_path="*\\.ssh\\*" OR Filesystem.file_path="*.gnupg*" OR Filesystem.file_name IN ("id_rsa","id_dsa","id_ecdsa","id_ed25519","secring.gpg")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | search process_name IN ("python","python3","python.exe","pythonw.exe") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("python.exe","pythonw.exe","python","python3")
| where (FolderPath contains @"\.ssh\" or FolderPath contains "/.ssh/" or FolderPath contains ".gnupg" or FileName in~ ("id_rsa","id_dsa","id_ecdsa","id_ed25519","secring.gpg"))
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FolderPath, FileName
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
