# [CRIT] Protestware is trending in open source: 4 different types and their impact

**Source:** Snyk
**Published:** 2022-03-22
**Article:** https://snyk.io/blog/protestware-open-source-types-impact/

## Threat Profile

Snyk Blog In this article
Written by Benji Catabi-Kalman 
March 22, 2022
0 mins read A few days ago, Snyk reported on a new type of threat vector in the open source community: protestware. The advisory was about a transitive vulnerability — peacenotwar — in node-ipc that impacted the supply chain of a great deal of developers. Snyk uses various intel threat feeds and algorithms to monitor chatter on potential threats to open source, and we believe this may just be the tip of a protestware iceber…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-23812`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1491.001** — Defacement: Internal Defacement
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1614** — System Location Discovery
- **T1485** — Data Destruction

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### peacenotwar protestware desktop file drop (WITH-LOVE-FROM-AMERICA.txt)

`UC_2299_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="WITH-LOVE-FROM-AMERICA.txt" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_id Filesystem.user
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "WITH-LOVE-FROM-AMERICA.txt"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### node-ipc/peacenotwar geo-locate check via ipgeolocation.io from Node runtime

`UC_2299_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*ipgeolocation.io" by DNS.src DNS.query DNS.dest
| `drop_dm_object_name(DNS)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "ipgeolocation.io"
| where InitiatingProcessFileName in~ ("node.exe","node")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### node-ipc destructive payload artifact (dao/ssl-geospec.js) on disk

`UC_2299_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="ssl-geospec.js" AND Filesystem.file_path="*\\node-ipc\\dao\\*" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.user
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "ssl-geospec.js"
| where FolderPath has @"\node-ipc\dao"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-23812`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
