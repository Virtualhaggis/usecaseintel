# [HIGH] Alert: peacenotwar module sabotages npm developers in the node-ipc package to protest the invasion of Ukraine

**Source:** Snyk
**Published:** 2022-03-16
**Article:** https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
March 16, 2022
0 mins read On March 15, 2022, users of the popular Vue.js frontend JavaScript framework started experiencing what can only be described as a supply chain attack impacting the npm ecosystem. This was the result of the nested dependencies node-ipc and peacenotwar being sabotaged as an act of protest by the maintainer of the node-ipc package.
This security incident involves destructive acts of corrupting files on disk by one maintainer…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-23812`
- **Domain (defanged):** `api.ipgeolocation.io`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1614** — System Location Discovery
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1485** — Data Destruction
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### node-ipc/peacenotwar geolocation beacon to api.ipgeolocation.io from Node runtime

`UC_2465_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*ipgeolocation.io*" Web.url="*ae511e1627824a968aaaa758a5309154*" by Web.src, Web.dest, Web.url, Web.http_user_agent, Web.app | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "node.exe"
| where RemoteUrl has "ipgeolocation.io"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFolderPath, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Mass file overwrite by Node runtime (node-ipc heart-emoji data destruction)

`UC_2465_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Filesystem.file_path) as distinct_files min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=modified by Filesystem.dest, _time span=5m | `drop_dm_object_name(Filesystem)` | where distinct_files > 200 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileModified"
| where InitiatingProcessFileName =~ "node.exe"
| where InitiatingProcessAccountName !endswith "$"
| summarize FilesModified = count(), DistinctFolders = dcount(FolderPath), SampleFiles = make_set(FolderPath, 10), StartTime = min(Timestamp), EndTime = max(Timestamp) by DeviceName, InitiatingProcessId, InitiatingProcessCommandLine, bin(Timestamp, 5m)
| where FilesModified > 100
| order by FilesModified desc
```

### Vulnerable node-ipc / peacenotwar package present (CVE-2022-23812)

`UC_2465_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities where Vulnerabilities.cve="CVE-2022-23812" by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity | `drop_dm_object_name(Vulnerabilities)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(30d)
| where CveId == "CVE-2022-23812"
   or (SoftwareName has "node-ipc" and SoftwareVersion in ("10.1.1","10.1.2","9.2.2"))
| project DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
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

### Article-specific behavioural hunt — Alert: peacenotwar module sabotages npm developers in the node-ipc package to pr

`UC_2465_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Alert: peacenotwar module sabotages npm developers in the node-ipc package to pr ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("vue.js","geospec.js","node.js","react.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("vue.js","geospec.js","node.js","react.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Alert: peacenotwar module sabotages npm developers in the node-ipc package to pr
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("vue.js", "geospec.js", "node.js", "react.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("vue.js", "geospec.js", "node.js", "react.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-23812`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `api.ipgeolocation.io`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 7 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
