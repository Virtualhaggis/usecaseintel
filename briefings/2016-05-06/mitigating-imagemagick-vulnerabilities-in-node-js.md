# [HIGH] Mitigating ImageMagick vulnerabilities in Node.js

**Source:** Snyk
**Published:** 2016-05-06
**Article:** https://snyk.io/blog/safe-imagemagick-for-node/

## Threat Profile

Snyk Blog In this article
Written by Guy Podjarny 
May 6, 2016
0 mins read Multiple severe and trivially exploited vulnerabilities in ImageMagick were disclosed earlier this week, and are known to be exploited in the wild. As there is no official fix yet, we created a package called imagemagick-safe which disables the vulnerable features, protecting against the known exploits.
TL; DR ImageMagick is an extremely popular library and binary for manipulating images. Amongst other uses, it’s often us…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ImageMagick binary spawning shell/recon process (ImageTragick CVE-2016-3714 delegate RCE)

`UC_3676_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("convert","mogrify","identify","composite","montage","conjure","stream","import","display","animate","magick","gm")) AND (Processes.process_name IN ("sh","bash","dash","curl","wget","nc","ncat","python","python3","perl","ruby","whoami","id","uname","hostname")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("convert","mogrify","identify","composite","montage","conjure","stream","import","display","animate","magick","gm")
| where FileName in~ ("sh","bash","dash","curl","wget","nc","ncat","python","python3","perl","ruby","whoami","id","uname","hostname")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### ImageMagick binary making outbound network connection (ImageTragick URL/HTTPS coder SSRF)

`UC_3676_2` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app IN ("convert","mogrify","identify","composite","montage","conjure","stream","import","magick","gm")) AND All_Traffic.dest_category!="internal" by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("convert","mogrify","identify","composite","montage","conjure","stream","import","magick","gm")
| where RemoteIPType == "Public"
| summarize FirstSeen=min(Timestamp), Conns=count(), Ports=make_set(RemotePort,10), Urls=make_set(RemoteUrl,10) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP
| order by FirstSeen desc
```

### Article-specific behavioural hunt — Mitigating ImageMagick vulnerabilities in Node.js

`UC_3676_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Mitigating ImageMagick vulnerabilities in Node.js ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Mitigating ImageMagick vulnerabilities in Node.js
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
