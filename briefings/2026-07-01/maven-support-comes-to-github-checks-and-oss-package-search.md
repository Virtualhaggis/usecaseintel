# [HIGH] Maven Support Comes to GitHub Checks and OSS Package Search

**Source:** StepSecurity
**Published:** 2026-07-01
**Article:** https://www.stepsecurity.io/blog/maven-support-comes-to-github-checks-and-oss-package-search

## Threat Profile

Back to Blog Product Maven Support Comes to GitHub Checks and OSS Package Search StepSecurity now supports Maven in GitHub Checks and OSS Package Search, blocking compromised and freshly published Java dependencies in your pull requests. Sai Likhith View LinkedIn June 25, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
For most of the last two years, the loudest supply chain attacks lived in npm and PyPI. Java teams watched fr…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `103.127.243.82`
- **Domain (defanged):** `fasterxml.org`
- **Domain (defanged):** `m.fasterxml.org`
- **SHA256:** `8bce95ebfb895537fec243e069d7193980361de9d916339906b11a14ffded94f`
- **SHA256:** `702161756dfd150ad3c214fbf97ce98fdc960ea7b3970b5300702ed8c953cafd`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1036.005** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Jackson Maven typosquat C2 — beacon to fasterxml.org / 103.127.243.82

`UC_144_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*fasterxml.org*" by DNS.src DNS.dest DNS.query 
| `drop_dm_object_name("DNS")` 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "fasterxml.org" or RemoteIP == "103.127.243.82"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Java/Spring drops & runs svchosts.exe (svchost masquerade) — Jackson typosquat implant

`UC_144_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="svchosts.exe" OR (Processes.parent_process_name IN ("java.exe","javaw.exe") AND Processes.process_name="svchosts.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "svchosts.exe"
   or SHA256 in ("8bce95ebfb895537fec243e069d7193980361de9d916339906b11a14ffded94f","702161756dfd150ad3c214fbf97ce98fdc960ea7b3970b5300702ed8c953cafd")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Jackson typosquat Cobalt Strike implant hash sighting (Win + macOS/Linux)

`UC_144_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("8bce95ebfb895537fec243e069d7193980361de9d916339906b11a14ffded94f","702161756dfd150ad3c214fbf97ce98fdc960ea7b3970b5300702ed8c953cafd") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash 
| `drop_dm_object_name("Filesystem")` 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in ("8bce95ebfb895537fec243e069d7193980361de9d916339906b11a14ffded94f","702161756dfd150ad3c214fbf97ce98fdc960ea7b3970b5300702ed8c953cafd")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `103.127.243.82`, `fasterxml.org`, `m.fasterxml.org`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `8bce95ebfb895537fec243e069d7193980361de9d916339906b11a14ffded94f`, `702161756dfd150ad3c214fbf97ce98fdc960ea7b3970b5300702ed8c953cafd`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
