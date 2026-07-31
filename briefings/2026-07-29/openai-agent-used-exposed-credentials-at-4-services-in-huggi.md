# [CRIT] OpenAI agent used exposed credentials at 4 services in Hugging Face breach

**Source:** BleepingComputer
**Published:** 2026-07-29
**Article:** https://www.bleepingcomputer.com/news/security/openai-agent-used-exposed-credentials-at-4-services-in-hugging-face-breach/

## Threat Profile

OpenAI agent used exposed credentials at 4 services in Hugging Face breach 
By Lawrence Abrams 
July 29, 2026
12:04 PM
0 
In a new update, OpenAI says its AI models also used publicly exposed credentials to compromise accounts on four third-party services during the recent attack on Hugging Face, expanding the scope of the four-day security incident to other organizations.
One account was used as an outbound relay and staging server during the attack, while another was used for data storage. The…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-65617`
- **CVE:** `CVE-2026-65921`
- **CVE:** `CVE-2026-65923`
- **CVE:** `CVE-2026-65924`
- **CVE:** `CVE-2026-65925`
- **CVE:** `CVE-2026-66014`
- **CVE:** `CVE-2026-66015`
- **CVE:** `CVE-2026-66018`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1190** — Exploit Public-Facing Application
- **T1219** — Remote Access Software
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### JFrog Artifactory zero-day chain (CVE-2026-65617 et al.) — vulnerable version present

`UC_46_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-65617","CVE-2026-65921","CVE-2026-65922","CVE-2026-65923","CVE-2026-65924","CVE-2026-65925","CVE-2026-66014","CVE-2026-66015","CVE-2026-66018") OR (Vulnerabilities.signature="*artifactory*") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.signature Vulnerabilities.severity
| `drop_dm_object_name(Vulnerabilities)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-65617","CVE-2026-65921","CVE-2026-65922","CVE-2026-65923","CVE-2026-65924","CVE-2026-65925","CVE-2026-66014","CVE-2026-66015","CVE-2026-66018")
   or (SoftwareVendor has "jfrog" and SoftwareName has "artifactory")
| project DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, RecommendedSecurityUpdateId
| order by VulnerabilitySeverityLevel desc, DeviceName asc
```

### JFrog Artifactory service process spawning a shell or downloader (RCE exploitation)

`UC_46_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process="*artifactory*" OR Processes.parent_process="*jfrog*" OR Processes.parent_process="*/opt/jfrog/*") AND Processes.process_name IN ("sh","bash","dash","busybox","curl","wget","python","python3","perl","nc","ncat") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFolderPath has_any ("/jfrog/","/artifactory/") or InitiatingProcessCommandLine has_any ("artifactory","jfrog")
| where FileName in~ ("sh","bash","dash","busybox","curl","wget","python","python3","perl","nc","ncat")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```

### Artifactory host egress to public internet (package-registry sandbox escape)

`UC_46_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="*artifactory*" AND All_Traffic.direction="outbound" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| where NOT (cidrmatch("10.0.0.0/8", dest) OR cidrmatch("172.16.0.0/12", dest) OR cidrmatch("192.168.0.0/16", dest) OR cidrmatch("127.0.0.0/8", dest))
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFolderPath has_any ("/jfrog/","/artifactory/") or InitiatingProcessCommandLine has_any ("artifactory","jfrog")
| where RemoteIPType == "Public"
| where not(RemoteUrl has_any ("npmjs.org","pypi.org","pythonhosted.org","repo1.maven.org","repo.maven.apache.org","registry.npmjs.org","nuget.org","docker.io","registry-1.docker.io","ghcr.io","crates.io","rubygems.org"))
| summarize ConnCount=count(), FirstSeen=min(Timestamp), Ports=make_set(RemotePort,10) by DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by FirstSeen desc
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

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-65617`, `CVE-2026-65921`, `CVE-2026-65923`, `CVE-2026-65924`, `CVE-2026-65925`, `CVE-2026-66014`, `CVE-2026-66015`, `CVE-2026-66018`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
