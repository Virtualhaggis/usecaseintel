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


One account was used as an outbound relay and staging server during the attack, while another was used for data stor…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-65617`
- **CVE:** `CVE-2026-65921`
- **CVE:** `CVE-2026-65922`
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
- **T1102** — Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable self-hosted JFrog Artifactory (CVE-2026-65617 cluster, pre-7.161.15)

`UC_1_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-65617","CVE-2026-65921","CVE-2026-65922","CVE-2026-65923","CVE-2026-65924","CVE-2026-65925","CVE-2026-66014","CVE-2026-66015","CVE-2026-66018") by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.cve Vulnerabilities.severity
| `drop_dm_object_name(Vulnerabilities)`
| `security_content_ctime(firstTime)`
| sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-65617","CVE-2026-65921","CVE-2026-65922","CVE-2026-65923","CVE-2026-65924","CVE-2026-65925","CVE-2026-66014","CVE-2026-66015","CVE-2026-66018")
| where SoftwareVendor has "jfrog" or SoftwareName has "artifactory"
| summarize Cves = make_set(CveId), MaxSeverity = max(VulnerabilitySeverityLevel), arg_max(Timestamp, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate) by DeviceName, DeviceId
| order by DeviceName asc
```

### Artifactory package-service (java) spawning a shell/interpreter — CVE-2026-65617 RCE

`UC_1_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.Processes.parent_process_name="java" AND (Endpoint.Processes.process_name IN ("sh","bash","dash","python","python3","perl","curl","wget","nc","ncat")) by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.parent_process Endpoint.Processes.process_name Endpoint.Processes.process
| `drop_dm_object_name(Endpoint.Processes)`
| where like(parent_process,"%artifactory%") OR user="artifactory"
| `security_content_ctime(firstTime)`
| sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "java" and InitiatingProcessCommandLine has "artifactory"
| where FileName in~ ("sh","bash","dash","python","python3","perl","curl","wget","nc","ncat")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Artifactory service egress to non-registry internet (sandbox escape / web-service relay)

`UC_1_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where Network_Traffic.All_Traffic.process_name="java" Network_Traffic.All_Traffic.direction="outbound" NOT (Network_Traffic.All_Traffic.dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8")) by Network_Traffic.All_Traffic.src Network_Traffic.All_Traffic.dest Network_Traffic.All_Traffic.dest_port Network_Traffic.All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| sort - firstTime
```

**Defender KQL:**
```kql
let Registries = dynamic(["npmjs.org","pypi.org","pythonhosted.org","maven.org","maven.apache.org","nuget.org","rubygems.org","crates.io","packagist.org","conda.anaconda.org","proxy.golang.org","gopkg.in","dl.google.com","registry.terraform.io","docker.io","ghcr.io","github.com","githubusercontent.com","jfrog.com","jfrog.io","debian.org","ubuntu.com","fedoraproject.org"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "java" and InitiatingProcessCommandLine has "artifactory"
| where RemoteIPType == "Public"
| where isnotempty(RemoteUrl)
| where not(RemoteUrl has_any (Registries))
| summarize FirstSeen = min(Timestamp), Conns = count(), Ports = make_set(RemotePort, 10) by DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
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
  - CVE(s): `CVE-2026-65617`, `CVE-2026-65921`, `CVE-2026-65922`, `CVE-2026-65923`, `CVE-2026-65924`, `CVE-2026-65925`, `CVE-2026-66014`, `CVE-2026-66015` _(+1 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
