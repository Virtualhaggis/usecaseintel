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
- **T1059** — Command and Scripting Interpreter
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090** — Proxy
- **T1102** — Web Service
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable self-managed JFrog Artifactory (OpenAI-disclosed zero-days, pre-7.161.15)

`UC_4_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-65617","CVE-2026-65921","CVE-2026-65922","CVE-2026-65923","CVE-2026-65924","CVE-2026-65925","CVE-2026-66014","CVE-2026-66015","CVE-2026-66018")
| project DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
```

### JFrog Artifactory service process spawning a shell or download LOLBIN (RCE)

`UC_4_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("java","java.exe","javaw.exe")) AND (Processes.parent_process="*artifactory*" OR Processes.parent_process="*jfrog*") AND (Processes.process_name IN ("sh","bash","dash","cmd.exe","powershell.exe","pwsh","curl","curl.exe","wget","python","python3","perl","nc","ncat")) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("java","java.exe","javaw.exe")
| where InitiatingProcessFolderPath has_any ("artifactory","jfrog")
| where FileName in~ ("sh","bash","dash","cmd.exe","powershell.exe","pwsh","curl","curl.exe","wget","python","python3","perl","nc","ncat")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Isolated Artifactory package-proxy host reaching non-registry public internet

`UC_4_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process="*artifactory*" OR All_Traffic.process="*jfrog*") AND All_Traffic.direction="outbound" NOT (All_Traffic.dest="*npmjs.org" OR All_Traffic.dest="*pypi.org" OR All_Traffic.dest="*pythonhosted.org" OR All_Traffic.dest="*maven.org" OR All_Traffic.dest="*gradle.org" OR All_Traffic.dest="*nuget.org" OR All_Traffic.dest="*rubygems.org" OR All_Traffic.dest="*docker.io" OR All_Traffic.dest="*ghcr.io" OR All_Traffic.dest="*crates.io" OR All_Traffic.dest="*jfrog.io" OR All_Traffic.dest="*golang.org" OR All_Traffic.dest="*packagist.org") by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.process | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFolderPath has_any ("artifactory","jfrog") or InitiatingProcessFileName in~ ("java","java.exe","javaw.exe")
| where RemoteIPType == "Public"
| where isempty(RemoteUrl) or not(RemoteUrl has_any ("npmjs.org","pypi.org","pythonhosted.org","maven.org","maven.apache.org","gradle.org","nuget.org","rubygems.org","docker.io","ghcr.io","gcr.io","registry.k8s.io","crates.io","golang.org","conda.anaconda.org","packagist.org","jfrog.io","jcenter.bintray.com"))
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Conns=count(), Ports=make_set(RemotePort, 20) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemoteUrl
| order by FirstSeen desc
```

### Server/tool egress to pastebin, request-capture (OAST) and screenshot staging services

`UC_4_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("*pastebin.com","*ghostbin.com","*rentry.co","*hastebin.com","*dpaste.com","*paste.ee","*controlc.com","*termbin.com","*webhook.site","*requestbin.com","*requestbin.net","*pipedream.net","*hookbin.com","*beeceptor.com","*oast.fun","*oast.pro","*oast.site","*oast.live","*oast.online","*interact.sh","*burpcollaborator.net","*canarytokens.com","*hcti.io","*urlbox.io","*microlink.io")) NOT (All_Traffic.process IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe")) by All_Traffic.src All_Traffic.process All_Traffic.dest All_Traffic.dest_ip | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("pastebin.com","ghostbin.com","rentry.co","hastebin.com","dpaste.com","paste.ee","controlc.com","termbin.com","webhook.site","requestbin.com","requestbin.net","pipedream.net","hookbin.com","beeceptor.com","oast.fun","oast.pro","oast.site","oast.live","oast.online","interact.sh","burpcollaborator.net","canarytokens.com","hcti.io","urlbox.io","microlink.io")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
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

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
