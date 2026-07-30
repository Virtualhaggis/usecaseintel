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
- **T1211** — Exploitation for Defense Evasion
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1102** — Web Service
- **T1583.006** — Acquire Infrastructure: Web Services
- **T1567** — Exfiltration Over Web Service
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unpatched JFrog Artifactory exposed to OpenAI-disclosed RCE/SSRF zero-days (7.161.15)

`UC_5_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-65617","CVE-2026-65921","CVE-2026-65923","CVE-2026-65924","CVE-2026-65925","CVE-2026-66014","CVE-2026-66015","CVE-2026-66018") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.category | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstTime) ctime(lastTime) | sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where SoftwareVendor has "jfrog" or SoftwareName has "artifactory"
| where CveId in ("CVE-2026-65617","CVE-2026-65921","CVE-2026-65923","CVE-2026-65924","CVE-2026-65925","CVE-2026-66014","CVE-2026-66015","CVE-2026-66018")
| summarize CVEs = make_set(CveId), MaxSeverity = max(VulnerabilitySeverityLevel), arg_max(Timestamp, SoftwareVersion, RecommendedSecurityUpdate) by DeviceName, SoftwareVendor, SoftwareName
| order by MaxSeverity desc
```

### Artifactory package-service RCE: java/artifactory process spawning shell or network tool

`UC_5_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("java","java.exe","artifactory") OR Processes.parent_process="*artifactory*") AND Processes.process_name IN ("sh","bash","dash","curl","wget","python","python3","nc","ncat","busybox","powershell.exe","cmd.exe","certutil.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java","java.exe","artifactory") or InitiatingProcessCommandLine has "artifactory"
| where FileName in~ ("sh","bash","dash","curl","wget","python","python3","nc","ncat","busybox","powershell.exe","cmd.exe","certutil.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Automated attack-infrastructure assembly via pastebin / request-capture / screenshot services

`UC_5_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app!="chrome" All_Traffic.app!="msedge" All_Traffic.app!="firefox" (All_Traffic.dest="*pastebin.com" OR All_Traffic.dest="*hastebin.com" OR All_Traffic.dest="*rentry.co" OR All_Traffic.dest="*webhook.site" OR All_Traffic.dest="*requestbin.com" OR All_Traffic.dest="*pipedream.net" OR All_Traffic.dest="*requestcatcher.com" OR All_Traffic.dest="*oast.fun" OR All_Traffic.dest="*oast.pro" OR All_Traffic.dest="*oast.live" OR All_Traffic.dest="*oastify.com" OR All_Traffic.dest="*ngrok.io" OR All_Traffic.dest="*ngrok-free.app" OR All_Traffic.dest="*interact.sh" OR All_Traffic.dest="*thum.io" OR All_Traffic.dest="*urlbox.io" OR All_Traffic.dest="*screenshotone.com" OR All_Traffic.dest="*urlscan.io") by All_Traffic.src All_Traffic.dest All_Traffic.app All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let InfraDomains = dynamic(["pastebin.com","hastebin.com","rentry.co","dpaste.org","paste.ee","controlc.com","0bin.net","termbin.com","webhook.site","requestbin.com","pipedream.net","requestcatcher.com","beeceptor.com","oast.fun","oast.pro","oast.live","oast.site","oast.online","oastify.com","ngrok.io","ngrok-free.app","interact.sh","canarytokens.com","screenshotmachine.com","thum.io","urlbox.io","screenshotone.com","urlscan.io"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public" and isnotempty(RemoteUrl)
| where RemoteUrl has_any (InfraDomains)
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe","brave.exe","opera.exe")
| summarize FirstSeen = min(Timestamp), Conns = count(), Urls = make_set(RemoteUrl, 20) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by FirstSeen desc
```

### Automated sign-in with exposed credentials (non-interactive, scripting user-agent)

`UC_5_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication.Authentication where Authentication.action="success" (Authentication.user_agent="*python-requests*" OR Authentication.user_agent="*python-urllib*" OR Authentication.user_agent="*curl/*" OR Authentication.user_agent="*Go-http-client*" OR Authentication.user_agent="*aiohttp*" OR Authentication.user_agent="*okhttp*" OR Authentication.user_agent="*Boto3*" OR Authentication.user_agent="*node-fetch*") by Authentication.user Authentication.src Authentication.app Authentication.user_agent | `drop_dm_object_name(Authentication)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where IsInteractive == false
| where UserAgent has_any ("python-requests","python-urllib","curl/","Go-http-client","aiohttp","okhttp","libwww-perl","Boto3","node-fetch","axios")
| summarize SignIns = count(), Apps = make_set(Application, 10), Countries = make_set(Country, 10), IPs = make_set(IPAddress, 10) by AccountUpn, UserAgent
| order by SignIns desc
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

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
