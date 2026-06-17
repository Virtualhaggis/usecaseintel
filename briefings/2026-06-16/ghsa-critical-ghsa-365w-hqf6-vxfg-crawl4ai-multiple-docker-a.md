# [CRIT] [GHSA / CRITICAL] GHSA-365w-hqf6-vxfg: Crawl4AI: Multiple Docker API Vulnerabilities - File Write, SSRF, Auth Bypass, XSS, JS Execution

**Source:** GitHub Security Advisories
**Published:** 2026-06-16
**Article:** https://github.com/advisories/GHSA-365w-hqf6-vxfg

## Threat Profile

Crawl4AI: Multiple Docker API Vulnerabilities - File Write, SSRF, Auth Bypass, XSS, JS Execution

### Summary

Multiple security vulnerabilities in the Crawl4AI Docker API server affecting endpoints for crawling, markdown/LLM extraction, screenshots, PDFs, webhooks, monitoring, JavaScript execution, and configuration.

### Vulnerabilities

#### 1. Arbitrary File Write via /screenshot and /pdf (CWE-22, CVSS 9.1)

The `output_path` parameter accepts arbitrary filesystem paths with no validation. A…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1083** — File and Directory Discovery
- **T1552.005** — Cloud Instance Metadata API
- **T1090** — Proxy
- **T1078** — Valid Accounts
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1078.001** — Valid Accounts: Default Accounts
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1185** — Browser Session Hijacking
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crawl4AI /screenshot or /pdf path traversal via output_path parameter

`UC_10_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as method values(Web.src) as src from datamodel=Web where Web.url IN ("*/screenshot*","*/pdf*") (Web.url="*output_path*" OR Web.http_user_agent="*output_path*") by Web.dest Web.src Web.http_user_agent Web.url
| `drop_dm_object_name(Web)`
| where match(url, "output_path\=.*(\.\./|%2e%2e|%2f|\/etc\/|\/root\/|\/var\/|\/home\/|\.ssh|\.bash|crontab|cron\.d|authorized_keys)")
| eval target_path=mvfilter(match(url, "output_path"))
| table firstTime lastTime src dest http_user_agent url method
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3","python","uvicorn","gunicorn","nginx.exe","caddy.exe")
| where RemoteUrl has_any ("/screenshot","/pdf")
| where RemoteUrl has "output_path" and (RemoteUrl has_any ("../","..%2f","%2e%2e") or RemoteUrl matches regex @"output_path=(/etc/|/root/|/var/|/home/|/proc/|/usr/local/bin/)")
| join kind=inner (
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("python.exe","python3","python","uvicorn","gunicorn")
    | where FolderPath !startswith "/tmp/crawl4ai-outputs" and FolderPath !startswith @"C:\tmp\crawl4ai-outputs"
    | where ActionType in ("FileCreated","FileModified")
) on DeviceId
| where Timestamp1 between (Timestamp .. Timestamp + 5s)
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, FolderPath, FileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Crawl4AI SSRF via /crawl, /md, /llm targeting cloud metadata or RFC1918

`UC_10_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.src) as src from datamodel=Network_Traffic where (All_Traffic.app=python OR All_Traffic.process_name IN ("python","python3","uvicorn","gunicorn")) (All_Traffic.dest_ip="169.254.169.254" OR All_Traffic.dest_ip="169.254.170.2" OR All_Traffic.dest="metadata.google.internal" OR All_Traffic.dest_ip="100.100.100.200" OR cidrmatch("10.0.0.0/8",All_Traffic.dest_ip) OR cidrmatch("172.16.0.0/12",All_Traffic.dest_ip) OR cidrmatch("192.168.0.0/16",All_Traffic.dest_ip) OR cidrmatch("127.0.0.0/8",All_Traffic.dest_ip)) by All_Traffic.dest_ip All_Traffic.src All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
let MetadataTargets = dynamic(["169.254.169.254","169.254.170.2","100.100.100.200","fd00:ec2::254"]);
let MetadataHostnames = dynamic(["metadata.google.internal","metadata.azure.com","169.254.169.254"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3","python","uvicorn","gunicorn")
| where InitiatingProcessCommandLine has_any ("crawl4ai","crawl4ai.server","uvicorn")
| where RemoteIP in (MetadataTargets) or RemoteUrl has_any (MetadataHostnames) or RemoteIPType in ("Private","Loopback","LinkLocal")
| where RemoteIP !startswith "::1" or RemoteIP startswith "::ffff:169.254" or RemoteIP startswith "::ffff:10." or RemoteIP startswith "::ffff:127."
   or RemoteIPType in ("Private","Loopback","LinkLocal")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Crawl4AI /monitor endpoint accessed without authorization header

`UC_10_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.status) as status values(Web.http_user_agent) as ua values(Web.url) as url from datamodel=Web where Web.url IN ("*/monitor/*","*/monitor/actions/cleanup*","*/monitor/ws*") by Web.src Web.dest Web.http_method Web.url
| `drop_dm_object_name(Web)`
| where status>=200 AND status<300
| where NOT match(http_user_agent, "(?i)(corp-monitor|internal-healthcheck)")
| sort 0 -firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3","python","uvicorn","gunicorn")
| where RemoteUrl has "/monitor/" or RemoteUrl has "/monitor/actions/cleanup" or RemoteUrl has "/monitor/ws"
| where RemoteIPType == "Public"
| summarize Hits = count(), Urls = make_set(RemoteUrl), FirstSeen = min(Timestamp) by DeviceName, RemoteIP
| where Hits >= 1
| order by FirstSeen desc
```

### Crawl4AI /execute_js endpoint spawning shell or system process child

`UC_10_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python.exe","python3","python","uvicorn","gunicorn","node","node.exe","chrome.exe","chromium","chromium.exe") (Processes.process_name IN ("bash","sh","dash","zsh","cmd.exe","powershell.exe","pwsh.exe","wmic.exe")) by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.parent_process
| `drop_dm_object_name(Processes)`
| where match(parent_process, "(?i)(crawl4ai|execute_js|uvicorn)")
| sort 0 -firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3","python","uvicorn","gunicorn","node","node.exe","chrome.exe","chromium","chromium.exe","chrome","playwright")
| where InitiatingProcessCommandLine has_any ("crawl4ai","uvicorn","execute_js","playwright")
| where FileName in~ ("bash","sh","dash","zsh","ksh","cmd.exe","powershell.exe","pwsh.exe","wmic.exe","curl","wget","nc","ncat","socat","python3","perl")
| where FolderPath !startswith "/snap/" and FolderPath !contains "playwright"
| project Timestamp, DeviceName, AccountName, ParentImage = InitiatingProcessFolderPath, ParentCmd = InitiatingProcessCommandLine, ChildImage = FolderPath, ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Crawl4AI JWT auth using hardcoded default 'mysecret' or weak signing key

`UC_10_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name IN ("python.exe","python3","python","uvicorn","gunicorn","docker","docker.exe") (Processes.process="*crawl4ai*" OR Processes.process="*SECRET_KEY*" OR Processes.process="*JWT_SECRET*") by Processes.dest Processes.user Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| where match(cmd, "(?i)(SECRET_KEY=mysecret|JWT_SECRET=mysecret|SECRET_KEY=\"mysecret\"|SECRET_KEY=password|SECRET_KEY=changeme|SECRET_KEY=secret|SECRET_KEY=\"\"|JWT_SECRET=\"\")")
| sort 0 -firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("docker.exe","docker","dockerd","containerd","podman")
   or FileName in~ ("python.exe","python3","python","uvicorn","gunicorn")
| where ProcessCommandLine has "crawl4ai"
   or InitiatingProcessCommandLine has "crawl4ai"
| where ProcessCommandLine matches regex @"(?i)(SECRET_KEY|JWT_SECRET)\s*=\s*[\"']?(mysecret|password|changeme|secret|admin|test|123|\"\"|'')"
   or InitiatingProcessCommandLine matches regex @"(?i)(SECRET_KEY|JWT_SECRET)\s*=\s*[\"']?(mysecret|password|changeme|secret|admin|test|123)"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Crawl4AI XSS injection in URL parameter targeting monitor dashboard

`UC_10_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as method from datamodel=Web where Web.url IN ("*/crawl*","*/crawl/job*","*/md*","*/llm*","*/markdown_extraction*","*/llm_extraction*") by Web.src Web.dest Web.url Web.http_method
| `drop_dm_object_name(Web)`
| where match(url, "(?i)(%3Cscript|<script|javascript:|onerror%3D|onerror=|onload%3D|onload=|onclick%3D|onmouseover%3D|<img[^>]+src%3D|<svg[^>]+onload|document\.cookie|fetch\(|window\.location)")
| sort 0 -firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3","python","uvicorn","gunicorn")
| where RemoteUrl has_any ("/crawl","/crawl/job","/md","/llm","/markdown_extraction","/llm_extraction")
| where RemoteUrl matches regex @"(?i)(%3Cscript|<script|javascript:|onerror%3D|onerror=|onload%3D|onclick%3D|%3Csvg|document\.cookie|window\.location)"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Crawl4AI webhook callback to non-corp external destination

`UC_10_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count sum(All_Traffic.bytes_out) as bytes_out min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic where (All_Traffic.app=python OR All_Traffic.process_name IN ("python","python3","uvicorn","gunicorn")) All_Traffic.dest_port IN (80,443,8000,8080,8443) NOT (All_Traffic.dest IN ("*.corp.local","*.internal") OR cidrmatch("10.0.0.0/8",All_Traffic.dest_ip) OR cidrmatch("172.16.0.0/12",All_Traffic.dest_ip) OR cidrmatch("192.168.0.0/16",All_Traffic.dest_ip)) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| where bytes_out > 1024
| sort 0 -bytes_out
```

**Defender KQL:**
```kql
let CorpDomains = dynamic([".corp.local",".internal",".local"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3","python","uvicorn","gunicorn")
| where InitiatingProcessCommandLine has_any ("crawl4ai","uvicorn")
| where RemoteIPType == "Public"
| where RemotePort in (80,443,8000,8080,8443)
| where not (RemoteUrl has_any (CorpDomains))
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Hosts = make_set(DeviceName,5), Urls = make_set(RemoteUrl,10) by RemoteIP, RemotePort
| where Connections >= 1
| order by FirstSeen desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-365w-hqf6-vxfg: Crawl4AI: Multiple Docker API Vulnerabili

`UC_10_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-365w-hqf6-vxfg: Crawl4AI: Multiple Docker API Vulnerabili ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/crawl4ai-outputs*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-365w-hqf6-vxfg: Crawl4AI: Multiple Docker API Vulnerabili
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/crawl4ai-outputs"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
