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
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service
- **T1090** — Proxy
- **T1018** — Remote System Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crawl4AI /screenshot or /pdf path traversal via output_path parameter

`UC_10_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.uri_path IN ("/screenshot","/pdf") AND (Web.url="*output_path*..*" OR Web.url="*output_path=%2e%2e*" OR Web.url="*output_path=%2F*" OR Web.url="*output_path=/etc/*" OR Web.url="*output_path=/root/*" OR Web.url="*output_path=/home/*/.ssh*" OR Web.url="*output_path=/var/spool/cron*") by Web.src Web.dest Web.uri_path Web.url Web.http_method Web.status | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("python","python3","uvicorn","gunicorn","chromium","chrome","headless_shell")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath !startswith "/tmp/crawl4ai-outputs"
      and FolderPath !startswith "/var/lib/crawl4ai"
      and FolderPath !startswith "/tmp/"
| where FolderPath has_any ("/etc/","/root/","/var/spool/cron","/.ssh/","/usr/local/bin/","/etc/cron.d/","/home/appuser/")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Crawl4AI process reaches cloud instance metadata service (SSRF success signal)

`UC_10_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.dest IN ("169.254.169.254","100.100.100.200","fd00:ec2::254") OR All_Traffic.dest_url IN ("http://metadata.google.internal/*","http://metadata.azure.com/*")) AND All_Traffic.app IN ("python","python3","uvicorn","gunicorn","chromium","chrome","headless_shell") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.user | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("169.254.169.254","100.100.100.200")
     or RemoteUrl has_any ("metadata.google.internal","metadata.azure.com","169.254.169.254")
| where InitiatingProcessFileName has_any ("python","python3","uvicorn","gunicorn","chrome","chromium","headless_shell")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Crawl4AI Python server spawns OS shell child (suspected /execute_js abuse)

`UC_10_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3","uvicorn","gunicorn","python.exe") AND Processes.process_name IN ("bash","sh","dash","zsh","cmd.exe","powershell.exe","pwsh.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | search NOT process IN ("*pip install*","*setup.py*","*--version*","*pre-commit*") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("python","python3","uvicorn","gunicorn")
| where FileName in~ ("bash","sh","dash","zsh","cmd.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine !has "pip install"
      and ProcessCommandLine !has "setup.py"
      and ProcessCommandLine !has "--version"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Crawl4AI webhook callback POSTs to external destination (SSRF / data exfil via /webhook)

`UC_10_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method IN ("POST","PUT") AND (Web.user_agent="python-requests/*" OR Web.user_agent="httpx/*" OR Web.user_agent="aiohttp/*" OR Web.user_agent="*crawl4ai*") by Web.src Web.dest Web.url Web.user_agent Web.http_method Web.status | `drop_dm_object_name(Web)` | search NOT (dest="10.*" OR dest="192.168.*" OR dest="172.16.*" OR dest="172.17.*" OR dest="172.18.*" OR dest="172.19.*" OR dest="172.2*.*" OR dest="172.30.*" OR dest="172.31.*" OR dest="127.*") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("python","python3","uvicorn","gunicorn")
| where RemoteIPType == "Public"
| where RemotePort in (80,443,8000,8080,8443)
| where InitiatingProcessCommandLine has_any ("crawl4ai","webhook","server")
     or InitiatingProcessParentFileName in~ ("dockerd","containerd-shim","containerd-shim-runc-v2")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Crawl4AI /md /llm /crawl /webhook receives XSS or script-injection payload

`UC_10_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.uri_path IN ("/md","/llm","/crawl","/crawl/stream","/webhook","/llm_extraction","/markdown_extraction") AND (Web.url="*<script*" OR Web.url="*%3Cscript*" OR Web.url="*onerror=*" OR Web.url="*onclick=*" OR Web.url="*onload=*" OR Web.url="*javascript:*" OR Web.url="*%3Csvg*" OR Web.url="*%3Ciframe*") by Web.src Web.dest Web.uri_path Web.url Web.http_method Web.status | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("python","python3","uvicorn","gunicorn","nginx","haproxy")
| where RemoteUrl has_any ("/md","/llm","/crawl","/webhook","/llm_extraction","/markdown_extraction")
| where RemoteUrl has_any ("<script","%3Cscript","onerror=","onclick=","onload=","javascript:","%3Csvg","%3Ciframe")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Crawl4AI /crawl receives internal/metadata/file:// URL (SSRF probe)

`UC_10_6` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.uri_path IN ("/crawl","/crawl/stream","/md","/llm") AND (Web.url="*url=http*://10.*" OR Web.url="*url=http*://192.168*" OR Web.url="*url=http*://172.1[6-9]*" OR Web.url="*url=http*://172.2*.*" OR Web.url="*url=http*://172.3[0-1]*" OR Web.url="*url=http*://127.*" OR Web.url="*url=http*://localhost*" OR Web.url="*url=file:*" OR Web.url="*url=gopher:*" OR Web.url="*169.254.169.254*" OR Web.url="*metadata.google.internal*" OR Web.url="*metadata.azure.com*" OR Web.url="*%3A%3Affff%3A*" OR Web.url="*[::ffff:*") by Web.src Web.dest Web.uri_path Web.url Web.http_method Web.status | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("/crawl","/crawl/stream","/md","/llm")
| where RemoteUrl has_any ("url=http://10.","url=http://192.168.","url=http://172.16.","url=http://172.17.","url=http://172.18.","url=http://172.19.","url=http://172.20.","url=http://172.31.","url=http://127.","url=http://localhost","url=file:","169.254.169.254","metadata.google.internal","metadata.azure.com","[::ffff:","%5B%3A%3Affff%3A")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
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

Severity classified as **CRIT** based on: 7 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
