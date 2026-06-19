# [CRIT] [GHSA / CRITICAL] GHSA-r253-r9jw-qg44: Crawl4AI: Unauthenticated RCE via Chromium launch-argument injection in browser_config.extra_args

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-r253-r9jw-qg44

## Threat Profile

Crawl4AI: Unauthenticated RCE via Chromium launch-argument injection in browser_config.extra_args

### Summary

The Docker API server accepted a request-supplied `browser_config.extra_args`, which flowed into Chromium's launch arguments. An attacker could inject Chromium switches that replace a child-process launch command (`--utility-cmd-prefix`, `--renderer-cmd-prefix`, `--gpu-launcher`, `--browser-subprocess-path`) together with `--no-zygote`, causing Chromium to fork/exec an attacker-control…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1659** — Content Injection
- **T1190** — Exploit Public-Facing Application
- **T1203** — Exploitation for Client Execution
- **T1059** — Command and Scripting Interpreter
- **T1595.002** — Vulnerability Scanning

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crawl4AI /crawl POST body carrying Chromium launcher-switch injection

`UC_7_0` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.http_user_agent) as user_agent values(Web.url) as url values(Web.http_method) as method from datamodel=Web where Web.http_method=POST (Web.url="*/crawl" OR Web.url="*/crawl/stream" OR Web.url="*/crawl/job" OR Web.uri_path="*/crawl*") (Web.url="*--no-zygote*" OR Web.url="*--utility-cmd-prefix*" OR Web.url="*--renderer-cmd-prefix*" OR Web.url="*--gpu-launcher*" OR Web.url="*--browser-subprocess-path*" OR Web.url="*extra_args*" OR Web.url="*browser_config*") by Web.src Web.dest Web.url Web.http_method Web.http_user_agent Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LaunchSwitches = dynamic(["--utility-cmd-prefix","--renderer-cmd-prefix","--gpu-launcher","--browser-subprocess-path","--no-zygote"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess")
| where LocalPort in (11235, 8000, 8080)
| where InitiatingProcessFileName has_any ("python.exe","python3","uvicorn","gunicorn","crawl4ai")
   or InitiatingProcessCommandLine has_any ("crawl4ai","uvicorn","crawl4ai.server")
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Chromium spawned with --no-zygote and subprocess-launcher flag (Crawl4AI RCE chain)

`UC_7_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmdline values(Processes.parent_process_name) as parent_name from datamodel=Endpoint.Processes where (Processes.process_name="chrome*" OR Processes.process_name="chromium*" OR Processes.process_name="chrome" OR Processes.process_name="chromium" OR Processes.process_name="headless_shell*") Processes.process="*--no-zygote*" (Processes.process="*--utility-cmd-prefix*" OR Processes.process="*--renderer-cmd-prefix*" OR Processes.process="*--gpu-launcher*" OR Processes.process="*--browser-subprocess-path*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName matches regex @"(?i)^(chrome|chromium|headless_shell|chrome\.exe|chromium\.exe)$"
   or InitiatingProcessFileName matches regex @"(?i)^(chrome|chromium|headless_shell|chrome\.exe|chromium\.exe)$"
| where ProcessCommandLine has "--no-zygote"
| where ProcessCommandLine has_any ("--utility-cmd-prefix","--renderer-cmd-prefix","--gpu-launcher","--browser-subprocess-path")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath, SHA256
| order by Timestamp desc
```

### Crawl4AI /crawl endpoint hit from unexpected container or external scanner

`UC_7_2` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as user_agents dc(Web.url) as url_count from datamodel=Web where Web.http_method=POST (Web.url="*/crawl" OR Web.url="*/crawl/stream" OR Web.url="*/crawl/job") by Web.src Web.dest Web.status
| `drop_dm_object_name(Web)`
| where NOT (cidrmatch("10.0.0.0/8",src) OR cidrmatch("172.16.0.0/12",src) OR cidrmatch("192.168.0.0/16",src))
   OR (cidrmatch("10.0.0.0/8",src) AND user_agents IN ("masscan*","nuclei*","zgrab*","python-requests*","curl*"))
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let Crawl4AIHosts = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has_any ("crawl4ai","uvicorn crawl4ai","crawl4ai.server")
    | summarize by DeviceId, DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess")
| where LocalPort in (11235, 8000, 8080, 80, 443)
| join kind=inner Crawl4AIHosts on DeviceId
| where RemoteIPType == "Public"
   or (RemoteIPType == "Private" and InitiatingProcessCommandLine has_any ("masscan","nuclei","zgrab","nmap","python-requests"))
| summarize Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Ports=make_set(LocalPort) by DeviceName, RemoteIP, RemoteIPType, InitiatingProcessFileName
| where Hits >= 1
| order by FirstSeen desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
