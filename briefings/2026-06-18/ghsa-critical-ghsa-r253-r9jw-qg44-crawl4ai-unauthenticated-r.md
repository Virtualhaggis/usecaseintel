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

- **T1190** — Exploit Public-Facing Application
- **T1659** — Content Injection
- **T1203** — Exploitation for Client Execution
- **T1059** — Command and Scripting Interpreter
- **T1611** — Escape to Host

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crawl4AI /crawl endpoint POST with Chromium launcher-switch payload in body (GHSA-r253-r9jw-qg44)

`UC_17_0` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_user_agent) as ua values(Web.src) as src values(Web.dest) as dest from datamodel=Web where Web.http_method="POST" (Web.url="*/crawl*" OR Web.url="*/crawl/stream*" OR Web.url="*/crawl/job*") (Web.url="*extra_args*" OR Web.url="*--utility-cmd-prefix*" OR Web.url="*--renderer-cmd-prefix*" OR Web.url="*--gpu-launcher*" OR Web.url="*--browser-subprocess-path*" OR Web.url="*--no-zygote*") by Web.src Web.dest Web.url Web.http_user_agent
| `drop_dm_object_name(Web)`
| where firstTime > relative_time(now(),"-7d")
| sort 0 -firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (80, 8000, 8080, 11235, 443, 8443)
| where RemoteUrl has_any ("/crawl", "/crawl/stream", "/crawl/job")
| where InitiatingProcessCommandLine has_any ("--utility-cmd-prefix", "--renderer-cmd-prefix", "--gpu-launcher", "--browser-subprocess-path", "--no-zygote", "extra_args")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, LocalIP, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Chromium process invoked with --no-zygote AND subprocess-launcher override flag co-occurrence (Crawl4AI RCE)

`UC_17_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name IN ("chrome.exe","chromium","chrome","headless_shell","chromium-browser","chromium.exe") OR Processes.process="*chromium*" OR Processes.process="*chrome*") Processes.process="*--no-zygote*" (Processes.process="*--utility-cmd-prefix*" OR Processes.process="*--renderer-cmd-prefix*" OR Processes.process="*--gpu-launcher*" OR Processes.process="*--browser-subprocess-path*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| where firstTime > relative_time(now(),"-7d")
| sort 0 -firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("chrome.exe","chromium","chrome","headless_shell","chromium-browser","chromium.exe")
   or ProcessCommandLine has_any ("/chrome", "/chromium", "\\chrome.exe", "\\chromium.exe", "headless_shell")
| where ProcessCommandLine has "--no-zygote"
| where ProcessCommandLine has_any ("--utility-cmd-prefix", "--renderer-cmd-prefix", "--gpu-launcher", "--browser-subprocess-path")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Chromium subprocess override spawns non-Chromium child (Crawl4AI RCE post-exploitation)

`UC_17_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as child_cmd values(Processes.process_name) as child_name values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.parent_process="*--utility-cmd-prefix*" OR Processes.parent_process="*--renderer-cmd-prefix*" OR Processes.parent_process="*--gpu-launcher*" OR Processes.parent_process="*--browser-subprocess-path*") (Processes.parent_process_name IN ("chrome.exe","chromium","chrome","headless_shell","chromium-browser","chromium.exe") OR Processes.parent_process="*chromium*" OR Processes.parent_process="*chrome*") NOT (Processes.process_name IN ("chrome.exe","chromium","chrome","headless_shell","chromium-browser","chromium.exe","crashpad_handler","crashpad_handler.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.parent_process
| `drop_dm_object_name(Processes)`
| where firstTime > relative_time(now(),"-7d")
| sort 0 -firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessCommandLine has_any ("--utility-cmd-prefix", "--renderer-cmd-prefix", "--gpu-launcher", "--browser-subprocess-path")
| where InitiatingProcessFileName in~ ("chrome.exe","chromium","chrome","headless_shell","chromium-browser","chromium.exe")
   or InitiatingProcessCommandLine has_any ("/chrome", "/chromium", "\\chrome.exe", "\\chromium.exe", "headless_shell")
| where FileName !in~ ("chrome.exe","chromium","chrome","headless_shell","chromium-browser","chromium.exe","crashpad_handler","crashpad_handler.exe")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentFile = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildFile = FileName,
          ChildCmd = ProcessCommandLine,
          ChildSHA256 = SHA256
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
