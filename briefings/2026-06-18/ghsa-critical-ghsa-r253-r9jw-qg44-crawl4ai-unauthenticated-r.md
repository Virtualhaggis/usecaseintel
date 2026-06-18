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

- **T1203** — Exploitation for Client Execution
- **T1059** — Command and Scripting Interpreter
- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Unix Shell
- **T1059.006** — Python
- **T1659** — Content Injection

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Chromium launched with command-execution launcher switches (Crawl4AI GHSA-r253-r9jw-qg44)

`UC_0_0` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("chrome", "chrome.exe", "chromium", "chromium-browser") AND (Processes.process="*--utility-cmd-prefix*" OR Processes.process="*--renderer-cmd-prefix*" OR Processes.process="*--gpu-launcher*" OR Processes.process="*--browser-subprocess-path*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("chrome", "chrome.exe", "chromium", "chromium-browser", "chromium.exe")
| where ProcessCommandLine has_any (
    "--utility-cmd-prefix",
    "--renderer-cmd-prefix",
    "--gpu-launcher",
    "--browser-subprocess-path"
  )
| extend NoZygote = ProcessCommandLine has "--no-zygote"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, NoZygote,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Chromium browser parent of shell or network utility child (Crawl4AI extra_args post-exploit)

`UC_0_1` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("chrome", "chrome.exe", "chromium", "chromium-browser", "chromium.exe") AND Processes.process_name IN ("sh", "bash", "dash", "zsh", "ash", "busybox", "python", "python3", "perl", "ruby", "curl", "wget", "nc", "ncat", "socat", "nslookup") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("chrome", "chrome.exe", "chromium", "chromium-browser", "chromium.exe")
| where FileName in~ ("sh", "bash", "dash", "zsh", "ash", "busybox",
                      "python", "python3", "perl", "ruby",
                      "curl", "wget", "nc", "ncat", "socat", "nslookup",
                      "cmd.exe", "powershell.exe")
| where InitiatingProcessCommandLine !has "chromedriver"
  and InitiatingProcessCommandLine !has "chrome_crashpad_handler"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Crawl4AI /crawl* endpoint hit with Chromium launcher-switch payload in request body

`UC_0_2` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.http_method="POST" AND (Web.url="*/crawl" OR Web.url="*/crawl/stream" OR Web.url="*/crawl/job" OR Web.uri_path IN ("/crawl","/crawl/stream","/crawl/job")) by Web.src Web.dest Web.url Web.http_user_agent Web.status Web.uri_query | `drop_dm_object_name(Web)` | search uri_query="*--utility-cmd-prefix*" OR uri_query="*--renderer-cmd-prefix*" OR uri_query="*--gpu-launcher*" OR uri_query="*--browser-subprocess-path*" OR uri_query="*extra_args*" | convert ctime(firstTime) ctime(lastTime)
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
