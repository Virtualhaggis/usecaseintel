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

- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1190** — Exploit Public-Facing Application
- **T1203** — Exploitation for Client Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Chromium subprocess-launcher switch + --no-zygote co-occurrence (Crawl4AI extra_args RCE)

`UC_39_0` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*--no-zygote*" AND (Processes.process="*--utility-cmd-prefix*" OR Processes.process="*--renderer-cmd-prefix*" OR Processes.process="*--gpu-launcher*" OR Processes.process="*--browser-subprocess-path*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine contains "--no-zygote"
| where ProcessCommandLine contains "--utility-cmd-prefix"
    or ProcessCommandLine contains "--renderer-cmd-prefix"
    or ProcessCommandLine contains "--gpu-launcher"
    or ProcessCommandLine contains "--browser-subprocess-path"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Headless Chromium spawning shell/interpreter child (Crawl4AI injected-command exec)

`UC_39_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("chrome","chromium","chromium-browser","headless_shell","chrome-headless-shell")) AND (Processes.process_name IN ("sh","bash","dash","zsh","curl","wget","python","python3","nc","ncat","perl","ruby","node")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("chrome","chromium","chromium-browser","headless_shell","chrome-headless-shell","chrome.exe","chromium.exe","headless_shell.exe")
| where FileName in~ ("sh","bash","dash","zsh","curl","wget","python","python3","nc","ncat","netcat","perl","ruby","node")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
