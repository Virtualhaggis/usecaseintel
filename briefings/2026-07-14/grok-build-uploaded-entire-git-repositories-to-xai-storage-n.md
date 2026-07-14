# [HIGH] Grok Build Uploaded Entire Git Repositories to xAI Storage, Not Just Files It Read

**Source:** The Hacker News
**Published:** 2026-07-14
**Article:** https://thehackernews.com/2026/07/grok-build-uploads-entire-git.html

## Threat Profile

Grok Build Uploads Entire Git Repositories to xAI Storage, Not Just Files It Reads 
 Swati Khandelwal  Jul 14, 2026 Artificial Intelligence / Data Privacy 
xAI's Grok Build coding CLI was uploading entire Git repositories, full commit history and all, to a Google Cloud Storage bucket run by xAI, not just the files a coding task needed.
A researcher publishing as cereblab , testing version 0.2.93 , captured one of those uploads, cloned the git bundle out of the intercepted request, and pulled b…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1567.002** — Exfiltration to Cloud Storage
- **T1567** — Exfiltration Over Web Service
- **T1119** — Automated Collection
- **T1005** — Data from Local System
- **T1074.001** — Local Data Staging
- **T1552.001** — Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Grok Build CLI uploads full repo/git-bundle to xAI storage channel (grok-code-session-traces)

`UC_15_0` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, sum(Web.bytes_out) as bytes_out, values(Web.http_method) as http_method, values(Web.url) as url from datamodel=Web where (Web.url="*grok-code-session-traces*" OR Web.url="*cli-chat-proxy.grok.com/v1/storage*" OR Web.dest="cli-chat-proxy.grok.com") by Web.src, Web.dest, Web.user | `drop_dm_object_name(Web)` | sort - bytes_out
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl has_any ("cli-chat-proxy.grok.com", "grok-code-session-traces"))
    or (InitiatingProcessFileName =~ "grok" and RemoteUrl has "storage.googleapis.com")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Connections=count(), SampleUrl=any(RemoteUrl)
          by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl
| order by LastSeen desc
```

### Grok Build CLI presence & execution (0.2.93/0.2.99) — exposed-endpoint discovery

`UC_15_1` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Processes.process) as process, values(Processes.process_path) as process_path, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_path="*/.grok/bin/grok*" OR Processes.process_name IN ("grok","grok-macos-aarch64","grok-macos-x86_64","grok-linux-x86_64","grok-linux-aarch64")) by Processes.dest, Processes.user, Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FolderPath endswith "/.grok/bin/grok")
    or FileName in~ ("grok", "grok-macos-aarch64", "grok-macos-x86_64", "grok-linux-x86_64", "grok-linux-aarch64")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Executions=count(), Version=any(ProcessVersionInfoProductVersion), SampleCmd=any(ProcessCommandLine)
          by DeviceName, AccountName, FileName, FolderPath
| order by LastSeen desc
```

### Grok Build CLI local staging of session/codebase archive (metadata.json → gs://grok-code-session-traces)

`UC_15_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Filesystem.file_path) as file_path, values(Filesystem.action) as action, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="metadata.json" OR Filesystem.file_path="*grok-code-session-traces*" OR (Filesystem.file_path="*/.grok/*" AND (Filesystem.file_name="*.bundle" OR Filesystem.file_path="*session_state*"))) by Filesystem.dest, Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "grok" or InitiatingProcessFolderPath endswith "/.grok/bin/grok"
| where FileName =~ "metadata.json"
    or FileName endswith ".bundle"
    or FolderPath has_any ("session_state", "grok-code-session-traces")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, ActionType, FileName, FolderPath, FileSize
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
