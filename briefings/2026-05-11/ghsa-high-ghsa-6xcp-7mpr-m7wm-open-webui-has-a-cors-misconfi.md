# [HIGH] [GHSA / HIGH] GHSA-6xcp-7mpr-m7wm: Open WebUI has a CORS misconfiguration and session validation issue

**Source:** GitHub Security Advisories
**Published:** 2026-05-11
**Article:** https://github.com/advisories/GHSA-6xcp-7mpr-m7wm

## Threat Profile

Open WebUI has a CORS misconfiguration and session validation issue

# GitHub Security Lab (GHSL) Vulnerability Report, open-webui: `GHSL-2024-174`, `GHSL-2024-175`

The [GitHub Security Lab](https://securitylab.github.com) team has identified potential security vulnerabilities in [open-webui](https://github.com/open-webui/open-webui).

We are committed to working with you to help resolve these issues. In this report you will find everything you need to effectively coordinate a resolution of the…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1212** — Exploitation for Credential Access
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1068** — Exploitation for Privilege Escalation
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1611** — Escape to Host

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable Open WebUI (< 0.3.33) inventory — GHSA-6xcp-7mpr-m7wm CORS+session RCE chain

`UC_90_2` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Vulnerabilities.signature) as signatures, latest(_time) as last_seen from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.signature="GHSA-6xcp-7mpr-m7wm" OR Vulnerabilities.signature="GHSL-2024-174" OR Vulnerabilities.signature="GHSL-2024-175" OR (Vulnerabilities.signature="open-webui" Vulnerabilities.cvss>=7.0)) by Vulnerabilities.dest Vulnerabilities.severity `drop_dm_object_name(Vulnerabilities)` | append [ search index=* sourcetype IN ("os:pip:freeze","pip:freeze","docker:inventory","kubernetes:pod") ("open-webui" OR "open_webui" OR "ghcr.io/open-webui") | rex "open[-_]webui[=\s:@v]+(?<version>\d+\.\d+\.\d+)" | where isnotnull(version) AND (version<"0.3.33") | stats latest(_time) as last_seen, values(version) as versions by host ] | sort -last_seen
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareName has "open-webui" or SoftwareName has "open_webui" or SoftwareVendor has "open-webui"
| extend Parts = split(SoftwareVersion, ".")
| extend Major = toint(Parts[0]), Minor = toint(Parts[1]), Patch = toint(Parts[2])
// fixed in 0.3.33 — flag anything strictly below
| where Major == 0 and (Minor < 3 or (Minor == 3 and Patch < 33))
| project Timestamp, DeviceId, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, IsInternetFacing, PublicIP, MachineGroup) by DeviceId
) on DeviceId
| project Timestamp, DeviceName, SoftwareName, SoftwareVersion, IsInternetFacing, PublicIP, MachineGroup
| order by IsInternetFacing desc, DeviceName asc
```

### [LLM] Open WebUI CORS RCE chain — POST /api/v1/functions/create followed by /toggle from same client

`UC_90_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats summariesonly=true count, values(Web.url) as urls, values(Web.http_method) as methods, values(Web.http_referrer) as referers, values(Web.user_agent) as uas, min(_time) as first_seen, max(_time) as last_seen from datamodel=Web.Web where Web.http_method=POST AND (Web.url="*/api/v1/functions/create*" OR Web.url="*/api/v1/functions/id/*/toggle*") by Web.src Web.dest Web.user `drop_dm_object_name(Web)` | eval seen_create=if(mvfind(urls,"functions/create")>=0,1,0), seen_toggle=if(mvfind(urls,"/toggle")>=0,1,0) | where seen_create=1 AND seen_toggle=1 AND (last_seen - first_seen) <= 120 | eval foreign_origin=if(isnull(referers) OR NOT match(mvjoin(referers," "),"(?i)^https?://(localhost|127\.|"+dest+")"),1,0) | table first_seen, last_seen, src, dest, user, urls, referers, uas, foreign_origin
```

**Defender KQL:**
```kql
// Defender XDR has no native inspection of internal Open WebUI HTTP traffic.
// Falls back to the network-egress side: detect the python/uvicorn backend
// reaching the /api/v1/functions/create endpoint from a host that just had
// inbound HTTP. Most useful when the Open WebUI host has Defender for Linux installed.
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python","python3","python3.11","python3.12","uvicorn","gunicorn")
| where InitiatingProcessCommandLine has_any ("open_webui","open-webui","backend.main","apps.webui.main")
| where ActionType in ("InboundConnectionAccepted","ListeningConnectionCreated")
| where LocalPort in (3000, 8080)
| summarize InboundCount = count(), RemoteIPs = make_set(RemoteIP, 50), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, DeviceId, LocalPort, InitiatingProcessFileName, bin(Timestamp, 5m)
| where InboundCount >= 2
| order by LastSeen desc
```

### [LLM] Open WebUI python worker spawning shell/recon commands — post-exploitation of GHSA-6xcp-7mpr-m7wm filter RCE

`UC_90_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats summariesonly=true count, values(Processes.process) as cmdlines, values(Processes.process_name) as child_names, min(_time) as first_seen from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3","python3.10","python3.11","python3.12","uvicorn","gunicorn") AND (Processes.parent_process="*open_webui*" OR Processes.parent_process="*open-webui*" OR Processes.parent_process="*apps.webui.main*" OR Processes.parent_process="*backend.main*") AND Processes.process_name IN ("whoami","id","uname","hostname","sh","bash","dash","ash","cat","curl","wget","nc","ncat","python","perl","ruby") by host Processes.user Processes.parent_process Processes.process_name `drop_dm_object_name(Processes)` | append [ | tstats summariesonly=true count, values(Filesystem.file_path) as files from datamodel=Endpoint.Filesystem where Filesystem.action=created AND Filesystem.process_name IN ("python","python3","uvicorn","gunicorn") AND Filesystem.file_path="/tmp/*" by host Filesystem.user Filesystem.file_name `drop_dm_object_name(Filesystem)` ] | sort -first_seen
```

**Defender KQL:**
```kql
let _proc = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("python","python3","python3.10","python3.11","python3.12","uvicorn","gunicorn")
    | where InitiatingProcessCommandLine has_any ("open_webui","open-webui","backend.main","apps.webui.main")
    | where FileName in~ ("whoami","id","uname","hostname","sh","bash","dash","ash","cat","curl","wget","nc","ncat","perl","ruby")
    | project Timestamp, DeviceName, DeviceId, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, Signal="child_process";
let _file = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType == "FileCreated"
    | where FolderPath startswith "/tmp/"
    | where InitiatingProcessFileName in~ ("python","python3","python3.10","python3.11","python3.12","uvicorn","gunicorn")
    | where InitiatingProcessCommandLine has_any ("open_webui","open-webui","backend.main","apps.webui.main")
    | project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, Signal="tmp_file_create";
union _proc, _file
| order by Timestamp desc
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Article-specific behavioural hunt — [GHSA / HIGH] GHSA-6xcp-7mpr-m7wm: Open WebUI has a CORS misconfiguration and se

`UC_90_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / HIGH] GHSA-6xcp-7mpr-m7wm: Open WebUI has a CORS misconfiguration and se ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/whoami.txt*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / HIGH] GHSA-6xcp-7mpr-m7wm: Open WebUI has a CORS misconfiguration and se
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/whoami.txt"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 5 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
