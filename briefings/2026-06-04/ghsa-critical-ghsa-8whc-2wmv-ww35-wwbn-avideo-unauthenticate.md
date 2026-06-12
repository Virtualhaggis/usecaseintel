# [CRIT] [GHSA / CRITICAL] GHSA-8whc-2wmv-ww35: WWBN AVideo: Unauthenticated Stored DOM Cross-Site Scripting via Per-Client Metadata Broadcast in YPTSocket Plugin

**Source:** GitHub Security Advisories
**Published:** 2026-06-04
**Article:** https://github.com/advisories/GHSA-8whc-2wmv-ww35

## Threat Profile

WWBN AVideo: Unauthenticated Stored DOM Cross-Site Scripting via Per-Client Metadata Broadcast in YPTSocket Plugin

# Unauthenticated Stored DOM XSS via `page_title` Broadcast in AVideo YPTSocket Plugin

## Summary

A stored DOM Cross-Site Scripting vulnerability (CWE-79) in the AVideo YPTSocket plugin lets any unauthenticated remote attacker execute arbitrary JavaScript in the authenticated origin of every administrator currently viewing a page that renders the YPTSocket online-users debug pane…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AVideo YPTSocket plugin XSS injection via webSocketSelfURI/page_title query strings

`UC_119_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.src) as src_ip values(Web.http_user_agent) as ua from datamodel=Web.Web where Web.url="*/plugin/YPTSocket/*" (Web.url="*webSocketSelfURI=*" OR Web.url="*page_title=*") (Web.url="*%3Cimg*" OR Web.url="*%3Cscript*" OR Web.url="*onerror%3D*" OR Web.url="*onload%3D*" OR Web.url="*%3Csvg*" OR Web.url="*javascript%3A*" OR Web.url="*String.fromCharCode*" OR Web.url="*%3Ciframe*") by Web.dest Web.src Web.http_method Web.http_user_agent Web.url Web.status _time | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "/plugin/YPTSocket/"
| where RemoteUrl has_any ("webSocketSelfURI=", "page_title=")
| where RemoteUrl has_any ("%3Cimg", "%3Cscript", "onerror%3D", "onload%3D", "%3Csvg", "javascript%3A", "String.fromCharCode", "%3Ciframe", "<img", "<script", "onerror=", "onload=")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
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

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-8whc-2wmv-ww35: WWBN AVideo: Unauthenticated Stored DOM C

`UC_119_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-8whc-2wmv-ww35: WWBN AVideo: Unauthenticated Stored DOM C ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("script.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("script.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-8whc-2wmv-ww35: WWBN AVideo: Unauthenticated Stored DOM C
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("script.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("script.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
