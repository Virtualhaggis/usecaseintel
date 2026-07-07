# [CRIT] [GHSA / CRITICAL] GHSA-q6xx-5vr8-p898: Nezha vulnerable to cross-tenant terminal/file-manager session hijack via WebSocket stream UUID without ownership check

**Source:** GitHub Security Advisories
**Published:** 2026-06-26
**Article:** https://github.com/advisories/GHSA-q6xx-5vr8-p898

## Threat Profile

Nezha vulnerable to cross-tenant terminal/file-manager session hijack via WebSocket stream UUID without ownership check

### Summary

In nezha **v1.14.13–v1.14.14** and **v2.0.0–v2.0.9**, the WebSocket endpoints `GET /ws/terminal/:id` and `GET /ws/file/:id` authenticate the caller only by the presence of a valid stream UUID, with no ownership check tying that UUID to the user who created the stream. Any authenticated dashboard user (including a `RoleMember`) who learns a live stream UUID can att…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1563** — Remote Service Session Hijacking
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Nezha WebSocket terminal/file-manager session hijack — one stream UUID attached from 2+ source IPs

`UC_129_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t dc(Web.src) as distinct_clients values(Web.src) as clients values(Web.user) as users count as hits min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/ws/terminal/*" OR Web.url="*/ws/file/*") by Web.url
| `drop_dm_object_name(Web)`
| rex field=url "/ws/(?<endpoint>terminal|file)/(?<stream_id>[0-9a-fA-F\-]{16,})"
| where isnotnull(stream_id) AND distinct_clients>1
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

### Nezha harvested stream-UUID replay — one client attaching to many distinct terminal/file WebSocket UUIDs

`UC_129_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t dc(Web.url) as distinct_streams values(Web.url) as streams count as hits min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/ws/terminal/*" OR Web.url="*/ws/file/*") by Web.src Web.user _time span=1h
| `drop_dm_object_name(Web)`
| where distinct_streams>5
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - distinct_streams
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


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
