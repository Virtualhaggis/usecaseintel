# [CRIT] [GHSA / CRITICAL] GHSA-f25v-x6vr-962g: Pheditor: Authentication Bypass in Forced Password-Change Flow via Unverified Current Password

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-f25v-x6vr-962g

## Threat Profile

Pheditor: Authentication Bypass in Forced Password-Change Flow via Unverified Current Password

## Summary

The forced password-change flow, triggered when the stored password is still the default (`admin`), does not verify that the password submitted by the client actually matches the current password. Any non-empty value in `pheditor_password` is enough to reach the password-change form, and submitting `pheditor_new_password` / `pheditor_confirm_password` in the same request is enough to set a…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1556** — Modify Authentication Process
- **T1505.003** — Server Software Component: Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Pheditor forced-password-change auth bypass — POST to pheditor.php

`UC_96_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method=POST (Web.url="*pheditor.php*" OR Web.uri_path="*pheditor.php") by Web.src Web.dest Web.url Web.uri_path Web.status Web.http_method Web.http_user_agent
| `drop_dm_object_name(Web)`
| sort - count
```

### Web-server / PHP process writes new .php file under webroot (post-Pheditor webshell drop)

`UC_96_2` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_path="*.php" (Filesystem.file_path="*\\inetpub\\wwwroot\\*" OR Filesystem.file_path="*\\htdocs\\*" OR Filesystem.file_path="*/var/www/*" OR Filesystem.file_path="*/www/*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.user Filesystem.action
| `drop_dm_object_name(Filesystem)`
| sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".php"
| where InitiatingProcessFileName in~ ("php-cgi.exe","php.exe","w3wp.exe","httpd.exe","apache2","nginx","php-fpm")
| where FolderPath has_any (@"\inetpub\", @"\htdocs\", "/var/www/", "/www/")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-f25v-x6vr-962g: Pheditor: Authentication Bypass in Forced

`UC_96_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-f25v-x6vr-962g: Pheditor: Authentication Bypass in Forced ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/j.txt*" OR Filesystem.file_path="*/dev/null*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-f25v-x6vr-962g: Pheditor: Authentication Bypass in Forced
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/j.txt", "/dev/null"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
