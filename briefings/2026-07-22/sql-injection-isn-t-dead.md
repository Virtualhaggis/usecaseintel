# [HIGH] SQL injection isn't dead

**Source:** Aikido
**Published:** 2026-07-22
**Article:** https://www.aikido.dev/blog/sql-injection-isnt-dead

## Threat Profile

Blog News SQL injection isn't dead SQL injection isn't dead Written by Dania Durnas Published on: Jul 22, 2026 Oops! A SQL injection bug just forced an emergency WordPress core patch last week.   
On July 17, WordPress shipped an emergency release to fix an unauthenticated remote code execution flaw in the core, reachable via a SQL injection that an anonymous attacker can exploit on a stock install. WordPress.org even turned on forced auto-updates because of how severe it is. Searchlight Cyber, …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-60137`
- **CVE:** `CVE-2026-63030`
- **CVE:** `CVE-2024-42005`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1505.003** — Web Shell
- **T1059** — Command and Scripting Interpreter
- **T1505** — Server Software Component

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### wp2shell SQLi via author__not_in REST parameter (CVE-2026-60137)

`UC_6_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.status) as status values(Web.http_method) as http_method from datamodel=Web where Web.url="*author__not_in*" AND (Web.url="*'*" OR Web.url="*%27*" OR Web.url="*union*" OR Web.url="*UNION*" OR Web.url="*select*" OR Web.url="*SELECT*" OR Web.url="*sleep*" OR Web.url="*information_schema*" OR Web.url="*0x*" OR Web.url="*--*" OR Web.url="*/*") by Web.src Web.dest Web.http_user_agent Web.url | `drop_dm_object_name(Web)` | sort - lastTime
```

### WordPress web-server/PHP process spawning a shell (wp2shell RCE)

`UC_6_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("php-cgi.exe","php.exe","php-fpm","w3wp.exe","httpd","httpd.exe","apache2","nginx","nginx.exe")) AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","whoami","whoami.exe","curl","curl.exe","wget","python","python3")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("php-cgi.exe","php.exe","php-fpm","w3wp.exe","httpd.exe","httpd","apache2","nginx.exe","nginx")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","whoami.exe","whoami","curl.exe","curl","wget","python.exe","python3")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Malicious PHP plugin/webshell dropped in wp-content by web server (wp2shell)

`UC_6_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*wp-content*plugins*" OR Filesystem.file_path="*wp-content*uploads*") AND Filesystem.file_name="*.php" AND Filesystem.process_name IN ("php-cgi.exe","php.exe","php-fpm","w3wp.exe","httpd","httpd.exe","apache2","nginx","nginx.exe") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has "wp-content" and (FolderPath has "plugins" or FolderPath has "uploads")
| where FileName endswith ".php"
| where InitiatingProcessFileName in~ ("php-cgi.exe","php.exe","php-fpm","w3wp.exe","httpd.exe","httpd","nginx.exe","nginx","apache2")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-60137`, `CVE-2026-63030`, `CVE-2024-42005`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
