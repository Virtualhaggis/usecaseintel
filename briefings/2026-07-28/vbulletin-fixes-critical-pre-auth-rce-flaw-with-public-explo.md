# [HIGH] vBulletin fixes critical pre-auth RCE flaw with public exploit

**Source:** BleepingComputer
**Published:** 2026-07-28
**Article:** https://www.bleepingcomputer.com/news/security/vbulletin-fixes-critical-pre-auth-rce-flaw-with-public-exploit/

## Threat Profile

vBulletin fixes critical pre-auth RCE flaw with public exploit 
By Bill Toulas 
July 28, 2026
02:08 PM
0 
A critical vulnerability in the vBulletin forum software allows unauthenticated attackers to execute arbitrary PHP code through template rendering.
The security issue is tracked as CVE-2026-61511 and affects vBulletin versions in the 5.x and 6.x branches up to 5.7.5 and 6.2.1, respectively.
vBulletin is a PHP-based proprietary forum platform released in 2000 and used by large online communit…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-61511`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### vBulletin CVE-2026-61511 pre-auth RCE via ajax/render/pagenav template request

`UC_13_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*ajax/render/pagenav*" OR Web.uri_path="*ajax/render/pagenav*") by Web.src Web.dest Web.site Web.http_method Web.uri_path Web.url Web.uri_query Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| eval phpfuck_score=if(match(url."".uri_query,"(?i)pagenav(\[|%5[bB])pagenumber") OR match(url."".uri_query,"[\^\(\)!~]{4,}"),1,0)
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
| sort - lastTime
```

### vBulletin web-server process (php-fpm/apache/nginx) spawning OS shell after CVE-2026-61511

`UC_13_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("php-fpm","php","php-cgi","httpd","apache2","nginx")) (Processes.process_name IN ("sh","bash","dash","zsh","whoami","id","uname","curl","wget","python","python3","perl","nc","ncat")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("php-fpm","php","php-cgi","httpd","apache2","nginx")
| where FileName in~ ("sh","bash","dash","zsh","whoami","id","uname","curl","wget","python","python3","perl","nc","ncat")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-61511`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 3 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
