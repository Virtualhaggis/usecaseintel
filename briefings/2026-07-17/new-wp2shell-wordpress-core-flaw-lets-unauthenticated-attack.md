# [CRIT] New wp2shell WordPress Core Flaw Lets Unauthenticated Attackers Run Code

**Source:** The Hacker News
**Published:** 2026-07-17
**Article:** https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html

## Threat Profile

New wp2shell WordPress Core Flaw Lets Unauthenticated Attackers Run Code 
 Swati Khandelwal  Jul 17, 2026 Vulnerability / Web Security 
An anonymous HTTP request can run code on a WordPress site. The bug is in core, so a bare install with zero plugins is exploitable.
Every 6.9 and 7.0 site was in range until Friday, when WordPress shipped 6.9.5 and 7.0.2 and enabled what it calls forced updates through its auto-update system.
Adam Kues at Assetnote, Searchlight Cyber's attack surface managemen…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-63030`
- **CVE:** `CVE-2026-60137`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1211** — Exploitation for Defense Evasion
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1505.003** — Server Software Component: Web Shell
- **T1005** — Data from Local System
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unauthenticated request to WordPress REST batch/v1 endpoint (wp2shell CVE-2026-63030)

`UC_67_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/wp-json/batch/v1*" OR Web.url="*rest_route=/batch/v1*" OR Web.url="*rest_route=%2Fbatch%2Fv1*" OR Web.uri_query="*rest_route=/batch/v1*" OR Web.uri_query="*rest_route=%2Fbatch%2Fv1*") by Web.src, Web.dest, Web.http_method, Web.url, Web.uri_query, Web.http_user_agent, Web.status | `drop_dm_object_name(Web)` | eval sqli_indicator=if(match(url."author__not_in") OR match(uri_query,"author__not_in"),"yes","no") | sort - lastTime
```

### Successful (HTTP 200) response from WordPress batch/v1 to an anonymous caller

`UC_67_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*batch/v1*" OR Web.uri_query="*rest_route=/batch/v1*" OR Web.uri_query="*rest_route=%2Fbatch%2Fv1*") Web.status=200 by Web.src, Web.dest, Web.http_method, Web.status | `drop_dm_object_name(Web)` | stats sum(count) as batch200_hits values(http_method) as methods min(firstTime) as firstTime max(lastTime) as lastTime by src, dest | where batch200_hits >= 1 | convert ctime(firstTime) ctime(lastTime) | sort - batch200_hits
```

### WordPress web-server / PHP-FPM process spawns a shell interpreter

`UC_67_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("apache2","httpd","nginx","php-fpm","php","php7.4","php8.0","php8.1","php8.2","php8.3")) AND (Processes.process_name IN ("sh","bash","dash","zsh","python","python3","perl","ruby","nc","ncat","socat")) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("apache2","httpd","nginx","php-fpm","php","php7.4","php8.0","php8.1","php8.2","php8.3")
| where FileName in~ ("sh","bash","dash","zsh","python","python3","perl","ruby","nc","ncat","socat")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### PHP webshell written under wp-content by WordPress web process

`UC_67_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/wp-content/uploads/*" OR Filesystem.file_path="*/wp-content/plugins/*" OR Filesystem.file_path="*/wp-content/themes/*") AND (Filesystem.file_name="*.php" OR Filesystem.file_name="*.phtml" OR Filesystem.file_name="*.php5" OR Filesystem.file_name="*.phar") AND Filesystem.action=created by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileCreated"
| where FolderPath has_any ("/wp-content/uploads/","/wp-content/plugins/","/wp-content/themes/")
| where FileName endswith ".php" or FileName endswith ".phtml" or FileName endswith ".php5" or FileName endswith ".phar"
| where InitiatingProcessFileName in~ ("apache2","httpd","nginx","php-fpm","php","php7.4","php8.0","php8.1","php8.2","php8.3")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### wp-config.php read via shell utility (post-RCE DB credential theft)

`UC_67_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*wp-config.php*" AND Processes.process_name IN ("cat","grep","egrep","less","more","head","tail","tar","cp","curl","wget","base64","xxd","strings","php","zip","gzip","scp","nc") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has "wp-config.php"
| where FileName in~ ("cat","grep","egrep","less","more","head","tail","tar","cp","curl","wget","base64","xxd","strings","php","zip","gzip","scp","nc")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-63030`, `CVE-2026-60137`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
