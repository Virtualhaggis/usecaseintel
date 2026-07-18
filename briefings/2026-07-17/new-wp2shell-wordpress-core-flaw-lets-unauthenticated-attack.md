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
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1505.003** — Server Software Component: Web Shell
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Anonymous request to WordPress REST batch endpoint (/wp-json/batch/v1 + rest_route=/batch/v1)

`UC_0_1` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method=POST (Web.url="*/wp-json/batch/v1*" OR Web.url="*rest_route=/batch/v1*" OR Web.uri_path="*/batch/v1*" OR Web.uri_query="*rest_route=/batch/v1*") by Web.src Web.dest Web.http_method Web.url Web.uri_path Web.uri_query Web.status Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

### WordPress batch endpoint request carrying SQL-injection / route-confusion markers (wp2shell)

`UC_0_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*/batch/v1*" OR Web.url="*rest_route=/batch/v1*") (Web.url="*union*select*" OR Web.url="*information_schema*" OR Web.url="*sleep(*" OR Web.url="*benchmark(*" OR Web.url="*extractvalue(*" OR Web.url="*updatexml(*" OR Web.url="*orderby*" OR Web.url="*/*!*" OR Web.url="*0x*") by Web.src Web.dest Web.http_method Web.url Web.status Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

### Web-server user (apache/nginx/php-fpm) spawns a shell or scripting interpreter

`UC_0_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("apache2","httpd","nginx","php-fpm","php","php7.4","php8.1","php8.2","php8.3") Processes.process_name IN ("sh","bash","dash","zsh","python","python3","perl","ruby","nc","ncat","curl","wget") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("apache2","httpd","nginx","php-fpm","php","php7.4","php8.1","php8.2","php8.3")
| where FileName in~ ("sh","bash","dash","zsh","python","python3","perl","ruby","nc","ncat","curl","wget")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### PHP webshell dropped in WordPress web root by web-server process

`UC_0_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") (Filesystem.file_name="*.php" OR Filesystem.file_name="*.phtml" OR Filesystem.file_name="*.php5" OR Filesystem.file_name="*.phar") (Filesystem.file_path="*wp-content/uploads*" OR Filesystem.file_path="*wp-content/plugins*" OR Filesystem.file_path="*wp-content/mu-plugins*" OR Filesystem.file_path="*/tmp/*") by Filesystem.dest Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName in~ ("apache2","httpd","nginx","php-fpm","php","php7.4","php8.1","php8.2","php8.3")
| where FileName endswith ".php" or FileName endswith ".phtml" or FileName endswith ".php5" or FileName endswith ".phar"
| where FolderPath has_any ("wp-content/uploads","wp-content/plugins","wp-content/mu-plugins","/tmp/")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA256
| order by Timestamp desc
```

### wp-config.php read by WordPress web-server or shell process (DB credential theft)

`UC_0_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*wp-config.php*" Processes.process_name IN ("cat","grep","less","more","head","tail","php","strings","awk","sed","xxd","base64","curl") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has "wp-config.php"
| where FileName in~ ("cat","grep","less","more","head","tail","php","strings","awk","sed","xxd","base64","curl")
| where InitiatingProcessFileName in~ ("sh","bash","dash","zsh","apache2","httpd","nginx","php-fpm","php") or AccountName in~ ("www-data","apache","nginx","httpd","daemon")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-63030`, `CVE-2026-60137`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
