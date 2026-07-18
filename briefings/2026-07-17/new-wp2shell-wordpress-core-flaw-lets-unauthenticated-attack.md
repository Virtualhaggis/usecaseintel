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
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Anonymous request to WordPress REST batch endpoint (/batch/v1 path + query-string variant)

`UC_0_1` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*/wp-json/batch/v1*" OR Web.uri_path="*/batch/v1*" OR Web.uri_query="*rest_route=/batch/v1*" OR Web.uri_query="*rest_route=%2Fbatch%2Fv1*" OR Web.uri_query="*author__not_in*") by Web.src, Web.dest, Web.http_method, Web.url, Web.uri_query, Web.status, Web.http_user_agent | `drop_dm_object_name(Web)` | sort - count
```

### Successful (2xx) response to WordPress /batch/v1 from a first-seen source IP

`UC_0_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*/batch/v1*" OR Web.uri_query="*rest_route=/batch/v1*" OR Web.uri_query="*rest_route=%2Fbatch%2Fv1*") (Web.status=200 OR Web.status=207) by Web.src, Web.dest, Web.http_method, Web.status, Web.http_user_agent | `drop_dm_object_name(Web)` | sort - count
```

### WordPress web server process spawns a shell/interpreter (wp2shell code execution)

`UC_0_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("apache2","httpd","nginx","php-fpm","php-fpm7.4","php-fpm8.1","php-fpm8.2","php","w3wp.exe")) (Processes.process_name IN ("sh","bash","dash","python","python3","perl","ruby","nc","ncat","cmd.exe","powershell.exe")) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | sort - count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("apache2","httpd","nginx","php-fpm","php","w3wp.exe")
| where FileName in~ ("sh","bash","dash","python","python3","perl","ruby","nc","ncat","cmd.exe","powershell.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### PHP webshell dropped in WordPress web root by web-server process

`UC_0_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/wp-content/uploads/*" OR Filesystem.file_path="*/wp-content/plugins/*" OR Filesystem.file_path="*/tmp/*") (Filesystem.file_name="*.php" OR Filesystem.file_name="*.phtml" OR Filesystem.file_name="*.php5" OR Filesystem.file_name="*.php7") by Filesystem.dest, Filesystem.file_path, Filesystem.file_name, Filesystem.process_name, Filesystem.action | `drop_dm_object_name(Filesystem)` | search process_name IN ("apache2","httpd","nginx","php-fpm","php","w3wp.exe") | sort - count
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName endswith ".php" or FileName endswith ".phtml" or FileName endswith ".php5" or FileName endswith ".php7"
| where FolderPath has_any ("/wp-content/uploads/","/wp-content/plugins/","\\wp-content\\uploads\\","\\wp-content\\plugins\\","/tmp/")
| where InitiatingProcessFileName has_any ("apache2","httpd","nginx","php-fpm","php","w3wp.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath, SHA256
| order by Timestamp desc
```

### wp-config.php read/exfiltrated by shell utility on WordPress host

`UC_0_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*wp-config.php*" (Processes.process_name IN ("cat","grep","less","more","head","tail","curl","wget","base64","xxd","tar","cp","strings","awk","sed","nl","php")) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | sort - count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "wp-config.php"
| where FileName in~ ("cat","grep","less","more","head","tail","curl","wget","base64","xxd","tar","cp","strings","awk","sed","nl","php")
| where InitiatingProcessFileName has_any ("apache2","httpd","nginx","php-fpm","php","sh","bash","dash")
   or InitiatingProcessAccountName in~ ("www-data","apache","nginx","httpd","daemon")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Reverse-shell egress from web-spawned interpreter on WordPress host

`UC_0_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process_name IN ("sh","bash","dash","python","python3","perl","ruby","nc","ncat")) All_Traffic.direction=outbound NOT (All_Traffic.dest_ip=10.0.0.0/8 OR All_Traffic.dest_ip=172.16.0.0/12 OR All_Traffic.dest_ip=192.168.0.0/16 OR All_Traffic.dest_ip=127.0.0.0/8) by All_Traffic.src, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("sh","bash","dash","python","python3","perl","ruby","nc","ncat")
| where InitiatingProcessParentFileName has_any ("apache2","httpd","nginx","php-fpm","php")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-63030`, `CVE-2026-60137`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
