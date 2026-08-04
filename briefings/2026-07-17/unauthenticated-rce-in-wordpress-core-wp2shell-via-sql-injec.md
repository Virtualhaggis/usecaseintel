# [CRIT] Unauthenticated RCE in WordPress core (wp2shell), via SQL injection

**Source:** Aikido
**Published:** 2026-07-17
**Article:** https://www.aikido.dev/blog/unauthenticated-rce-in-wordpress-wp2shell

## Threat Profile

Blog Vulnerabilities & Threats Unauthenticated RCE in WordPress core (wp2shell) Unauthenticated RCE in WordPress core (wp2shell) Written by Dania Durnas Published on: Jul 17, 2026 SQL injections are still among us. On July 17, WordPress released an emergency security update. Version 7.0.2 fixes an unauthenticated remote code execution flaw in WordPress core that an anonymous attacker can trigger against a stock install with no plugins involved. If your site runs an affected version, update today…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-60137`
- **CVE:** `CVE-2026-63030`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1505.003** — Server Software Component: Web Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### WordPress wp2shell batch REST API pre-auth RCE exploitation (CVE-2026-63030/60137)

`UC_175_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.uri_path="*/batch/v1*" OR Web.url="*/wp-json/batch/v1*" OR Web.uri_query="*rest_route=/batch/v1*") by Web.src, Web.dest, Web.site, Web.http_method, Web.uri_path, Web.uri_query, Web.url, Web.status, Web.http_user_agent
| `drop_dm_object_name("Web")`
| where http_method IN ("POST","PUT","PATCH","DELETE") OR like(uri_query,"%author_exclude%") OR like(uri_query,"%author__not_in%") OR like(url,"%author_exclude%") OR like(url,"%SLEEP(%") OR like(uri_query,"%NOT IN%")
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### Web server daemon (php-fpm/apache/nginx/w3wp) spawning a shell or network tool — wp2shell post-exploit code execution

`UC_175_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("httpd","apache2","nginx","php-fpm","php-fpm7.4","php-fpm8.0","php-fpm8.1","php-fpm8.2","php-fpm8.3","w3wp.exe","php-cgi.exe") AND Processes.process_name IN ("sh","bash","dash","zsh","nc","ncat","netcat","curl","wget","python","python3","perl","cmd.exe","powershell.exe","pwsh")) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("httpd","apache2","nginx","php-fpm","php-fpm7.4","php-fpm8.0","php-fpm8.1","php-fpm8.2","php-fpm8.3","w3wp.exe","php-cgi.exe")
| where FileName in~ ("sh","bash","dash","zsh","nc","ncat","netcat","curl","wget","python","python3","perl","cmd.exe","powershell.exe","pwsh")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ParentProc=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine, ChildProc=FileName, ChildCmd=ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### New PHP file written into WordPress web root by a web daemon — wp2shell web shell drop

`UC_175_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.action="created" AND (Filesystem.file_path="*/wp-content/*" OR Filesystem.file_path="*/wp-admin/*" OR Filesystem.file_path="*/wp-includes/*") AND (Filesystem.file_name="*.php" OR Filesystem.file_name="*.phtml" OR Filesystem.file_name="*.php5" OR Filesystem.file_name="*.php7" OR Filesystem.file_name="*.phar")) by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.action
| `drop_dm_object_name("Filesystem")`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FolderPath has_any ("/wp-content/","\\wp-content\\","/wp-admin/","\\wp-admin\\","/wp-includes/","\\wp-includes\\")
| where FileName endswith ".php" or FileName endswith ".phtml" or FileName endswith ".php5" or FileName endswith ".php7" or FileName endswith ".phar"
| where InitiatingProcessFileName in~ ("httpd","apache2","nginx","php-fpm","php-fpm7.4","php-fpm8.0","php-fpm8.1","php-fpm8.2","php-fpm8.3","w3wp.exe","php-cgi.exe")
| project Timestamp, DeviceName, User=InitiatingProcessAccountName, FolderPath, FileName, WebDaemon=InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-60137`, `CVE-2026-63030`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
