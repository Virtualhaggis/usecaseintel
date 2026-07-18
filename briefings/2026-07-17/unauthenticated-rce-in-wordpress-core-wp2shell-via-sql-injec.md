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
- **T1211** — Exploitation for Defense Evasion
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1505.003** — Server Software Component: Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### WordPress wp2shell SQLi via author__not_in REST parameter (CVE-2026-60137)

`UC_1_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*author__not_in*" OR Web.uri_query="*author__not_in*") by Web.src, Web.dest, Web.http_method, Web.url, Web.uri_query, Web.status, Web.http_user_agent
| `drop_dm_object_name(Web)`
| eval hay=url." ".uri_query
| where match(hay, "(?i)author__not_in[^0-9,\s].*?(union|select|sleep\(|benchmark\(|updatexml|extractvalue|information_schema|group_concat|0x[0-9a-f]{4}|--|%27|')")
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

### WordPress REST batch-route access — wp2shell RCE entry point (CVE-2026-63030)

`UC_1_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*/wp-json/batch/v1*" OR Web.url="*rest_route=/batch/v1*" OR Web.uri_query="*rest_route=/batch/v1*") by Web.src, Web.dest, Web.http_method, Web.url, Web.status, Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - count
```

### Web daemon (php-fpm/apache/nginx) spawning shell — wp2shell post-exploit code execution

`UC_1_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Endpoint.Processes.parent_process_name IN ("php-fpm","php-fpm7.4","php-fpm8.1","php-fpm8.2","apache2","httpd","nginx","php") AND Endpoint.Processes.process_name IN ("bash","sh","dash","nc","ncat","netcat","curl","wget","python","python3","perl","ruby")) by Endpoint.Processes.dest, Endpoint.Processes.user, Endpoint.Processes.parent_process_name, Endpoint.Processes.process_name, Endpoint.Processes.process
| `drop_dm_object_name(Endpoint.Processes)`
| where match(process, "(?i)(/dev/tcp/|-i\b|-e\b|bash -i|sh -i|reverse|https?://|-c\s)")
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("php-fpm","php-fpm7.4","php-fpm8.1","php-fpm8.2","apache2","httpd","nginx","php")
| where FileName in~ ("bash","sh","dash","nc","ncat","netcat","curl","wget","python","python3","perl","ruby")
| where ProcessCommandLine has_any ("/dev/tcp/","-i","-e","bash -i","sh -i","reverse","http://","https://","-c ")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### PHP web shell written to WordPress web root by server process (wp2shell persistence)

`UC_1_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Endpoint.Filesystem.action=created AND Endpoint.Filesystem.file_path IN ("*/wp-content/*","*/wp-includes/*","*/wp-admin/*") AND Endpoint.Filesystem.file_name IN ("*.php","*.phtml","*.php5","*.php7")) by Endpoint.Filesystem.dest, Endpoint.Filesystem.file_path, Endpoint.Filesystem.file_name, Endpoint.Filesystem.process_name, Endpoint.Filesystem.user
| `drop_dm_object_name(Endpoint.Filesystem)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileCreated"
| where FolderPath has_any ("/wp-content/","/wp-includes/","/wp-admin/","\\wp-content\\","\\wp-includes\\","\\wp-admin\\")
| where FileName endswith ".php" or FileName endswith ".phtml" or FileName endswith ".php5" or FileName endswith ".php7"
| where InitiatingProcessFileName in~ ("php-fpm","php-fpm7.4","php-fpm8.1","php-fpm8.2","apache2","httpd","nginx","php","w3wp.exe")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
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

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
