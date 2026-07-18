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
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### WordPress wp2shell pre-auth RCE: requests to /wp-json/batch/v1 batch endpoint (CVE-2026-63030)

`UC_1_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where (Web.url="*/wp-json/batch/v1*" OR Web.url="*rest_route=/batch/v1*") Web.http_method=POST by Web.src, Web.dest, Web.url, Web.http_method, Web.status, Web.http_user_agent | `drop_dm_object_name(Web)` | sort - count
```

### WordPress SQL injection via author__not_in parameter (CVE-2026-60137)

`UC_1_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where Web.url="*author__not_in*" (Web.url="*union*" OR Web.url="*select*" OR Web.url="*sleep(*" OR Web.url="*benchmark(*" OR Web.url="*information_schema*" OR Web.url="*0x*" OR Web.url="*%27*" OR Web.url="*--*") by Web.src, Web.dest, Web.url, Web.http_method, Web.status | `drop_dm_object_name(Web)` | sort - count
```

### Web daemon (php-fpm/apache/nginx) spawning a shell or network tool — WordPress RCE post-exploit

`UC_1_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("php-fpm","php","apache2","httpd","nginx","caddy")) (Processes.process_name IN ("sh","bash","dash","nc","ncat","netcat","curl","wget","python","python3","perl","ruby")) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | sort - count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("php-fpm","php","php8.2","php8.3","apache2","httpd","nginx","caddy")
| where FileName in~ ("sh","bash","dash","nc","ncat","netcat","curl","wget","python","python3","perl","ruby")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath
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

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
