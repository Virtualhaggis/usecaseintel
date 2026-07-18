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
- **T1059** — Command and Scripting Interpreter
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1505.003** — Server Software Component: Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### WordPress wp2shell pre-auth RCE: anonymous batch/v1 endpoint access + author__not_in SQLi (CVE-2026-63030/60137)

`UC_0_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/wp-json/batch/v1*" OR Web.url="*rest_route=/batch/v1*" OR Web.url="*rest_route=%2Fbatch%2Fv1*") by Web.src, Web.dest, Web.http_method, Web.url, Web.status
| `drop_dm_object_name(Web)`
| eval sqli_indicator=if(match(url,"(?i)author__not_in|union\s+select|sleep\(|benchmark\(|information_schema|0x[0-9a-f]{6,}"),"sqli-in-batch-route","anon-batch-access")
| stats count values(http_method) as methods values(status) as statuses values(url) as sample_urls by src, dest, sqli_indicator, firstTime, lastTime
| `security_content_ctime(firstTime)` `security_content_ctime(lastTime)`
| sort - count
```

### WordPress PHP/web worker spawning a shell — wp2shell RCE execution

`UC_0_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("php-fpm","php-fpm7.4","php-fpm8.0","php-fpm8.1","php-fpm8.2","php-fpm8.3","php","php-cgi","httpd","apache2","nginx","w3wp.exe") AND Processes.process_name IN ("sh","bash","dash","zsh","ksh","python","python3","perl","ruby","nc","ncat","cmd.exe","powershell.exe","curl","wget")) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` `security_content_ctime(lastTime)`
| sort - count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("php-fpm","php-fpm7.4","php-fpm8.0","php-fpm8.1","php-fpm8.2","php-fpm8.3","php","php-cgi","httpd","apache2","nginx","w3wp.exe")
| where FileName in~ ("sh","bash","dash","zsh","ksh","python","python3","perl","ruby","nc","ncat","cmd.exe","powershell.exe","curl","wget")
| where AccountName !endswith "$"
| where not (ProcessCommandLine has_any ("mysqldump","wp-cli","wp-cron","/convert ","imagemagick","gs -"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-63030`, `CVE-2026-60137`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
