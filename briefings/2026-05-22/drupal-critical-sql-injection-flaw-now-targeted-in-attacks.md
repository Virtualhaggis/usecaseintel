# [HIGH] Drupal: Critical SQL injection flaw now targeted in attacks

**Source:** BleepingComputer
**Published:** 2026-05-22
**Article:** https://www.bleepingcomputer.com/news/security/drupal-critical-sql-injection-flaw-now-targeted-in-attacks/

## Threat Profile

Drupal: Critical SQL injection flaw now targeted in attacks 
By Bill Toulas 
May 22, 2026
09:14 AM
0 
Drupal is warning that hackers are attempting to exploit a "highly critical" SQL injection vulnerability announced earlier this week.
The content management system (CMS) project published a PSA on May 18, urging administrators to reserve time for core updates that addressed an issue that threat actors might start exploiting "within hours or days."
The flaw is now tracked as CVE-2026-9082 and was…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-9082`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059** — Command and Scripting Interpreter
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1505.003** — Server Software Component: Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Unauthenticated SQLi probe against Drupal endpoints (CVE-2026-9082)

`UC_34_1` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.uri_query) as uri_query values(Web.user_agent) as ua values(Web.http_method) as method from datamodel=Web where (Web.uri_path="*/jsonapi/*" OR Web.uri_path="*/node/*" OR Web.uri_path="*/views/ajax*" OR Web.uri_path="*/search/*" OR Web.uri_path="*/rest/*" OR Web.uri_path="*/entity/*" OR Web.uri_path="*/user/login*" OR Web.uri_path="*/?q=*") AND (Web.url="*pg_sleep*" OR Web.url="*UNION*SELECT*" OR Web.url="*COPY*FROM*PROGRAM*" OR Web.url="*pg_read_file*" OR Web.url="*lo_import*" OR Web.url="*%5B*%27*%5D*" OR Web.url="*[*'*]*" OR Web.url="*--+*" OR Web.url="*%27)*OR*%27*") by Web.dest Web.src Web.uri_path Web.http_method Web.status host | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

### [LLM] Drupal/PHP/web server process spawning shell or LOLBin (post-CVE-2026-9082 RCE)

`UC_34_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("php-fpm","php-fpm.exe","httpd","httpd.exe","apache2","nginx","nginx.exe","w3wp.exe","php-cgi.exe","php.exe","php","drush")) AND (Processes.process_name IN ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh.exe","wget","curl","perl","python","python3","nc","ncat","socat","whoami","id","uname") OR Processes.process IN ("*\/dev\/tcp\/*","*bash -i*","*sh -i*","*nc -e*","*mkfifo*","*-NoProfile -enc*","*Invoke-WebRequest*","*DownloadString*","*python -c*","*perl -e*")) by host user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WebParents = dynamic(["php-fpm","php-fpm.exe","httpd","httpd.exe","apache2","nginx","nginx.exe","w3wp.exe","php-cgi.exe","php.exe","php","drush"]);
let ShellChildren = dynamic(["sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh.exe","wget","curl","perl","python","python3","nc","ncat","socat","whoami","id","uname","hostname"]);
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ (WebParents)
| where FileName in~ (ShellChildren)
    or ProcessCommandLine has_any ("/dev/tcp/","bash -i","sh -i","nc -e","mkfifo","python -c","perl -e","-NoProfile -enc","-NoP -e","Invoke-WebRequest","DownloadString","curl http","wget http")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] Web server writes PHP/PHAR file outside Drupal's compiled-twig path (webshell drop)

`UC_34_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.process_name IN ("php-fpm","php-fpm.exe","httpd","httpd.exe","apache2","nginx","nginx.exe","w3wp.exe","php-cgi.exe","php.exe","php")) AND (Filesystem.file_name="*.php" OR Filesystem.file_name="*.phtml" OR Filesystem.file_name="*.phar" OR Filesystem.file_name="*.inc") AND NOT (Filesystem.file_path="*/files/php/twig/*" OR Filesystem.file_path="*\\files\\php\\twig\\*" OR Filesystem.file_path="*/core/lib/*" OR Filesystem.file_path="*\\core\\lib\\*" OR Filesystem.file_path="*/vendor/*" OR Filesystem.file_path="*\\vendor\\*") by host Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WebParents = dynamic(["php-fpm","php-fpm.exe","httpd","httpd.exe","apache2","nginx","nginx.exe","w3wp.exe","php-cgi.exe","php.exe","php"]);
DeviceFileEvents
| where Timestamp > ago(LookbackDays)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName in~ (WebParents)
| where FileName endswith ".php" or FileName endswith ".phtml" or FileName endswith ".phar" or FileName endswith ".inc"
| where not(FolderPath has_any ("files/php/twig","files\\php\\twig","core/lib","core\\lib","/vendor/","\\vendor\\"))
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, FileSize,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-9082`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
