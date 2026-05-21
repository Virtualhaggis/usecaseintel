# [CRIT] Highly Critical Drupal Core Flaw Exposes PostgreSQL Sites to RCE Attacks

**Source:** The Hacker News
**Published:** 2026-05-21
**Article:** https://thehackernews.com/2026/05/highly-critical-drupal-core-flaw.html

## Threat Profile

Highly Critical Drupal Core Flaw Exposes PostgreSQL Sites to RCE Attacks 
 Ravie Lakshmanan  May 21, 2026 Web Security / Vulnerability 
Drupal has released security updates for a "highly critical" security vulnerability in Drupal Core that could be exploited by attackers to achieve remote code execution, privilege escalation, or information disclosure.
The vulnerability, now tracked as CVE-2026-9082 , carries a CVSS score of 6.5 out of 10.0, per CVE.org. Drupal said the vulnerability resides i…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-9082`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1505.003** — Server Software Component: Web Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PostgreSQL-syntax SQL injection probes against Drupal endpoints (anonymous, unauthenticated)

`UC_18_4` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as ua values(Web.src) as src_ip from datamodel=Web.Web where Web.dest_category="drupal" OR Web.url="*/node*" OR Web.url="*/jsonapi*" OR Web.url="*/rest*" OR Web.url="*/search*" OR Web.url="*/views*" OR Web.url="*/user/login*" by Web.src Web.dest Web.url Web.status Web.http_method | `drop_dm_object_name(Web)` | where match(url, "(?i)(pg_sleep\(|pg_read_file|COPY\s+\w+\s+FROM\s+PROGRAM|::regclass|::text|\"\s*;\s*--|UNION\s+ALL\s+SELECT|information_schema\.tables|pg_catalog\.|current_database\(\)|version\(\))") | where status<500 | stats min(firstTime) as firstTime max(lastTime) as lastTime values(url) as urls values(http_method) as methods values(status) as statuses dc(url) as uniq_urls count by src dest | where count>=3 OR uniq_urls>=2 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Defender Advanced Hunting does not natively carry web access logs; if your Drupal frontends ship to DeviceNetworkEvents via an ingestion connector, pivot on URL strings observed in DeviceNetworkEvents.RemoteUrl back to internal hosts.
let PgInjectionMarkers = dynamic(["pg_sleep(","pg_read_file","COPY "," FROM PROGRAM","::regclass","::text","information_schema.tables","pg_catalog.","current_database()","UNION ALL SELECT","' OR 1=1--","\";--"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess")
| where RemoteUrl has_any ("/node","/jsonapi","/rest","/search","/views","/user/login","/admin")
| where RemoteUrl has_any (PgInjectionMarkers)
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| summarize HitCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), SampleUrls=make_set(RemoteUrl,5) by DeviceName, RemoteIP
| where HitCount >= 3
```

### [LLM] Drupal docroot webshell drop or post-exploit shell spawn from PHP-FPM/Apache/Nginx (CVE-2026-9082 post-exploit)

`UC_18_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.process_path) as proc_paths values(Processes.user) as users from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("php-fpm","php-fpm7.4","php-fpm8.1","php-fpm8.2","php-fpm8.3","httpd","apache2","nginx","w3wp.exe") AND Processes.process_name IN ("sh","bash","dash","zsh","python","python3","perl","ruby","nc","ncat","socat","curl","wget","psql","cmd.exe","powershell.exe") by host Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where NOT match(process, "(?i)(logrotate|drush\s+cron|drush\s+cache-rebuild)") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Two-arm detection: (A) shell spawn from web-tier parent, (B) new PHP/phar file written into Drupal docroot by web-tier process.
let WebParents = dynamic(["php-fpm","php-fpm7.4","php-fpm8.0","php-fpm8.1","php-fpm8.2","php-fpm8.3","httpd","apache2","nginx","w3wp.exe"]);
let ShellChildren = dynamic(["sh","bash","dash","zsh","ksh","python","python3","perl","ruby","nc","ncat","socat","curl","wget","psql","cmd.exe","powershell.exe","pwsh"]);
let ShellSpawn = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName has_any (WebParents)
    | where FileName has_any (ShellChildren)
    | where not (ProcessCommandLine has_any ("drush cron","drush cache-rebuild","logrotate"))
    | project Timestamp, DeviceName, Arm="shell_spawn", InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName;
let PhpDrop = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("FileCreated","FileModified","FileRenamed")
    | where FileName endswith ".php" or FileName endswith ".phtml" or FileName endswith ".phar" or FileName endswith ".php7" or FileName endswith ".inc"
    | where FolderPath has_any ("/sites/default/files","/sites/all/files","/web/sites/","\\sites\\default\\files","\\web\\sites\\")
    | where InitiatingProcessFileName has_any (WebParents)
    | project Timestamp, DeviceName, Arm="php_drop", InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA256, InitiatingProcessAccountName;
ShellSpawn
| union PhpDrop
| order by Timestamp desc
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-9082`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
