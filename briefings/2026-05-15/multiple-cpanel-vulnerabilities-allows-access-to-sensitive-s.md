# [HIGH] Multiple cPanel Vulnerabilities Allows Access to Sensitive System Resources

**Source:** Cyber Security News
**Published:** 2026-05-15
**Article:** https://cybersecuritynews.com/cpanel-vulnerabilities/

## Threat Profile

Home Cyber Security News 
Multiple cPanel Vulnerabilities Allows Access to Sensitive System Resources 
By Abinaya 
May 15, 2026 




In a severe blow to web hosting environments worldwide, administrators are racing against the clock to patch a massive wave of security vulnerabilities affecting cPanel and WebHost Manager (WHM). 
Threat actors are currently eyeing newly disclosed flaws that grant unauthenticated access to sensitive system resources, potentially allowing complete server comprom…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-29202`
- **CVE:** `CVE-2026-29201`
- **CVE:** `CVE-2026-43284`
- **CVE:** `CVE-2026-43500`
- **CVE:** `CVE-2026-40684`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1053.005** — Scheduled Task
- **T1059.006** — Command and Scripting Interpreter: Perl
- **T1505.003** — Server Software Component: Web Shell
- **T1083** — File and Directory Discovery
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] cPanel WHM create_user API 'plugin' parameter Perl code injection (CVE-2026-29202)

`UC_2_2` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.uri_query) as uri_query values(Web.user) as user values(Web.user_agent) as user_agent values(Web.http_method) as method from datamodel=Web where Web.http_method=POST (Web.url="*create_user*" OR Web.uri_path="*create_user*") (Web.url="*plugin=*" OR Web.uri_query="*plugin=*") (Web.url="*%60*" OR Web.url="*`*" OR Web.url="*system(*" OR Web.url="*exec(*" OR Web.url="*eval(*" OR Web.url="*qx{*" OR Web.url="*%2Fbin%2Fsh*" OR Web.url="*/bin/sh*" OR Web.url="*base64*" OR Web.url="*open(*" OR Web.url="*%7C*sh*") by Web.src Web.dest Web.http_user_agent
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| eval cve="CVE-2026-29202", note="cPanel create_user plugin-param Perl injection"
```

**Defender KQL:**
```kql
// Article: cPanel create_user API perl injection via 'plugin' parameter.
// Host-side trail — cpsrvd / whostmgrd spawning interpreters with injection-shaped cmdlines.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("cpsrvd","cpsrvd-ssl","whostmgrd","cpanel","cpanellogd")
| where FileName in~ ("perl","sh","bash","dash","nc","ncat","wget","curl","python","python3","php")
| where ProcessCommandLine has_any (" -e ","system(","exec(","eval(","qx{","/bin/sh","/bin/bash","/dev/tcp","base64 -d","base64 --decode","|sh","| sh","open(","`")
| project Timestamp, DeviceName, AccountName,
          ParentImage=InitiatingProcessFolderPath, ParentCmd=InitiatingProcessCommandLine,
          Child=FileName, ChildCmd=ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] cPanel feature-file arbitrary file read via path traversal (CVE-2026-29201)

`UC_2_3` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.uri_query) as uri_query values(Web.src) as src values(Web.user_agent) as user_agent values(Web.status) as status from datamodel=Web where (Web.url="*feature=*" OR Web.url="*/feature/*" OR Web.uri_query="*feature=*") (Web.url="*..%2F*" OR Web.url="*..%2f*" OR Web.url="*../*" OR Web.url="*%2e%2e%2f*" OR Web.url="*%2e%2e/*" OR Web.url="*%2fetc%2fpasswd*" OR Web.url="*/etc/passwd*" OR Web.url="*/etc/shadow*" OR Web.url="*.my.cnf*" OR Web.url="*wp-config*" OR Web.url="*/root/*" OR Web.url="*/var/cpanel/*" OR Web.url="*.htpasswd*" OR Web.url="*%2froot%2f*") by Web.dest Web.src Web.url
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| eval cve="CVE-2026-29201", note="cPanel feature-file arbitrary read via traversal"
```

**Defender KQL:**
```kql
// CVE-2026-29201 — cPanel feature-file arbitrary read.
// Defender for Endpoint on Linux does NOT emit file-read events, so we hunt the secondary signal:
// cpsrvd / whostmgrd spawning readers (cat/less/perl/python) against sensitive paths during exploitation.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("cpsrvd","cpsrvd-ssl","whostmgrd","cpanel","cpanellogd")
| where FileName in~ ("cat","less","more","head","tail","perl","python","python3","awk","sed","od","strings")
| where ProcessCommandLine has_any ("/etc/passwd","/etc/shadow","/root/",".my.cnf","wp-config","/etc/cpanel/","/var/cpanel/",".htpasswd",".ssh/id_","/etc/sudoers")
| project Timestamp, DeviceName, AccountName,
          ParentImage=InitiatingProcessFolderPath, ParentCmd=InitiatingProcessCommandLine,
          Reader=FileName, ReaderCmd=ProcessCommandLine
| order by Timestamp desc
```

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-29202`, `CVE-2026-29201`, `CVE-2026-43284`, `CVE-2026-43500`, `CVE-2026-40684`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
