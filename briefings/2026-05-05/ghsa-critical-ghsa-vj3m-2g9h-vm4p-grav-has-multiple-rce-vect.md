# [HIGH] [GHSA / CRITICAL] GHSA-vj3m-2g9h-vm4p: Grav has multiple RCE vectors: unsafe unserialize (x3), command injection in git clone, SSTI blocklist bypass

**Source:** GitHub Security Advisories
**Published:** 2026-05-05
**Article:** https://github.com/advisories/GHSA-vj3m-2g9h-vm4p

## Threat Profile

Grav has multiple RCE vectors: unsafe unserialize (x3), command injection in git clone, SSTI blocklist bypass

Multiple RCE vectors were found in Grav CMS. Three are critical, two are high.

**1. Unsafe unserialize() in JobQueue — direct RCE gadget (Critical)**

`system/src/Grav/Common/Scheduler/JobQueue.php:465` calls `unserialize(base64_decode(...))` without restricting `allowed_classes`. The `Job` class has `call_user_func_array($this->command, $this->args)` in its execution path, which is a …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.006** — Command and Scripting Interpreter: Python (via gadget)
- **T1221** — Template Injection
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Grav CMS git clone command injection via InstallCommand (GHSA-vj3m-2g9h-vm4p)

`UC_157_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name="php-fpm*" OR Processes.parent_process_name="php" OR Processes.parent_process_name="php-cgi" OR Processes.parent_process_name="apache2" OR Processes.parent_process_name="httpd" OR Processes.parent_process_name="nginx" OR Processes.parent_process_name="www-data") AND Processes.process_name="git" AND Processes.process="*clone*" AND (Processes.process="*--upload-pack=*" OR Processes.process="*--config=*" OR Processes.process="*--exec=*" OR Processes.process="*-c core.*" OR Processes.process="*$(*" OR Processes.process="*`*" OR Processes.process="*;*" OR Processes.process="*&&*" OR Processes.process="*||*" OR Processes.process="* | *") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("php-fpm","php","php-cgi","apache2","httpd","nginx")
| where FileName =~ "git"
| where ProcessCommandLine has "clone"
| where ProcessCommandLine has_any ("--upload-pack=","--config=","--exec=","-c core.","$(","`","&&","||","| sh","| bash")
   or ProcessCommandLine matches regex @"(?i)git\s+clone[^|]*(;|\|\s*\S)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

### [LLM] Grav Twig SSTI blocklist-bypass payload (twig_array_reduce / file_get_contents)

`UC_157_1` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as agents values(Web.http_method) as methods from datamodel=Web where Web.url="*twig_array_reduce*" OR Web.url="*twig_array_some*" OR Web.url="*twig_array_every*" OR Web.url="*twig_array_reduce%28*" OR Web.url="*file_get_contents%28*" OR Web.url="*fwrite%28*" by Web.src Web.dest Web.uri_path Web.http_method | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Defender XDR has no native inbound-HTTP table; this approximates by
// catching the strings in any URL observed by DeviceNetworkEvents and any
// hits in DeviceFileEvents where a Grav cache/log file contains the payload.
let sigs = dynamic(["twig_array_reduce","twig_array_some","twig_array_every"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (sigs)
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| union (
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FolderPath has_any ("/grav","\\grav","/user/data","/cache/twig")
    | where FileName has_any (sigs) or FolderPath has_any (sigs)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath
)
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 2 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
