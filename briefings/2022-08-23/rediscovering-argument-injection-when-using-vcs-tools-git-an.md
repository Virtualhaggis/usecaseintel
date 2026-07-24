# [HIGH] Rediscovering argument injection when using VCS tools — git and mercurial

**Source:** Snyk
**Published:** 2022-08-23
**Article:** https://snyk.io/blog/argument-injection-when-using-git-and-mercurial/

## Threat Profile

Snyk Blog In this article
Written by Alessio Della Libera 
August 23, 2022
0 mins read One of the main goals for this research was to explore how it is possible to execute arbitrary commands even when using a safe API that prevents command injection. The focus will be on Version Control System (VCS) tools like git and hg (mercurial), that, among some of their options, allow the execution of arbitrary commands (under some circumstances).
The targets for this research are web applications and libr…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-25766`
- **CVE:** `CVE-2022-29184`
- **CVE:** `CVE-2022-23915`
- **CVE:** `CVE-2022-24433`
- **CVE:** `CVE-2022-25648`
- **CVE:** `CVE-2022-24440`
- **CVE:** `CVE-2022-21223`
- **CVE:** `CVE-2022-21235`
- **CVE:** `CVE-2022-25866`
- **CVE:** `CVE-2022-21187`
- **CVE:** `CVE-2022-25865`
- **CVE:** `CVE-2022-24065`
- **CVE:** `CVE-2022-26945`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Git argument injection via --upload-pack option spawned by web-app runtime

`UC_2051_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("git","git.exe")) AND (Processes.process="*--upload-pack*") AND (Processes.parent_process_name IN ("node","node.exe","python","python3","python.exe","ruby","ruby.exe","java","java.exe","php","php-fpm","php-cgi.exe","w3wp.exe","gunicorn","uwsgi","puma","unicorn")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id | `drop_dm_object_name(Processes)` | search NOT process="*git-upload-pack*" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("git","git.exe")
| where ProcessCommandLine has "--upload-pack"
| where ProcessCommandLine has_any ("ls-remote","fetch","pull","clone","fetch-pack")
| where InitiatingProcessFileName in~ ("node","node.exe","python","python3","python.exe","ruby","ruby.exe","java","java.exe","php","php-fpm","php-cgi.exe","w3wp.exe","gunicorn","uwsgi","puma","unicorn")
| where AccountName !endswith "$"
| where not(ProcessCommandLine has "git-upload-pack")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Mercurial argument injection via --config alias/hooks or --debugger from app runtime

`UC_2051_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("hg","hg.exe")) AND ((Processes.process="*--config*" AND (Processes.process="*alias.*=!*" OR Processes.process="*hooks.pre-*" OR Processes.process="*hooks.post-*")) OR Processes.process="*--debugger*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("hg","hg.exe")
| where (ProcessCommandLine has "--config" and (ProcessCommandLine matches regex @"(?i)alias\.[a-z0-9_-]+\s*=\s*!" or ProcessCommandLine has_any ("hooks.pre-","hooks.post-"))) or ProcessCommandLine has "--debugger"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### git/hg spawning a shell as child of a web-app runtime (argument-injection RCE evidence)

`UC_2051_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("git","git.exe","hg","hg.exe")) AND (Processes.process_name IN ("sh","sh.exe","bash","bash.exe","dash","zsh","cmd.exe","powershell.exe","pwsh")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("git","git.exe","hg","hg.exe")
| where FileName in~ ("sh","sh.exe","bash","bash.exe","dash","zsh","cmd.exe","powershell.exe","pwsh")
| where InitiatingProcessParentFileName in~ ("node","node.exe","python","python3","python.exe","ruby","ruby.exe","java","java.exe","php","php-fpm","php-cgi.exe","w3wp.exe","gunicorn","uwsgi","puma","unicorn")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, GrandParent=InitiatingProcessParentFileName, Parent=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine, Child=FileName, ChildCmd=ProcessCommandLine
| order by Timestamp desc
```

### Article-specific behavioural hunt — Rediscovering argument injection when using VCS tools — git and mercurial

`UC_2051_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Rediscovering argument injection when using VCS tools — git and mercurial ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Rediscovering argument injection when using VCS tools — git and mercurial
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-25766`, `CVE-2022-29184`, `CVE-2022-23915`, `CVE-2022-24433`, `CVE-2022-25648`, `CVE-2022-24440`, `CVE-2022-21223`, `CVE-2022-21235` _(+5 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, 5 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
