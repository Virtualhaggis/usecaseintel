# [CRIT] Controlling your server with a reverse shell attack

**Source:** Snyk
**Published:** 2022-08-10
**Article:** https://snyk.io/blog/reverse-shell-attack/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
August 10, 2022
0 mins read Editor's note: May 9, 2023 This post, originally published on August 10, 2022, has been updated to show how Snyk can help you prevent reverse shell attacks.
Creating and running an application in your favorite language is usually pretty simple. After you create your application, deploying it and showing it to the world is also quite straightforward. The last thing you need is someone to take over your system and full…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-44228`
- **CVE:** `CVE-2022-22965`
- **CVE:** `CVE-2022-33980`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1571** — Non-Standard Port
- **T1095** — Non-Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Bash reverse shell via /dev/tcp file-descriptor redirection

`UC_2089_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name from datamodel=Endpoint.Processes where (Processes.process="*/dev/tcp/*" OR Processes.process="*/dev/udp/*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine contains "/dev/tcp/" or ProcessCommandLine contains "/dev/udp/"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Interactive shell process initiating outbound network connection (reverse-shell C2)

`UC_2089_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic where (All_Traffic.app="bash" OR All_Traffic.app="sh" OR All_Traffic.app="dash" OR All_Traffic.app="zsh" OR All_Traffic.app="ksh") AND All_Traffic.direction="outbound" AND All_Traffic.dest!="127.0.0.1" by All_Traffic.src All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ ("bash","sh","dash","zsh","ksh")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, RemoteIP, RemotePort
| order by Timestamp desc
```

### Server application runtime spawning shell with /dev/tcp redirection (RCE to reverse shell)

`UC_2089_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("java","node","python","python3","php","php-fpm","ruby","httpd","nginx","catalina.sh")) AND (Processes.process_name IN ("bash","sh","dash","zsh","ksh")) AND (Processes.process="*/dev/tcp/*" OR Processes.process="*/dev/udp/*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java","node","python","python3","php","php-fpm","ruby","httpd","nginx","catalina.sh")
| where FileName in~ ("bash","sh","dash","zsh","ksh")
| where ProcessCommandLine contains "/dev/tcp/" or ProcessCommandLine contains "/dev/udp/"
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — Controlling your server with a reverse shell attack

`UC_2089_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Controlling your server with a reverse shell attack ```
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
      AND (Filesystem.file_path="*/dev/tcp/127.0.0.1/9001*" OR Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Controlling your server with a reverse shell attack
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
| where (FolderPath has_any ("/dev/tcp/127.0.0.1/9001") or FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-44228`, `CVE-2022-22965`, `CVE-2022-33980`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
