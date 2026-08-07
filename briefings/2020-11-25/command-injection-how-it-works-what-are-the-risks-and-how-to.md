# [HIGH] Command injection: how it works, what are the risks, and how to prevent it

**Source:** Snyk
**Published:** 2020-11-25
**Article:** https://snyk.io/blog/command-injection/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
November 25, 2020
0 mins read Command injection attacks—also known as operating system command injection attacks—exploit a programming flaw to execute system commands without proper input validation, escaping, or sanitization, which may lead to arbitrary commands executed by a malicious attacker.
What are the risks of command injections? Depending on the setup of the application and the process configuration that executes it, a command injection vu…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### systeminformation inetChecksite curl argument injection (CVE-2020-7752)

`UC_3268_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*--connect-timeout 5 -m 5*" (Processes.process="* -o *" OR Processes.process="* -O *" OR Processes.process="* --output *" OR Processes.process="* -T *" OR Processes.process="* --upload-file *" OR Processes.process="* -K *" OR Processes.process="* --config *" OR Processes.process="* -d *" OR Processes.process="* --data *") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine contains "--connect-timeout 5 -m 5"   // systeminformation inetChecksite hardcoded curl args
| where ProcessCommandLine matches regex @"(?i)(?:^|\s)(?:-o|-O|-T|-K|--output|--upload-file|--config|-d|--data)\b"   // injected curl flag absent from the legitimate command
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Arbitrary child process from systeminformation inetChecksite shell pipeline

`UC_3268_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process="*--connect-timeout 5 -m 5*" NOT (Processes.process_name IN ("curl","head","cut","sh","bash","dash")) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessCommandLine contains "--connect-timeout 5 -m 5"   // parent shell = inetChecksite curl pipeline
| where FileName !in~ ("curl","head","cut","sh","bash","dash")           // expected pipeline members; any other child = injected command
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — Command injection: how it works, what are the risks, and how to prevent it

`UC_3268_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Command injection: how it works, what are the risks, and how to prevent it ```
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
      AND (Filesystem.file_path="*/dev/null*" OR Filesystem.file_path="*/tmp/abc*" OR Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Command injection: how it works, what are the risks, and how to prevent it
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
| where (FolderPath has_any ("/dev/null", "/tmp/abc") or FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
