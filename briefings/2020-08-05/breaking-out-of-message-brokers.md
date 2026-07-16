# [CRIT] Breaking out of message brokers

**Source:** Snyk
**Published:** 2020-08-05
**Article:** https://snyk.io/blog/message-brokers/

## Threat Profile

Snyk Blog In this article
Written by Adam Goldschmidt 
August 5, 2020
0 mins read I recently reported two vulnerabilities in Apache Airflow—an open-source library that allows developers to programmatically author, schedule, and monitor workflows. Both of the vulnerabilities allow the attacker to change scope and gain privileges for a different machine, and they both rely on the attacker gaining access to the message broker before performing the attack.
In this blog post, I aim to show you why me…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2020-11982`
- **CVE:** `CVE-2020-11981`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1053.005** — Scheduled Task
- **T1204.002** — User Execution: Malicious File
- **T1059** — Command and Scripting Interpreter
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.006** — Command and Scripting Interpreter: Python

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Celery task injected into Apache Airflow message broker (unacked queue / execute_command)

`UC_3300_3` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*lpush*" OR Processes.process="*rpush*" OR Processes.process="*hset*" OR Processes.process="*hmset*" OR Processes.process="*amqp-publish*" OR Processes.process="*basic_publish*") (Processes.process="*celery*" OR Processes.process="*unacked*" OR Processes.process="*execute_command*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where ProcessCommandLine has_any ("lpush","rpush","hset","hmset","amqp-publish","basic_publish")
| where ProcessCommandLine has_any ("celery","unacked","celery_executor.execute_command","execute_command")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Apache Airflow Celery worker spawns non-airflow child (command-injection RCE, CVE-2020-11981)

`UC_3300_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.parent_process="*celery*" Processes.parent_process="*worker*") OR (Processes.parent_process="*airflow*" Processes.parent_process="*worker*")) (Processes.process_name="sh" OR Processes.process_name="bash" OR Processes.process_name="dash" OR Processes.process_name="zsh" OR Processes.process_name="nc" OR Processes.process_name="ncat" OR Processes.process_name="netcat" OR Processes.process_name="socat" OR Processes.process_name="curl" OR Processes.process_name="wget" OR Processes.process_name="perl" OR Processes.process_name="ruby") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | search NOT (process="*airflow tasks run*" OR process="*airflow run*") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (InitiatingProcessCommandLine has_all ("celery","worker")) or (InitiatingProcessCommandLine has_all ("airflow","worker"))
| where (FileName in~ ("sh","bash","dash","zsh","nc","ncat","netcat","socat","curl","wget","perl","ruby"))
     or (FileName in~ ("python","python3") and ProcessCommandLine has "-c")
| where not (ProcessCommandLine has "airflow tasks run" or ProcessCommandLine has "airflow run")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Apache Airflow task run with --pickle flag (pickle deserialization, CVE-2020-11982)

`UC_3300_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*airflow*" Processes.process="*--pickle*" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "airflow"
| where ProcessCommandLine has "--pickle"
| where ProcessCommandLine has_any ("run","tasks run")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Hosts exposed to Apache Airflow Celery broker RCE (CVE-2020-11981 / CVE-2020-11982)

`UC_3300_6` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.cve="CVE-2020-11981" OR Vulnerabilities.cve="CVE-2020-11982") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.signature Vulnerabilities.severity | `drop_dm_object_name(Vulnerabilities)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2020-11981","CVE-2020-11982")
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
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

### Article-specific behavioural hunt — Breaking out of message brokers

`UC_3300_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Breaking out of message brokers ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/passwd*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Breaking out of message brokers
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/passwd"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2020-11982`, `CVE-2020-11981`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
