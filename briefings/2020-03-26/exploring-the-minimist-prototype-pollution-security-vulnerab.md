# [CRIT] Exploring the minimist prototype pollution security vulnerability

**Source:** Snyk
**Published:** 2020-03-26
**Article:** https://snyk.io/blog/prototype-pollution-minimist/

## Threat Profile

Snyk Blog In this article
Written by Kirill Efimov 
March 26, 2020
0 mins read On March 11th, 2020, Snyk published a medium severity prototype pollution security vulnerability (CVE-2020-7598) affecting the minimist npm package . This is part of ongoing research by the Snyk security research team which had previously uncovered similar vulnerabilities in other high-profile JavaScript libraries such as lodash and jQuery .
What is a prototype pollution vulnerability? This security vulnerability that…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2020-7598`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1068** — Exploitation for Privilege Escalation
- **T1574.010** — Hijack Execution Flow: Services File Permissions Weakness
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Prototype pollution payload in CLI args (--__proto__ / constructor.prototype) to Node tool

`UC_3392_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process IN ("*--__proto__*","*__proto__.*","*__proto__[*","*constructor.prototype*","*constructor[*prototype*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | where user!="-" | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine matches regex @"(?i)(--?)?(__proto__|constructor\.prototype|constructor\[)"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### World-writable executable run as a shell (-c) — minimist polluted shell privesc payload

`UC_3392_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_path IN ("/tmp/*","/var/tmp/*","/dev/shm/*")) Processes.process="* -c *" by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_path Processes.process | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath matches regex @"^/(tmp|var/tmp|dev/shm)/"
| where ProcessCommandLine matches regex @"^/(tmp|var/tmp|dev/shm)/\S+\s+-c(\s|$)"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          ProcessIntegrityLevel, SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — Exploring the minimist prototype pollution security vulnerability

`UC_3392_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Exploring the minimist prototype pollution security vulnerability ```
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
      AND (Filesystem.file_path="*/tmp/exploit*" OR Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Exploring the minimist prototype pollution security vulnerability
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
| where (FolderPath has_any ("/tmp/exploit") or FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2020-7598`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
