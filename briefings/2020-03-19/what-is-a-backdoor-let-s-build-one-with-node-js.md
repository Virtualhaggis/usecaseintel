# [HIGH] What is a backdoor? Let’s build one with Node.js

**Source:** Snyk
**Published:** 2020-03-19
**Article:** https://snyk.io/blog/what-is-a-backdoor/

## Threat Profile

Snyk Blog In this article
Written by Ulises Gascón 
March 19, 2020
0 mins read A backdoor in our code that can perform OS injection is one of the most scary scenarios ever. Currently, npm has more than 1.2M of public packages available. For the last three years, our dependencies have become the perfect target for cybercriminals. We saw many new attacks going live, like typosquatting attack or event-stream incident , confirming that our ecosystem can be very fragile if we don’t build a stronger c…

## Indicators of Compromise (high-fidelity only)

- **MD5:** `c4fbb68607bcbb25407e0362dab0b2ea`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1505.003** — Server Software Component: Web Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Node.js process spawning OS command shell (child_process.exec backdoor)

`UC_3098_2` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="node.exe" AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","whoami.exe","whoami","id","cat","type.exe","ipconfig.exe","hostname.exe","net.exe","net1.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe" or InitiatingProcessFileName =~ "node"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","whoami.exe","whoami","id","cat","type.exe","ipconfig.exe","hostname.exe","net.exe","net1.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Inbound web request to Node app with ?cmd= command-injection backdoor parameter

`UC_3098_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*cmd=whoami*" OR Web.url="*cmd=cat*" OR Web.url="*cmd=id*" OR Web.url="*cmd=ipconfig*" OR Web.url="*cmd=net*" OR Web.url="*cmd=type*" OR Web.url="*cmd=.env*" OR Web.url="*cmd=cat+.env*") by Web.src Web.dest Web.http_method Web.url Web.http_user_agent Web.status | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

### Installation of malicious npm package 'browser-redirect' (supply-chain backdoor)

`UC_3098_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.cmd","npm.exe","npm","yarn.cmd","yarn","pnpm.cmd","pnpm","node.exe","node")) AND Processes.process="*browser-redirect*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "browser-redirect"
| where ProcessCommandLine has_any ("install","add","ci","i ") or InitiatingProcessFileName has_any ("npm","node","yarn","pnpm")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Article-specific behavioural hunt — What is a backdoor? Let’s build one with Node.js

`UC_3098_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — What is a backdoor? Let’s build one with Node.js ```
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
// Article-specific bespoke detection — What is a backdoor? Let’s build one with Node.js
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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c4fbb68607bcbb25407e0362dab0b2ea`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
