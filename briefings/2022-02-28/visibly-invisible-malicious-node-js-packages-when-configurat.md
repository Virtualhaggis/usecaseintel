# [HIGH] Visibly invisible malicious Node.js packages: When configuration niche meets invisible characters

**Source:** Snyk
**Published:** 2022-02-28
**Article:** https://snyk.io/blog/visibly-invisible-malicious-node-js-packages-when-configuration-niche-meets-invisible-characters/

## Threat Profile

Snyk Blog In this article
Written by Aviad Hahami 
February 28, 2022
0 mins read We’ve seen a massive increase in the number of open source packages created and used in the wild during the past few years. These days every ecosystem has its package manager, and almost every package manager has its hidden gems and configurations.
That said, as developers continuously install an ever-expanding number of packages, attackers gain interest in the packages’ attack surfaces. Then, the journey to craft t…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1036.009** — Masquerading: Break Process Trees / Invalid Code Signature (filename masquerade)
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### npm/yarn install spawning anomalous shell or working-dir binary (.npmrc/.yarnrc config override RCE)

`UC_2607_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","node","npm.cmd","yarn.cmd","npm","yarn","npm.exe","yarn.exe")) (Processes.parent_process IN ("*install*","*npm ci*","*yarn*","*yarnpkg*")) (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","bash","sh","dash","zsh","wscript.exe","cscript.exe","mshta.exe") OR Processes.process_path IN ("*\\Downloads\\*","*\\source\\repos\\*","*\\git\\*","/tmp/*","/var/tmp/*")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process_path Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | where NOT match(user,"\$$")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe","node","npm.cmd","yarn.cmd","npm","yarn","npm.exe","yarn.exe")
| where InitiatingProcessCommandLine has_any ("install","npm ci","yarn","yarnpkg")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","bash","sh","dash","zsh","wscript.exe","cscript.exe","mshta.exe")
      or FolderPath has_any (@"\Downloads\", @"\source\repos\", "/tmp/", "/var/tmp/")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### File dropped with invisible Unicode in its name (Hangul Filler U+3164 masquerading)

`UC_2607_2` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | regex file_name="[\x{3164}\x{ffa0}\x{200b}-\x{200f}\x{202a}-\x{202e}\x{2060}\x{2066}-\x{2069}\x{feff}]" | where NOT match(user,"\$$")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName matches regex @"[\x{3164}\x{ffa0}\x{200b}-\x{200f}\x{202a}-\x{202e}\x{2060}\x{2066}-\x{2069}\x{feff}]"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — Visibly invisible malicious Node.js packages: When configuration niche meets inv

`UC_2607_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Visibly invisible malicious Node.js packages: When configuration niche meets inv ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","evil.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","evil.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Visibly invisible malicious Node.js packages: When configuration niche meets inv
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "evil.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "evil.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
