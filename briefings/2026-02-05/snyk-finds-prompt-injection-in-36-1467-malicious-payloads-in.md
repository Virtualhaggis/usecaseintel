# [CRIT] Snyk Finds Prompt Injection in 36%, 1467 Malicious Payloads in a ToxicSkills Study of Agent Skills Supply Chain Compromise

**Source:** Snyk
**Published:** 2026-02-05
**Article:** https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/

## Threat Profile

Snyk Blog In this article
Written by Luca Beurer-Kellner 
Aleksei Kudrinskii 
Marco Milanta 
Kristian Bonde Nielsen 
Hemang Sarkar 
Liran Tal 
February 5, 2026
0 mins read The first comprehensive security audit of the Agent Skills ecosystem reveals malware, credential theft, and prompt injection attacks targeting OpenClaw, Claude Code, and Cursor users 
Agent skills are reusable capability packages that instruct AI agents how to interact with tools, APIs, or system resources—and they're rapidly …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Supply Chain
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1105** — Ingress Tool Transfer
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Dev endpoint contacts ClawHub / skills.sh agent-skill marketplace

`UC_690_3` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="*clawhub.ai*" OR All_Traffic.dest="*skills.sh*" OR All_Traffic.dest="*skillsmp*") by All_Traffic.src All_Traffic.app All_Traffic.dest_port All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("clawhub.ai","skills.sh","skillsmp")
| where InitiatingProcessFileName in~ ("node","node.exe","claude","claude.exe","cursor","cursor.exe","openclaw","openclaw.exe","curl","curl.exe","wget","powershell.exe","pwsh")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### AI coding agent spawns remote fetch-and-execute (curl | bash / curl | source)

`UC_690_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node","node.exe","claude","claude.exe","cursor","cursor.exe","openclaw","openclaw.exe")) AND (Processes.process="*curl*" OR Processes.process="*wget*" OR Processes.process="*Invoke-WebRequest*" OR Processes.process="*iwr *") AND (Processes.process="*| bash*" OR Processes.process="*|bash*" OR Processes.process="*| sh*" OR Processes.process="*|sh*" OR Processes.process="*| source*" OR Processes.process="*|source*" OR Processes.process="*| zsh*" OR Processes.process="*Invoke-Expression*" OR Processes.process="*| iex*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node","node.exe","claude","claude.exe","cursor","cursor.exe","openclaw","openclaw.exe")
| where ProcessCommandLine has_any ("curl","wget","Invoke-WebRequest","iwr ")
| where ProcessCommandLine has_any ("|bash","| bash","|sh","| sh","| source","|source","| zsh","Invoke-Expression","| iex","|iex")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### AI agent skill exfiltrates GitHub token / env secrets via dynamic-context shell-out

`UC_690_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node","node.exe","claude","claude.exe","cursor","cursor.exe","openclaw","openclaw.exe","bash","sh","zsh","cmd.exe","powershell.exe","pwsh")) AND (Processes.process="*gh auth token*" OR Processes.process="*printenv*" OR Processes.process="*process.env*" OR Processes.process="*os.environ*" OR Processes.process="*cat .env*" OR Processes.process="*type .env*" OR Processes.process="*id_rsa*" OR Processes.process="*id_ed25519*" OR Processes.process="*.aws/credentials*" OR Processes.process="*.aws\\credentials*" OR Processes.process="*wallet.dat*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node","node.exe","claude","claude.exe","cursor","cursor.exe","openclaw","openclaw.exe","bash","sh","zsh","cmd.exe","powershell.exe","pwsh")
| where ProcessCommandLine has_any ("gh auth token","printenv","process.env","os.environ","cat .env","type .env","id_rsa","id_ed25519",".aws/credentials",".aws\\credentials","wallet.dat","Login Data")
| where AccountName !endswith "$"
| extend ExfilContext = iff(ProcessCommandLine has_any ("curl","wget","Invoke-RestMethod","--data-binary","-X POST","nc "), "inline-exfil", "read-only")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, ExfilContext, InitiatingProcessCommandLine
| order by Timestamp desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — Snyk Finds Prompt Injection in 36%, 1467 Malicious Payloads in a ToxicSkills Stu

`UC_690_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Snyk Finds Prompt Injection in 36%, 1467 Malicious Payloads in a ToxicSkills Stu ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("skills.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("skills.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Snyk Finds Prompt Injection in 36%, 1467 Malicious Payloads in a ToxicSkills Stu
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("skills.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("skills.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 6 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
