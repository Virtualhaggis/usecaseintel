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
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059** — Command and Scripting Interpreter
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SKILL.md written to ~/.claude/skills/ or ~/.openclaw/skills/ (agent-skill install)

`UC_565_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_name="SKILL.md" (Filesystem.file_path="*\\.claude\\skills\\*" OR Filesystem.file_path="*\\.openclaw\\skills\\*" OR Filesystem.file_path="*/.claude/skills/*" OR Filesystem.file_path="*/.openclaw/skills/*" OR Filesystem.file_path="*\\.cursor\\skills\\*" OR Filesystem.file_path="*/.cursor/skills/*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where match(process_name, "(?i)^(claude|cursor|code|git|curl|wget|pwsh|powershell|bash|sh|zsh)(\.exe)?$") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName =~ "SKILL.md"
| where FolderPath has_any (@"\.claude\skills\", @"\.openclaw\skills\", @"\.cursor\skills\", "/.claude/skills/", "/.openclaw/skills/", "/.cursor/skills/")
| where InitiatingProcessFileName has_any ("claude.exe", "claude", "cursor.exe", "cursor", "code.exe", "git.exe", "git", "curl.exe", "curl", "wget.exe", "wget", "pwsh.exe", "powershell.exe", "bash", "sh", "zsh")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### curl | bash or wget | sh executed by Claude/Cursor/OpenClaw agent process

`UC_565_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("claude","claude.exe","cursor","cursor.exe","code","code.exe","openclaw","openclaw.exe") OR Processes.parent_process IN ("*claude*","*cursor*","*openclaw*")) Processes.process_name IN ("bash","sh","zsh","pwsh.exe","powershell.exe") (Processes.process="*curl*|*bash*" OR Processes.process="*curl*|*sh*" OR Processes.process="*wget*|*bash*" OR Processes.process="*wget*|*sh*" OR Processes.process="*iwr*iex*" OR Processes.process="*Invoke-WebRequest*Invoke-Expression*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("claude.exe", "claude", "cursor.exe", "cursor", "code.exe", "openclaw.exe", "openclaw")
   or InitiatingProcessParentFileName has_any ("claude.exe", "cursor.exe", "code.exe", "openclaw.exe")
| where FileName in~ ("bash", "bash.exe", "sh", "zsh", "pwsh.exe", "powershell.exe", "cmd.exe")
| where ProcessCommandLine matches regex @"(?i)(curl|wget)\s+[^|]*\|\s*(bash|sh|zsh)"
   or ProcessCommandLine matches regex @"(?i)(Invoke-WebRequest|iwr|curl)\s+[^|]+\s*\|\s*(Invoke-Expression|iex)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### AI agent process reads cloud-credential, SSH or dotenv files (skill credential theft)

`UC_565_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem where Filesystem.action=read (Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*\\.aws\\credentials" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*\\.ssh\\id_*" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*\\.npmrc" OR Filesystem.file_path="*/.netrc" OR Filesystem.file_path="*\\.netrc" OR Filesystem.file_name=".env" OR Filesystem.file_path="*/.config/gh/hosts.yml" OR Filesystem.file_path="*\\.gitconfig") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where match(process_name, "(?i)^(claude|cursor|code|openclaw|bash|sh|zsh|pwsh|powershell)(\.exe)?$") | sort - count
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileAccessed", "FileCreated", "FileModified")
| where FileName in~ ("credentials", "config", ".npmrc", ".netrc", ".env", "id_rsa", "id_ed25519", "id_ecdsa", "hosts.yml", ".gitconfig")
   or FolderPath has_any (@"\.aws\", @"\.ssh\", "/.aws/", "/.ssh/", "/.config/gh/")
| where InitiatingProcessFileName has_any ("claude.exe", "claude", "cursor.exe", "cursor", "code.exe", "openclaw.exe", "openclaw")
   or InitiatingProcessParentFileName has_any ("claude.exe", "cursor.exe", "code.exe", "openclaw.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FolderPath, FileName
| order by Timestamp desc
```

### Outbound connection to clawhub.ai or skills.sh from CLI agent (skill marketplace fetch)

`UC_565_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as process_name from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="*clawhub.ai*" OR All_Traffic.dest="*skills.sh*") by All_Traffic.src All_Traffic.user All_Traffic.app | `drop_dm_object_name(All_Traffic)` | where match(process_name, "(?i)(claude|cursor|code|openclaw|curl|wget|git|pwsh|powershell|python|node)(\.exe)?$") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("clawhub.ai", "skills.sh")
| where InitiatingProcessFileName has_any ("claude.exe", "claude", "cursor.exe", "cursor", "code.exe", "openclaw.exe", "openclaw", "curl.exe", "curl", "wget.exe", "wget", "git.exe", "pwsh.exe", "powershell.exe", "python.exe", "python", "node.exe", "node")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "safari")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Prompt-injection markers (base64, Unicode tags, 'ignore previous instructions') in SKILL.md content

`UC_565_7` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.process_name) as process_name values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") Filesystem.file_name="SKILL.md" by Filesystem.dest Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)` | join type=inner file_hash [search index=* sourcetype IN ("file:content","yara:scan") (content="*ignore previous instructions*" OR content="*ignore all previous*" OR content="*<system>*" OR content="*</system>*" OR content="*disregard prior*" OR content="*[U+E0000]*" OR content="*base64*decode*") | fields file_hash content] | sort - count
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FileName =~ "SKILL.md"
| where FolderPath has_any (@"\.claude\skills\", @"\.openclaw\skills\", @"\.cursor\skills\", "/.claude/skills/", "/.openclaw/skills/", "/.cursor/skills/")
| extend Extra = tostring(AdditionalFields)
| where Extra matches regex @"(?i)(ignore\s+(all\s+)?previous\s+instructions|disregard\s+(all\s+)?prior|</?system>|</?assistant>|\[INST\]|<\|im_start\|>)"
   or Extra contains "\U000E0000"
   or Extra matches regex @"[A-Za-z0-9+/]{200,}={0,2}"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, SHA256, Extra
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

`UC_565_2` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
