# [HIGH] Claude Code RCE Flaw Lets Attackers Execute Commands via Malicious Deeplinks

**Source:** Cyber Security News
**Published:** 2026-05-18
**Article:** https://cybersecuritynews.com/claude-code-rce-flaw/

## Threat Profile

Home Cyber Security News 
Claude Code RCE Flaw Lets Attackers Execute Commands via Malicious Deeplinks 
By Guru Baran 
May 18, 2026 
A critical remote code execution (RCE) vulnerability has been discovered in Anthropic’s Claude Code CLI tool , allowing attackers to execute arbitrary commands on a victim’s machine by tricking them into clicking a specially crafted deeplink.
The flaw, now patched in Claude Code version 2.1.118, was rooted in a naive command-line argument parser that could be weapo…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1219** — Remote Access Software
- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1546** — Event Triggered Execution
- **T1204.001** — User Execution: Malicious Link
- **T1190** — Exploit Public-Facing Application
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1033** — System Owner/User Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Claude Code launched with injected --settings hooks/SessionStart payload (deeplink RCE)

`UC_14_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE (Processes.process_name IN ("claude","claude.exe","claude.cmd","node","node.exe")) AND Processes.process="*--prefill*" AND Processes.process="*--settings=*" AND Processes.process="*hooks*" AND Processes.process="*SessionStart*" BY Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.process_hash | `drop_dm_object_name(Processes)` | eval is_inline_json=if(match(process,"--settings=\\{"),1,0) | where is_inline_json=1 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("claude.exe","claude","claude.cmd","node.exe","node")
| where ProcessCommandLine has "prefill"
| where ProcessCommandLine has "settings"
| where ProcessCommandLine has "hooks"
| where ProcessCommandLine has "SessionStart"
| where ProcessCommandLine contains "--settings={" or ProcessCommandLine contains "--settings=%7B" or ProcessCommandLine matches regex @"(?i)--settings\s*=\s*\{"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Claude Code parent spawns shell with PoC-style recon/file-write at session startup

`UC_14_3` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE (Processes.parent_process_name IN ("claude","claude.exe","claude.cmd","node","node.exe")) AND (Processes.process_name IN ("bash","bash.exe","sh","zsh","cmd.exe","powershell.exe","pwsh","pwsh.exe")) AND (Processes.process="*-c *" OR Processes.process="*/c *" OR Processes.process="*-Command *" OR Processes.process="*-EncodedCommand*") AND (Processes.process="*id*" OR Processes.process="*whoami*" OR Processes.process="*/tmp/*" OR Processes.process="*\\Temp\\*" OR Processes.process="*curl *" OR Processes.process="*wget *" OR Processes.process="*nslookup *" OR Processes.process="*base64*") BY Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _claude_parents = dynamic(["claude.exe","claude","claude.cmd","node.exe","node"]);
let _shells = dynamic(["bash.exe","bash","sh","zsh","cmd.exe","powershell.exe","pwsh.exe","pwsh"]);
let ClaudeLaunches =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ _claude_parents
    | project ClaudeTime = Timestamp, DeviceId, ClaudePid = ProcessId,
              ClaudeName = FileName, ClaudeCmd = ProcessCommandLine;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ _claude_parents
| where FileName in~ _shells
| where ProcessCommandLine has_any ("-c ","/c ","-Command","-EncodedCommand","-enc ")
| where ProcessCommandLine has_any ("id","whoami","uname","/tmp/",@"\Temp\","curl","wget","nslookup","base64","cat /etc/","~/.ssh",@"\Users\Public\")
| join kind=inner ClaudeLaunches on $left.DeviceId == $right.DeviceId, $left.InitiatingProcessId == $right.ClaudePid
| extend SecondsAfterClaudeLaunch = datetime_diff('second', Timestamp, ClaudeTime)
| where SecondsAfterClaudeLaunch between (0 .. 30)
| project Timestamp, DeviceName, AccountName, SecondsAfterClaudeLaunch, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ClaudeCmd
| order by Timestamp desc
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — Claude Code RCE Flaw Lets Attackers Execute Commands via Malicious Deeplinks

`UC_14_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Claude Code RCE Flaw Lets Attackers Execute Commands via Malicious Deeplinks ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/pwned.txt*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Claude Code RCE Flaw Lets Attackers Execute Commands via Malicious Deeplinks
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/pwned.txt"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
