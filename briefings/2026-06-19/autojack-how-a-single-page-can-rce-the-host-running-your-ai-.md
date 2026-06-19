# [CRIT] AutoJack: How a single page can RCE the host running your AI agent

**Source:** Microsoft Security Blog
**Published:** 2026-06-19
**Article:** https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/

## Threat Profile

Content types Research 
Products and services Microsoft Defender 
Topics Actionable threat insights 
AI and agents 
Ongoing research into AI agent framework security identified an exploit chain in AutoGen Studio (AutoGen’s open-source prototyping user interface) that allows untrusted web content rendered by a browsing agent to reach a local Model Context Protocol (MCP) WebSocket and spawn arbitrary processes on the host. The technique, which we call AutoJack, jacks the agent into becoming the at…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1190** — Exploit Public-Facing Application
- **T1199** — Trusted Relationship
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1133** — External Remote Services
- **T1505.003** — Server Software Component: Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AutoGen Studio Python parent spawning shell/LOLBin child (AutoJack RCE outcome)

`UC_10_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","pythonw.exe","autogenstudio.exe","uvicorn.exe") OR Processes.parent_process="*autogenstudio*" OR Processes.parent_process="*autogen_studio*" OR Processes.parent_process="*autogenstudio.web*") AND (Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","calc.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","bash.exe","wsl.exe","sh.exe","node.exe") OR Processes.process IN ("*-EncodedCommand*","*-enc *","*bash -c *","*cmd /c *","*sh -c *")) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process, Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","autogenstudio.exe","uvicorn.exe")
     or InitiatingProcessCommandLine has_any ("autogenstudio","autogen_studio","autogenstudio.web","autogen_studio.web")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","calc.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","bash.exe","wsl.exe","sh.exe")
     or ProcessCommandLine has_any ("-EncodedCommand","-enc ","bash -c","cmd /c","sh -c","powershell -nop","FromBase64String")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256, InitiatingProcessId, ProcessId
| order by Timestamp desc
```

### Loopback WebSocket to AutoGen Studio MCP endpoint (/api/mcp/ws/ on :8081) from headless browser

`UC_10_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("127.0.0.1","::1","localhost") AND All_Traffic.dest_port=8081 AND All_Traffic.app IN ("chrome.exe","chromium.exe","msedge.exe","headless_shell.exe","node.exe","playwright.exe") by All_Traffic.src, All_Traffic.user, All_Traffic.app, All_Traffic.dest, All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | join type=inner src [ | tstats summariesonly=t count from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","pythonw.exe","autogenstudio.exe") OR Processes.parent_process="*autogenstudio*") AND Processes.process_name IN ("chrome.exe","chromium.exe","msedge.exe","headless_shell.exe","node.exe") by Processes.dest | rename Processes.dest as src | fields src ]
```

**Defender KQL:**
```kql
let AgentBrowsers = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","autogenstudio.exe")
         or InitiatingProcessCommandLine has_any ("autogenstudio","autogen_studio","MultimodalWebSurfer","playwright","fetch_webpage")
    | where FileName in~ ("chrome.exe","chromium.exe","msedge.exe","headless_shell.exe","node.exe","playwright.exe")
    | project AgentTime = Timestamp, DeviceId, BrowserProcessId = ProcessId, BrowserImage = FolderPath, AgentParentCmd = InitiatingProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("127.0.0.1","::1") or RemoteUrl in~ ("localhost","127.0.0.1")
| where RemotePort == 8081
| where InitiatingProcessFileName in~ ("chrome.exe","chromium.exe","msedge.exe","headless_shell.exe","node.exe","playwright.exe")
| join kind=inner AgentBrowsers on $left.DeviceId == $right.DeviceId, $left.InitiatingProcessId == $right.BrowserProcessId
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteUrl, AgentParentCmd
| order by Timestamp desc
```

### Vulnerable AutoGen Studio MCP service exposed on loopback (pre-b047730 git build)

`UC_10_7` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("python.exe","pythonw.exe","uvicorn.exe","autogenstudio.exe") AND (Processes.process="*autogenstudio.web*" OR Processes.process="*autogen_studio.web*" OR Processes.process="*-m autogenstudio*" OR Processes.process="*autogenstudio ui*")) by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let McpServers = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("python.exe","pythonw.exe","uvicorn.exe","autogenstudio.exe")
    | where ProcessCommandLine has_any ("autogenstudio.web","autogen_studio.web","-m autogenstudio","autogenstudio ui","autogen_studio ui")
    | summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Cmds = make_set(ProcessCommandLine, 5) by DeviceId, DeviceName, AccountName, FileName;
McpServers
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where LocalPort == 8081 or RemotePort == 8081
    | where LocalIP in ("127.0.0.1","::1","0.0.0.0") or RemoteIP in ("127.0.0.1","::1")
    | summarize ConnCount = count(), DistinctSources = dcount(RemoteIP) by DeviceId
) on DeviceId
| project FirstSeen, LastSeen, DeviceName, AccountName, FileName, Cmds, ConnCount, DistinctSources
| order by LastSeen desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
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

### Article-specific behavioural hunt — AutoJack: How a single page can RCE the host running your AI agent

`UC_10_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — AutoJack: How a single page can RCE the host running your AI agent ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("malicious_web_server.py","web_summarizer_app.py","app.py","bash.exe","wsl.exe","curl.exe","wget.exe","pythonw.exe") OR Processes.process="*-enc *")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("malicious_web_server.py","web_summarizer_app.py","app.py","bash.exe","wsl.exe","curl.exe","wget.exe","pythonw.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — AutoJack: How a single page can RCE the host running your AI agent
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("malicious_web_server.py", "web_summarizer_app.py", "app.py", "bash.exe", "wsl.exe", "curl.exe", "wget.exe", "pythonw.exe") or ProcessCommandLine has_any ("-enc "))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("malicious_web_server.py", "web_summarizer_app.py", "app.py", "bash.exe", "wsl.exe", "curl.exe", "wget.exe", "pythonw.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
