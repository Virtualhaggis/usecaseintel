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
- **T1059** — Command and Scripting Interpreter
- **T1203** — Exploitation for Client Execution
- **T1190** — Exploit Public-Facing Application
- **T1559** — Inter-Process Communication
- **T1566.002** — Phishing: Spearphishing Link
- **T1185** — Browser Session Hijacking

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AutoGen Studio agent (python) spawns shell/LOLBin as 'MCP server' (AutoJack RCE)

`UC_112_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process="*autogenstudio*" OR (Processes.parent_process="*autogen*" AND Processes.parent_process="*mcp*")) AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wsl.exe","calc.exe","mshta.exe","certutil.exe","curl.exe","wget.exe","regsvr32.exe","rundll32.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| search NOT (process="*modelcontextprotocol*" OR process="*mcp-server*")
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessCommandLine has "autogenstudio" or (InitiatingProcessCommandLine has "autogen" and InitiatingProcessCommandLine has "mcp")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wsl.exe","calc.exe","mshta.exe","certutil.exe","curl.exe","wget.exe","regsvr32.exe","rundll32.exe")
| where AccountName !endswith "$"
| where not (ProcessCommandLine has_any ("modelcontextprotocol","mcp-server","@modelcontextprotocol"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ChildBinary = FileName, ChildCmd = ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Loopback WebSocket to AutoGen MCP control plane carrying server_params (AutoJack)

`UC_112_6` · phase: **delivery** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=8081 (All_Traffic.dest IN ("127.0.0.1","::1") OR All_Traffic.dest="localhost") (All_Traffic.app IN ("python.exe","pythonw.exe") OR All_Traffic.process_name IN ("python.exe","pythonw.exe")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort == 8081
| where RemoteIP in ("127.0.0.1","::1") or RemoteUrl has_any ("127.0.0.1","localhost")
| where InitiatingProcessCommandLine has "autogenstudio" or InitiatingProcessCommandLine has_any ("MultimodalWebSurfer","playwright","fetch_webpage") or InitiatingProcessFileName in~ ("python.exe","pythonw.exe")
| where RemoteUrl has_any ("server_params","/api/mcp/ws")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### AutoJack confused-deputy: agent fetches external page then hits local MCP :8081

`UC_112_7` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app IN ("python.exe","pythonw.exe") OR All_Traffic.process_name IN ("python.exe","pythonw.exe")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port _time span=2m
| `drop_dm_object_name(All_Traffic)`
| eval is_loopback=if((dest IN ("127.0.0.1","::1") AND dest_port=8081),1,0)
| eval is_external=if((NOT (cidrmatch("10.0.0.0/8",dest) OR cidrmatch("192.168.0.0/16",dest) OR cidrmatch("172.16.0.0/12",dest) OR cidrmatch("127.0.0.0/8",dest))) AND dest_port!=8081,1,0)
| stats sum(is_loopback) as loopback_hits sum(is_external) as external_hits values(dest) as dests by src _time
| where loopback_hits>0 AND external_hits>0
| sort - _time
```

**Defender KQL:**
```kql
let Window = 120s;
let Loopback = DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemotePort == 8081 and RemoteIP in ("127.0.0.1","::1")
    | where InitiatingProcessFileName in~ ("python.exe","pythonw.exe") or InitiatingProcessCommandLine has "autogenstudio"
    | project LoopbackTime = Timestamp, DeviceId, InitiatingProcessId, AgentCmd = InitiatingProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe") or InitiatingProcessCommandLine has_any ("autogenstudio","MultimodalWebSurfer","playwright","fetch_webpage")
| join kind=inner Loopback on DeviceId, InitiatingProcessId
| where LoopbackTime between (Timestamp .. Timestamp + Window)
| project ExternalFetchTime = Timestamp, LoopbackTime, DelaySec = datetime_diff('second', LoopbackTime, Timestamp), DeviceName, ExternalIP = RemoteIP, ExternalUrl = RemoteUrl, AgentCmd
| order by ExternalFetchTime desc
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

`UC_112_4` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 8 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
