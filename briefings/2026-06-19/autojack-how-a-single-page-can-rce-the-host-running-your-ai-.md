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
- **T1190** — Exploit Public-Facing Application
- **T1559** — Inter-Process Communication
- **T1059.003** — Windows Command Shell
- **T1505.003** — Web Shell
- **T1199** — Trusted Relationship
- **T1204.001** — Malicious Link

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Headless browser / Playwright child of autogenstudio connecting to localhost:8081

`UC_26_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("chrome.exe","msedge.exe","chromium.exe","playwright.exe","headless_shell.exe","node.exe") AND (Processes.parent_process_name IN ("python.exe","pythonw.exe","autogenstudio.exe") OR Processes.process=*MultimodalWebSurfer* OR Processes.process=*playwright* OR Processes.process=*--remote-debugging-port*) by host Processes.process_name Processes.parent_process_name Processes.user | `drop_dm_object_name(Processes)` | join type=inner host [| tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("127.0.0.1","::1") AND All_Traffic.dest_port IN (8081,8080,8000) by host All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let AgentBrowsers = DeviceProcessEvents
    | where Timestamp > ago(LookbackDays)
    | where FileName in~ ("chrome.exe","msedge.exe","chromium.exe","playwright.exe","headless_shell.exe","node.exe")
    | where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","autogenstudio.exe")
         or ProcessCommandLine has_any ("playwright","--remote-debugging-port","MultimodalWebSurfer","autogen","headless")
    | project ProcTime = Timestamp, DeviceId, DeviceName, AccountName,
              BrowserProc = FileName, BrowserCmd = ProcessCommandLine,
              AgentParent = InitiatingProcessFileName, AgentParentCmd = InitiatingProcessCommandLine,
              BrowserPid = ProcessId;
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where RemoteIP in ("127.0.0.1","::1")
| where RemotePort in (8081, 8080, 8000)
| where AccountName !endswith "$"
| join kind=inner AgentBrowsers on DeviceId
| where Timestamp between (ProcTime .. ProcTime + 2h)
| project Timestamp, DeviceName, AccountName, BrowserProc, BrowserCmd,
          AgentParent, AgentParentCmd, RemoteIP, RemotePort
| order by Timestamp desc
```

### AutoGen Studio Python parent spawning shell / LOLBin child (StdioServerParams RCE)

`UC_26_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_name) as child from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python.exe","pythonw.exe","autogenstudio.exe") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","wsl.exe","calc.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe") AND (Processes.parent_process=*autogenstudio* OR Processes.parent_process=*autogen* OR Processes.parent_process=*ui.app* OR Processes.parent_process=*uvicorn*) by host Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","autogenstudio.exe")
| where InitiatingProcessCommandLine has_any ("autogenstudio","autogen_agentchat","autogen_ext","ui.app","uvicorn","mcp")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","wsl.exe","calc.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### HTTP request to /api/mcp/ws/ endpoint with server_params query parameter (AutoJack payload)

`UC_26_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.src) as src from datamodel=Web.Web where Web.url="*/api/mcp/ws/*" AND Web.url="*server_params=*" by host Web.dest Web.user | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has "/api/mcp/ws/"
   and RemoteUrl has "server_params="
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### AutoGen agent external web fetch followed by localhost MCP port connection (time-correlation)

`UC_26_8` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as externalTime values(All_Traffic.dest) as externalDest from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (80,443,8443) AND NOT (All_Traffic.dest IN ("127.0.0.1","::1","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")) AND All_Traffic.process_name IN ("python.exe","pythonw.exe","chrome.exe","msedge.exe","chromium.exe","playwright.exe","headless_shell.exe") by host All_Traffic.user | `drop_dm_object_name(All_Traffic)` | join type=inner host [| tstats `summariesonly` count min(_time) as loopbackTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("127.0.0.1","::1") AND All_Traffic.dest_port IN (8081,8080,8000) by host | `drop_dm_object_name(All_Traffic)`] | where loopbackTime >= externalTime AND loopbackTime <= externalTime + 60 | `security_content_ctime(externalTime)` | `security_content_ctime(loopbackTime)`
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowSeconds = 60;
let ExternalFetch = DeviceNetworkEvents
    | where Timestamp > ago(LookbackDays)
    | where RemotePort in (80, 443, 8443)
    | where RemoteIPType == "Public"
    | where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","chrome.exe","msedge.exe","chromium.exe","playwright.exe","headless_shell.exe","node.exe")
    | where InitiatingProcessCommandLine has_any ("autogenstudio","autogen","MultimodalWebSurfer","fetch_webpage","playwright","--remote-debugging-port")
         or InitiatingProcessParentFileName in~ ("python.exe","pythonw.exe","autogenstudio.exe")
    | project ExternalTime = Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName,
              ExternalUrl = RemoteUrl, ExternalIP = RemoteIP,
              AgentProc = InitiatingProcessFileName, AgentCmd = InitiatingProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where RemoteIP in ("127.0.0.1","::1")
| where RemotePort in (8081, 8080, 8000)
| join kind=inner ExternalFetch on DeviceId
| where Timestamp between (ExternalTime .. ExternalTime + WindowSeconds * 1s)
| extend DelaySec = datetime_diff('second', Timestamp, ExternalTime)
| project ExternalTime, LoopbackTime = Timestamp, DelaySec,
          DeviceName, InitiatingProcessAccountName, ExternalUrl, ExternalIP,
          AgentProc, AgentCmd, LoopbackPort = RemotePort
| order by ExternalTime desc
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

`UC_26_4` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 9 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
