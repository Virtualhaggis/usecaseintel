# [CRIT] [GHSA / CRITICAL] GHSA-9rvc-vf7m-pgm2: FlowiseAI: Authenticated Host RCE via POST /api/v1/node-custom-function and NodeVM Sandbox Escape

**Source:** GitHub Security Advisories
**Published:** 2026-05-14
**Article:** https://github.com/advisories/GHSA-9rvc-vf7m-pgm2

## Threat Profile

FlowiseAI: Authenticated Host RCE via POST /api/v1/node-custom-function and NodeVM Sandbox Escape

### Summary

`POST /api/v1/node-custom-function` lacks route-level authorization, allowing any authenticated user or API key to submit arbitrary JavaScript to the `Custom JS Function` node.

When `E2B_APIKEY` is not configured — the common deployment case — Flowise executes this code inside a `NodeVM` sandbox. This sandbox can be escaped, allowing an attacker to reach the host `process` object and …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.004** — Unix Shell
- **T1059.001** — PowerShell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] FlowiseAI NodeVM Sandbox Escape — POST to /api/v1/node-custom-function

`UC_25_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.user) as user values(Web.status) as status values(Web.src) as src values(Web.http_user_agent) as user_agent from datamodel=Web where Web.http_method=POST Web.url="*/api/v1/node-custom-function*" by Web.dest Web.url
| `drop_dm_object_name(Web)`
| where status="200" OR status="201"
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Defender Advanced Hunting cannot inspect HTTP request paths/bodies for non-Microsoft web apps.
// Fallback: surface inbound connections to a Flowise host (default :3000) so analysts can pivot to proxy/WAF logs.
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("InboundConnectionAccepted","ListeningConnectionCreated")
| where LocalPort == 3000
| where InitiatingProcessFileName in~ ("node.exe","node")
| where InitiatingProcessCommandLine has "flowise"
| project Timestamp, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] Flowise node process spawning OS shell/recon binary (NodeVM escape post-exploitation)

`UC_25_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user values(Processes.parent_process) as parent_cmdline from datamodel=Endpoint.Processes where (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node") Processes.parent_process="*flowise*" (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="sh" OR Processes.process_name="bash" OR Processes.process_name="dash" OR Processes.process_name="zsh" OR Processes.process_name="id" OR Processes.process_name="whoami" OR Processes.process_name="hostname" OR Processes.process_name="uname" OR Processes.process_name="cat" OR Processes.process_name="curl" OR Processes.process_name="wget" OR Processes.process_name="nc" OR Processes.process_name="ncat") by host Processes.dest Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where InitiatingProcessCommandLine has "flowise"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","zsh","id","whoami","hostname","uname","cat","curl","wget","nc","ncat")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256,
          IsInitiatingProcessRemoteSession
| order by Timestamp desc
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

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-9rvc-vf7m-pgm2: FlowiseAI: Authenticated Host RCE via POS

`UC_25_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-9rvc-vf7m-pgm2: FlowiseAI: Authenticated Host RCE via POS ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","poc_flowise_nodecustomfunction_rce_2026.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","poc_flowise_nodecustomfunction_rce_2026.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-9rvc-vf7m-pgm2: FlowiseAI: Authenticated Host RCE via POS
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "poc_flowise_nodecustomfunction_rce_2026.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "poc_flowise_nodecustomfunction_rce_2026.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
