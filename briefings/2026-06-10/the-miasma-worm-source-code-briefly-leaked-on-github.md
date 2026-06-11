# [HIGH] The ‘Miasma’ worm source code briefly leaked on GitHub

**Source:** BleepingComputer
**Published:** 2026-06-10
**Article:** https://www.bleepingcomputer.com/news/security/the-miasma-worm-source-code-briefly-leaked-on-github/

## Threat Profile

The ‘Miasma’ worm source code briefly leaked on GitHub 
By Bill Toulas 
June 10, 2026
04:27 PM
0 
The Miasma credential-stealing attack framework, which has recently targeted open-source ecosystems through supply-chain attacks, was briefly open-sourced on GitHub.
Miasma appears to be an evolution of the earlier Shai-Hulud worm, which was previously leaked on GitHub and shares much of the same features, techniques, and even code.
The malware infects a developer machine, steals the build environme…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `396cac9e457ec54ff6d3f6311cb5cc1da8054d019ce3ffa1de5741506c7a4ea4`
- **SHA256:** `d8d170af3de17bb9b217c52aaaffdf9395f35ef015a57ef676e406c121e5e223`
- **SHA256:** `f0641e053e81f0d01fa46db35a83e0a34494886503086866d956d14e81fd3e1c`
- **SHA256:** `d5a97614d5319ce9c8e01fa0b4eb06fb5b9e54fa13b23d718174a1546444123b`
- **SHA256:** `f88258e21592084a2f93a572ade8f9b91c0cd0e242f5cf6121ed7bad0f7bdd1f`
- **SHA256:** `25e121e3b7d300c0d0075b33e5eca39a3e6a659fb9cfee52b70ef71686628f1b`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1485** — Data Destruction
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1554** — Compromise Host Software Binary
- **T1546** — Event Triggered Execution
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555.005** — Credentials from Password Managers: Password Managers
- **T1552.007** — Unsecured Credentials: Container API
- **T1528** — Steal Application Access Token
- **T1567.001** — Exfiltration Over Web Service: Exfiltration to Code Repository
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1567** — Exfiltration Over Web Service
- **T1021.007** — Remote Services: Cloud Services
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Miasma dead-man switch — `rm -rf ~/; rm -rf ~/Documents` from systemd user service or launchd

`UC_37_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name=rm AND (Processes.process="*rm -rf ~/*" OR Processes.process="*rm -rf $HOME*" OR Processes.process="*rm -rf ~/Documents*") AND Processes.parent_process_name IN (systemd, "systemd --user", launchd, launchctl, init) by host Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceInfo has_any ("Linux","macOS") or FileName =~ "rm"
| where FileName =~ "rm"
| where ProcessCommandLine has "-rf"
| where ProcessCommandLine has_any ("~/","$HOME","~/Documents")
| where InitiatingProcessFileName in~ ("systemd","launchd","launchctl","init")
   or InitiatingProcessParentFileName in~ ("systemd","launchd")
| project Timestamp, DeviceName, AccountName,
          ProcessCommandLine,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          GrandparentName = InitiatingProcessParentFileName
| order by Timestamp desc
```

### Systemd user service or LaunchAgent dropped by node / npm / pip / gem

`UC_37_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as writers from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.config/systemd/user/*.service" OR Filesystem.file_path="*/Library/LaunchAgents/*.plist") AND Filesystem.process_name IN (node, npm, pnpm, yarn, bun, python, python3, pip, pip3, ruby, gem, sh, bash, zsh, curl, wget) by host Filesystem.user Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has "/.config/systemd/user/" and FileName endswith ".service")
   or (FolderPath has "/Library/LaunchAgents/" and FileName endswith ".plist")
| where InitiatingProcessFileName in~ ("node","npm","pnpm","yarn","bun","python","python3","pip","pip3","ruby","gem","sh","bash","zsh","curl","wget")
| project Timestamp, DeviceName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### Miasma AI tool config poisoning — writes to Claude / Cursor / Copilot / Gemini / Kiro / Cline configs

`UC_37_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as writers from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*/.claude/*","*/.config/claude/*","*/.cursor/*","*/.cursor-tutor/*","*/.config/github-copilot/*","*/.config/copilot/*","*/.gemini/*","*/.config/gemini/*","*/.kiro/*","*/.cline/*","*/.config/cline/*") OR Filesystem.file_name IN ("CLAUDE.md","claude_desktop_config.json","settings.json",".cursorrules",".cursorignore","copilot-chat.json",".geminirc","cline_mcp_settings.json")) AND NOT Filesystem.process_name IN (Code, code, cursor, Cursor, claude, Claude, Gemini, gemini, copilot, Copilot, idea, pycharm, electron, Slack) by host Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let ai_tool_paths = dynamic(["/.claude/","/.config/claude/","/.cursor/","/.cursor-tutor/","/.config/github-copilot/","/.config/copilot/","/.gemini/","/.config/gemini/","/.kiro/","/.cline/","/.config/cline/"]);
let ai_tool_files = dynamic(["CLAUDE.md","claude_desktop_config.json",".cursorrules",".cursorignore","copilot-chat.json",".geminirc","cline_mcp_settings.json"]);
let legit_writers = dynamic(["code","Code","cursor","Cursor","claude","Claude","gemini","Gemini","copilot","electron","idea","pycharm","Slack"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any (ai_tool_paths)) or (FileName in (ai_tool_files))
| where not(InitiatingProcessFileName in~ (legit_writers))
| where InitiatingProcessFileName in~ ("node","npm","pnpm","yarn","bun","python","python3","pip","ruby","gem","sh","bash","zsh","curl","wget","tee")
| project Timestamp, DeviceName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Miasma credential harvesting — package-manager child reads ~/.aws, ~/.ssh, ~/.kube, ~/.npmrc, password vaults

`UC_37_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as readers from datamodel=Endpoint.Filesystem where Filesystem.action=read AND (Filesystem.file_path IN ("*/.aws/credentials","*/.aws/config","*/.ssh/id_*","*/.ssh/config","*/.kube/config","*/.docker/config.json","*/.npmrc","*/.pypirc","*/.gem/credentials","*/.config/gh/hosts.yml","*/.config/hub","*/.password-store/*","*/.config/1Password/*","*/.config/Bitwarden*/*","*/.netrc","*/.jfrog/*")) AND Filesystem.process_name IN (node, npm, pnpm, yarn, bun, python, python3, pip, ruby, gem, sh, bash, zsh, curl, wget) by host Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where mvcount(paths) >= 3
```

**Defender KQL:**
```kql
let secret_paths = dynamic(["/.aws/credentials","/.aws/config","/.ssh/id_","/.ssh/config","/.kube/config","/.docker/config.json","/.npmrc","/.pypirc","/.gem/credentials","/.config/gh/hosts.yml","/.config/hub","/.password-store/","/.config/1Password/","/.config/Bitwarden","/.netrc","/.jfrog/"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileAccessed" or ActionType == "FileRead"
| where FolderPath has_any (secret_paths) or FileName in ("credentials",".npmrc",".pypirc",".netrc","hosts.yml","config.json")
| where InitiatingProcessFileName in~ ("node","npm","pnpm","yarn","bun","python","python3","pip","ruby","gem","sh","bash","zsh","curl","wget")
| summarize HitCount = count(),
            DistinctPaths = dcount(FolderPath),
            SamplePaths = make_set(strcat(FolderPath, FileName), 10),
            SampleCmd = any(InitiatingProcessCommandLine)
            by bin(Timestamp, 5m), DeviceName, InitiatingProcessAccountName,
               InitiatingProcessFileName, InitiatingProcessId
| where DistinctPaths >= 3   // fan-out across multiple secret stores in one process is the Miasma shape
| order by Timestamp desc
```

### Miasma GitHub-as-C2 — outbound api.github.com from a systemd/launchd-spawned process or clone of 'Miasma-Open-Source-Release'

`UC_37_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.app) as app values(All_Traffic.process_name) as proc values(All_Traffic.parent_process_name) as parent from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="api.github.com" OR All_Traffic.dest="raw.githubusercontent.com" OR All_Traffic.dest="codeload.github.com") AND All_Traffic.parent_process_name IN (systemd, launchd, launchctl, init) by host All_Traffic.user All_Traffic.process_name All_Traffic.parent_process_name | `drop_dm_object_name(All_Traffic)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process="*Miasma-Open-Source-Release*" by host Processes.user Processes.process Processes.process_name | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
// (a) systemd/launchd-spawned outbound to GitHub API
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("api.github.com","raw.githubusercontent.com","codeload.github.com","uploads.github.com")
| where InitiatingProcessParentFileName in~ ("systemd","launchd","launchctl","init")
   or InitiatingProcessFileName in~ ("systemd","launchd")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessAccountName
| union (
    // (b) clone or fetch of the leaked repo name
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has "Miasma-Open-Source-Release"
    | project Timestamp, DeviceName, RemoteUrl="", RemoteIP="",
              InitiatingProcessFileName, InitiatingProcessCommandLine=ProcessCommandLine,
              InitiatingProcessParentFileName, InitiatingProcessAccountName=AccountName
)
| order by Timestamp desc
```

### Miasma supply-chain propagation — npm publish / twine upload / gem push / jfrog upload from non-CI/CD context

`UC_37_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process="*npm publish*" OR Processes.process="*pnpm publish*" OR Processes.process="*yarn publish*" OR Processes.process="*bun publish*" OR Processes.process="*twine upload*" OR Processes.process="*python*-m*twine*" OR Processes.process="*gem push*" OR Processes.process="*jf rt upload*" OR Processes.process="*jfrog rt upload*") by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | join type=left host [| tstats `summariesonly` values(All_Traffic.dest) as registries from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="registry.npmjs.org" OR All_Traffic.dest="upload.pypi.org" OR All_Traffic.dest="rubygems.org" OR All_Traffic.dest="*.jfrog.io") by host | `drop_dm_object_name(All_Traffic)`] | search NOT host IN ("*-ci-*","*-runner-*","github-actions-*","gitlab-runner-*")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("npm publish","pnpm publish","yarn publish","bun publish","twine upload","gem push","jf rt upload","jfrog rt upload")
   or (FileName in~ ("npm","pnpm","yarn","bun") and ProcessCommandLine has " publish")
   or (FileName =~ "gem" and ProcessCommandLine has " push ")
| where DeviceName !startswith "ci-" and DeviceName !contains "-runner-" and DeviceName !startswith "github-actions" and DeviceName !startswith "gitlab-runner"
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, DeviceType, MachineGroup) by DeviceId
) on DeviceId
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessParentFileName,
          MachineGroup
| order by Timestamp desc
```

### Miasma lateral movement — AWS SSM StartSession or SendCommand from a developer access key outside business hours / VPC

`UC_37_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`cloudtrail` (eventName=StartSession OR eventName=SendCommand OR eventName=StartAutomationExecution) eventSource=ssm.amazonaws.com errorCode="*" NOT errorCode=* | rename userIdentity.type as identityType userIdentity.userName as userName userIdentity.arn as userArn userIdentity.sessionContext.sessionIssuer.userName as roleName | where identityType IN ("IAMUser","AssumedRole") | search NOT sourceIPAddress IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16") | stats count min(_time) as firstTime max(_time) as lastTime values(eventName) as actions values(requestParameters.target) as targets values(requestParameters.documentName) as documents by sourceIPAddress userName roleName userAgent | where count >= 1
```

**Defender KQL:**
```kql
// SSM client-side invocation on the workstation
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "aws" or FileName =~ "aws.exe")
   and ProcessCommandLine has "ssm"
   and ProcessCommandLine has_any ("start-session","send-command","start-automation-execution")
| where InitiatingProcessParentFileName in~ ("systemd","launchd","launchctl","node","npm","pnpm","yarn","bun","python","python3","sh","bash","zsh")
| project Timestamp, DeviceName, AccountName,
          ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `396cac9e457ec54ff6d3f6311cb5cc1da8054d019ce3ffa1de5741506c7a4ea4`, `d8d170af3de17bb9b217c52aaaffdf9395f35ef015a57ef676e406c121e5e223`, `f0641e053e81f0d01fa46db35a83e0a34494886503086866d956d14e81fd3e1c`, `d5a97614d5319ce9c8e01fa0b4eb06fb5b9e54fa13b23d718174a1546444123b`, `f88258e21592084a2f93a572ade8f9b91c0cd0e242f5cf6121ed7bad0f7bdd1f`, `25e121e3b7d300c0d0075b33e5eca39a3e6a659fb9cfee52b70ef71686628f1b`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
