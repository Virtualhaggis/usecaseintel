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
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1546** — Event Triggered Execution
- **T1059** — Command and Scripting Interpreter
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1528** — Steal Application Access Token
- **T1105** — Ingress Tool Transfer
- **T1021.008** — Remote Services: Direct Cloud VM Connections
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1570** — Lateral Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Miasma dead-man-switch destructive home directory wipe

`UC_35_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*rm*-rf*~*" Processes.process="*Documents*") by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.process_id | `drop_dm_object_name(Processes)` | rex field=process "(?i)rm\s+-rf\s+(~|\$HOME)/?\s*(;|&&|$).*rm\s+-rf\s+(~|\$HOME)/Documents" | where isnotnull(_raw) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "rm -rf" and ProcessCommandLine has "Documents"
| where ProcessCommandLine matches regex @"(?i)rm\s+-rf\s+(~|\$HOME)/?\s*(;|&&|\||\n)"
| where ProcessCommandLine matches regex @"(?i)rm\s+-rf\s+(~|\$HOME)/Documents"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, FolderPath, SHA256
| order by Timestamp desc
```

### Miasma 72-hour monitor persistence via systemd user service or LaunchAgent

`UC_35_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Filesystem.file_path) as paths, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.config/systemd/user/*.service" OR Filesystem.file_path="*/Library/LaunchAgents/*.plist") Filesystem.action IN (created, modified, written) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | where NOT match(process_name, "(?i)^(systemd|launchd|brew|apt|dpkg|yum|dnf|snap|installer|pkg|Code|Cursor)$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MiasmaHashes = dynamic(["396cac9e457ec54ff6d3f6311cb5cc1da8054d019ce3ffa1de5741506c7a4ea4","d8d170af3de17bb9b217c52aaaffdf9395f35ef015a57ef676e406c121e5e223","f0641e053e81f0d01fa46db35a83e0a34494886503086866d956d14e81fd3e1c","d5a97614d5319ce9c8e01fa0b4eb06fb5b9e54fa13b23d718174a1546444123b","f88258e21592084a2f93a572ade8f9b91c0cd0e242f5cf6121ed7bad0f7bdd1f","25e121e3b7d300c0d0075b33e5eca39a3e6a659fb9cfee52b70ef71686628f1b","d630397de8b01af0f6f5cf4463da91b17f28195a2c50c8f3f38ad9f7873fdb8e","3a9db5ba0c8cd4c91e91717df6b1a141fc1e0fbc0558b5a78d7f5c23f5b2a150"]);
let PersistenceDrops = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("FileCreated","FileModified","FileRenamed")
    | where FolderPath matches regex @"(?i)/\.config/systemd/user(/|$)"
          or FolderPath matches regex @"(?i)/Library/LaunchAgents(/|$)"
          or FileName endswith ".service" and FolderPath has "systemd/user"
          or FileName endswith ".plist" and FolderPath has "LaunchAgents"
    | where InitiatingProcessFileName !in~ ("systemd","launchd","brew","apt","apt-get","dpkg","yum","dnf","snap","installer","pkg","Code","Code Helper","Cursor","Cursor Helper")
    | where InitiatingProcessAccountName !endswith "$"
    | project Timestamp, DeviceName, FolderPath, FileName, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName, InitiatingProcessId;
let GithubBeacons = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has_any ("api.github.com","github.com")
    | project NetTime = Timestamp, DeviceName, RemoteUrl, RemoteIP,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessId;
PersistenceDrops
| join kind=inner GithubBeacons on DeviceName
| where NetTime between (Timestamp .. Timestamp + 72h)
| summarize BeaconCount = count(), FirstBeacon = min(NetTime), LastBeacon = max(NetTime)
          by Timestamp, DeviceName, FolderPath, FileName, SHA256,
             InitiatingProcessFileName, InitiatingProcessCommandLine
| where BeaconCount >= 20
| extend KnownHash = SHA256 in (MiasmaHashes)
| order by Timestamp desc
```

### Miasma AI coding tool config poisoning via non-IDE writer

`UC_35_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Filesystem.file_path) as paths, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN (created, modified, written) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | where match(file_path, "(?i)/\.(claude|cursor|gemini|kiro|cline)(/|$)|/\.config/(github-copilot|copilot|cursor|kiro|cline)/|/Library/Application Support/(Claude|Cursor|GitHub Copilot|Gemini|Kiro|Cline)/") | where match(process_name, "(?i)^(bash|sh|zsh|dash|node|npm|npx|yarn|pnpm|python|python3|git|curl|wget|ruby|gem|pip|pip3|tar|unzip)$") | where NOT match(process_name, "(?i)^(claude|cursor|code|code-helper|gemini|copilot|kiro|cline)$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath matches regex @"(?i)/\.(claude|cursor|gemini|kiro|cline)(/|$)"
      or FolderPath matches regex @"(?i)/\.config/(github-copilot|copilot|cursor|kiro|cline)(/|$)"
      or FolderPath matches regex @"(?i)/Library/Application Support/(Claude|Cursor|GitHub Copilot|Gemini|Kiro|Cline)/"
| where InitiatingProcessFileName in~ ("bash","sh","zsh","dash","node","npm","npx","yarn","pnpm","python","python3","git","curl","wget","ruby","gem","pip","pip3","tar","unzip")
| where InitiatingProcessFileName !in~ ("claude","cursor","Cursor Helper","Code","Code Helper","gemini","copilot","kiro","cline")
| where InitiatingProcessAccountName !endswith "$"
| where FileName endswith ".md" or FileName endswith ".json" or FileName endswith ".yaml" or FileName endswith ".yml" or FileName endswith ".toml" or FileName startswith "AGENTS" or FileName startswith "CLAUDE" or FileName has "mcp" or FileName has "settings"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Miasma developer credential file harvest fan-out

`UC_35_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, dc(Filesystem.file_path) as cred_paths_hit, values(Filesystem.file_path) as paths_sampled, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.pypirc" OR Filesystem.file_path="*/.gem/credentials" OR Filesystem.file_path="*/.kube/config" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.netrc" OR Filesystem.file_path="*/.config/gh/hosts.yml" OR Filesystem.file_path="*/.config/git/credentials" OR Filesystem.file_path="*/.ssh/id_rsa" OR Filesystem.file_path="*/.ssh/id_ed25519" OR Filesystem.file_path="*/.ssh/id_ecdsa" OR Filesystem.file_path="*/.config/op/*" OR Filesystem.file_path="*/.password-store/*" OR Filesystem.file_path="*/.cargo/credentials*" OR Filesystem.file_path="*/.jfrog/*") Filesystem.action IN (read, accessed, opened) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_id _time span=1m | `drop_dm_object_name(Filesystem)` | where cred_paths_hit >= 4 | where NOT match(process_name, "(?i)^(aws|kubectl|docker|ssh|sshd|git|gh|node|npm|pnpm|yarn|gem|pip|pip3|gpg|op|1password|Code|Cursor|claude|TimeMachine|tmutil|rsync|restic|borg|kopia)$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CredPathFragments = dynamic([
    "/.aws/credentials","/.aws/config","/.npmrc","/.pypirc",
    "/.gem/credentials","/.kube/config","/.docker/config.json",
    "/.netrc","/.config/gh/hosts.yml","/.config/git/credentials",
    "/.ssh/id_rsa","/.ssh/id_ed25519","/.ssh/id_ecdsa",
    "/.config/op/","/.password-store/","/.cargo/credentials","/.jfrog/"
]);
let AllowedReaders = dynamic([
    "aws","kubectl","docker","ssh","sshd","git","gh","node","npm","pnpm","yarn",
    "gem","pip","pip3","gpg","op","1password","Code","Code Helper","Cursor",
    "claude","tmutil","rsync","restic","borg","kopia"
]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileAccessed","FileOpened","FileRead","FileCreated")
| extend FullPath = strcat(FolderPath, "/", FileName)
| where FullPath has_any (CredPathFragments)
| where InitiatingProcessFileName !in~ (AllowedReaders)
| where InitiatingProcessAccountName !endswith "$"
| summarize CredsHit = dcount(FullPath), SamplePaths = make_set(FullPath, 20),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DeviceName, InitiatingProcessId, InitiatingProcessFileName,
             InitiatingProcessCommandLine, InitiatingProcessAccountName,
             bin(Timestamp, 1m)
| where CredsHit >= 4
| order by LastSeen desc
```

### Miasma-Open-Source-Release repository fetch via git clone or HTTP download

`UC_35_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Processes.process) as cmd, values(Processes.parent_process_name) as parent, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*Miasma-Open-Source-Release*" by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "Miasma-Open-Source-Release"
     or InitiatingProcessCommandLine has "Miasma-Open-Source-Release"
| project Timestamp, DeviceName, AccountName, EventKind = "process",
          FileName, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName),
(DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "Miasma-Open-Source-Release"
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
          EventKind = "network", FileName = "", ProcessCommandLine = RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName = InitiatingProcessParentFileName)
| order by Timestamp desc
```

### AWS SSM cross-host fan-out from a developer IAM principal

`UC_35_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, dc(All_Changes.object) as target_count, min(_time) as firstTime, max(_time) as lastTime, values(All_Changes.command) as actions, values(All_Changes.object) as targets from datamodel=Change.All_Changes where All_Changes.command IN ("StartSession","SendCommand","StartAutomationExecution") All_Changes.result="success" sourcetype="aws:cloudtrail" by All_Changes.user All_Changes.src All_Changes.user_type _time span=10m | `drop_dm_object_name(All_Changes)` | where target_count >= 5 | where NOT match(user, "(?i)^(arn:aws:iam::\d+:role/(SSMPatchManager|aws-service-role|AWSServiceRoleFor|OrganizationAccountAccessRole|ssm-automation-))") | convert ctime(firstTime) ctime(lastTime)
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

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
