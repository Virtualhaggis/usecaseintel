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
- **T1213.003** — Code Repositories
- **T1199** — Trusted Relationship
- **T1543.002** — Systemd Service
- **T1547.013** — XDG Autostart Entries
- **T1543.001** — Launch Agent
- **T1485** — Data Destruction
- **T1529** — System Shutdown/Reboot
- **T1059.004** — Unix Shell
- **T1552.001** — Credentials In Files
- **T1555.005** — Password Managers
- **T1528** — Steal Application Access Token
- **T1552.007** — Container API
- **T1554** — Compromise Host Software Binary
- **T1546** — Event Triggered Execution
- **T1647** — Plist File Modification
- **T1021.007** — Cloud Services
- **T1078.004** — Cloud Accounts
- **T1059.009** — Cloud API
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Miasma 'Miasma-Open-Source-Release' GitHub repo creation across dev accounts

`UC_46_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where All_Changes.action=created All_Changes.object_category=repository All_Changes.object="*Miasma-Open-Source-Release*" by All_Changes.user All_Changes.object All_Changes.src | `drop_dm_object_name(All_Changes)` | stats dc(user) as uniqUsers values(user) as users values(object) as repos by src | where uniqUsers >= 1
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "GitHub"
| where ActionType in ("CreateRepo", "RepositoryCreated", "create_repository")
| where ObjectName has "Miasma-Open-Source-Release" or RawEventData contains "Miasma-Open-Source-Release"
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, ObjectName, ActionType, UserAgent, RawEventData
| order by Timestamp desc
```

### Miasma persistence: systemd user service or macOS LaunchAgent dropped by dev run

`UC_46_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.config/systemd/user/*" Filesystem.file_name="*.service") OR (Filesystem.file_path="*/Library/LaunchAgents/*" Filesystem.file_name="*.plist") Filesystem.action IN (created, modified, renamed) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where NOT match(process_name,"(?i)^(systemctl|launchctl|apt|apt-get|dpkg|brew|snap|dnf|yum|installer|softwareupdate)$")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where (FolderPath has "/.config/systemd/user" and FileName endswith ".service")
    or (FolderPath has "/Library/LaunchAgents" and FileName endswith ".plist")
| where not (InitiatingProcessFileName in~ ("systemctl","launchctl","apt","apt-get","dpkg","brew","snap","dnf","yum","installer","softwareupdate"))
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Miasma dead-man switch: rm -rf ~/ ; rm -rf ~/Documents on token revocation

`UC_46_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("rm","bash","sh","zsh","dash") (Processes.process="*rm -rf ~/*" OR Processes.process="*rm -rf $HOME*" OR Processes.process="*rm -rf /home/*" OR Processes.process="*rm -rf ~/Documents*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("rm","bash","sh","zsh","dash","fish")
| where ProcessCommandLine matches regex @"(?i)rm\s+-rf?\s+(~/?|\$HOME/?|/home/[^\s]+/?)(\s|;|$)"
   or ProcessCommandLine has_all ("rm","-rf","~/Documents")
| where not (InitiatingProcessFileName in~ ("make","cargo","go","npm","yarn","pnpm","gradle","mvn","bazel","cmake","docker","podman"))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Miasma credential fan-out: single process reading 3+ developer secret stores

`UC_46_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*/.aws/config*" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/config*" OR Filesystem.file_path="*/.kube/config*" OR Filesystem.file_path="*/.docker/config.json*" OR Filesystem.file_path="*/.npmrc*" OR Filesystem.file_path="*/.pypirc*" OR Filesystem.file_path="*/.gem/credentials*" OR Filesystem.file_path="*/.config/gh/hosts.yml*" OR Filesystem.file_path="*/.gitconfig*" OR Filesystem.file_path="*/.netrc*" OR Filesystem.file_path="*/1Password/*.sqlite*" OR Filesystem.file_path="*/LastPass/*" OR Filesystem.file_path="*/Bitwarden/*.json*" OR Filesystem.file_path="*/.config/jfrog/*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | stats dc(file_path) as distinctStores values(file_path) as stores by dest user process_name process_guid | where distinctStores >= 3
```

**Defender KQL:**
```kql
let lookback = 1h;
let stores = dynamic(["/.aws/credentials","/.aws/config","/.ssh/id_","/.ssh/config","/.kube/config","/.docker/config.json","/.npmrc","/.pypirc","/.gem/credentials","/.config/gh/hosts.yml","/.gitconfig","/.netrc","/1Password","/LastPass","/Bitwarden","/.config/jfrog"]);
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileAccessed","FileModified","FileCreated")
| where FolderPath has_any (stores) or FileName has_any (stores)
| where not (InitiatingProcessFileName in~ ("aws","gh","kubectl","docker","helm","git","ssh","ssh-agent","1password","op","bitwarden-cli","bw"))
| summarize StoresHit = dcount(FolderPath), SampleStores = make_set(FolderPath, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| where StoresHit >= 3
| order by LastSeen desc
```

### Miasma AI coding tool config poisoning (Claude/Gemini/Cursor/Copilot/Kiro/Cline)

`UC_46_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN (created, modified) (Filesystem.file_path="*/.claude/*" OR Filesystem.file_path="*/.config/claude*" OR Filesystem.file_path="*/.gemini/*" OR Filesystem.file_path="*/.config/google-generative-ai*" OR Filesystem.file_path="*/.cursor/*" OR Filesystem.file_path="*/Library/Application Support/Cursor/*" OR Filesystem.file_path="*/.config/github-copilot/*" OR Filesystem.file_path="*/.vscode/extensions/github.copilot*" OR Filesystem.file_path="*/.kiro/*" OR Filesystem.file_path="*/.cline/*" OR Filesystem.file_path="*/.continue/*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | where NOT match(process_name, "(?i)^(code|code-insiders|cursor|cursor-helper|claude|gemini|kiro|cline|node|python.?|brew|installer|apt)$")
```

**Defender KQL:**
```kql
let aiConfigPaths = dynamic(["/.claude/","/.config/claude","/.gemini/","/.config/google-generative-ai","/.cursor/","/Library/Application Support/Cursor/","/.config/github-copilot/","/.vscode/extensions/github.copilot","/.kiro/","/.cline/","/.continue/"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (aiConfigPaths)
| where FileName endswith ".json" or FileName endswith ".yaml" or FileName endswith ".yml" or FileName endswith ".toml" or FileName endswith ".md" or FileName endswith ".mdx"
| where not (InitiatingProcessFileName in~ ("code","code-insiders","cursor","cursor-helper","claude","gemini","kiro","cline","node","python","python3","brew","installer","apt","dpkg","npm","pnpm"))
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### AWS SSM StartSession or aws-cli ssm from non-bastion / new caller

`UC_46_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where All_Changes.vendor_product="AWS CloudTrail" All_Changes.object_category="ssm" All_Changes.action IN ("StartSession","SendCommand","ResumeSession") All_Changes.status="success" by All_Changes.user All_Changes.src All_Changes.user_agent All_Changes.object | `drop_dm_object_name(All_Changes)` | join type=left user [| tstats `summariesonly` count as baselineCount from datamodel=Change.All_Changes where earliest=-30d@d latest=-1d@d All_Changes.vendor_product="AWS CloudTrail" All_Changes.object_category="ssm" All_Changes.action IN ("StartSession","SendCommand") by All_Changes.user | `drop_dm_object_name(All_Changes)`] | where isnull(baselineCount) OR baselineCount=0
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType in ("StartSession","SendCommand","ResumeSession")
| extend rawData = tostring(RawEventData)
| where rawData has "ssm.amazonaws.com"
| join kind=leftanti (
    CloudAppEvents
    | where Timestamp between (ago(30d) .. ago(7d))
    | where Application == "Amazon Web Services"
    | where ActionType in ("StartSession","SendCommand","ResumeSession")
    | distinct AccountObjectId
  ) on AccountObjectId
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, UserAgent, ActionType, ObjectName
| order by Timestamp desc
```

### Package publish (npm/PyPI/RubyGems) from compromised developer endpoint

`UC_46_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*npm publish*" OR Processes.process="*pnpm publish*" OR Processes.process="*yarn publish*" OR Processes.process="*twine upload*" OR Processes.process="*python -m twine upload*" OR Processes.process="*gem push*" OR Processes.process="*jfrog rt upload*") by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | where NOT match(parent_process_name, "(?i)^(jenkins|gh-actions|gitlab-runner|github-actions-runner|buildkite-agent|circleci-agent)$")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (ProcessCommandLine has_all ("npm", "publish"))
    or (ProcessCommandLine has_all ("pnpm", "publish"))
    or (ProcessCommandLine has_all ("yarn", "publish"))
    or (ProcessCommandLine has_all ("twine", "upload"))
    or (ProcessCommandLine has_all ("gem", "push"))
    or (ProcessCommandLine has_all ("jfrog", "rt", "upload"))
| where not (InitiatingProcessParentFileName in~ ("jenkins","github-actions-runner","gitlab-runner","buildkite-agent","circleci-agent","runner","Runner.Listener"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
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

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
