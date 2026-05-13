# [HIGH] What is Slopsquatting? The AI Package Hallucination Attack Already Happening

**Source:** Aikido
**Published:** 2026-02-20
**Article:** https://www.aikido.dev/blog/slopsquatting-ai-package-hallucination-attacks

## Threat Profile

Blog Guides & Best Practices What is Slopsquatting? The AI Package Hallucination Attack Already Happening What is Slopsquatting? The AI Package Hallucination Attack Already Happening Written by Dania Durnas Published on: Feb 20, 2026 Typosquatting, registering a typoed version of a popular package and waiting for a developer to accidentally type and install the wrong package, has been around for a decade in npm. It’s nothing new— the registry has protections for it. 
Then AI came along and chang…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059** — Command and Scripting Interpreter
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Installation of confirmed slopsquatted packages (unused-imports, react-codeshift, huggingface-cli)

`UC_350_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.parent_process_name) as parent_process_name values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name IN ("npm.exe","npm","npx.exe","npx","pnpm.exe","pnpm","yarn.exe","yarn","pip.exe","pip","pip3","pip3.exe","uv","uv.exe","poetry","poetry.exe","node.exe","node") AND (Processes.process="*unused-imports*" OR Processes.process="*react-codeshift*" OR Processes.process="*huggingface-cli*") AND NOT Processes.process="*eslint-plugin-unused-imports*" by host Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | rename firstTime as first_time lastTime as last_time | convert ctime(first_time) ctime(last_time)
```

**Defender KQL:**
```kql
let installers = dynamic(["npm.exe","npx.exe","pnpm.exe","yarn.exe","pip.exe","pip3.exe","uv.exe","poetry.exe","node.exe","python.exe","python3.exe"]);
let slop_names = dynamic(["unused-imports","react-codeshift","huggingface-cli"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (installers) or InitiatingProcessFileName in~ (installers)
| where ProcessCommandLine has_any (slop_names) or InitiatingProcessCommandLine has_any (slop_names)
| where not(ProcessCommandLine has "eslint-plugin-unused-imports")
| where not(InitiatingProcessCommandLine has "eslint-plugin-unused-imports")
| where ProcessCommandLine has_any (" install "," i "," add ","npx ","pip install","uv add","poetry add")
   or InitiatingProcessCommandLine has_any (" install "," i "," add ","npx ","pip install","uv add","poetry add")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] AI coding agent process triggers npm/npx/pip install (slopsquatting exposure surface)

`UC_350_5` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where Processes.process_name IN ("npm.exe","npm","npx.exe","npx","pnpm.exe","pnpm","yarn.exe","yarn","pip.exe","pip","pip3","uv","poetry") AND (Processes.process="* install *" OR Processes.process="*npx *" OR Processes.process="* add *") AND (Processes.parent_process_name IN ("claude.exe","claude","cursor.exe","cursor","aider","aider.exe","gh-copilot.exe","copilot.exe","codeium.exe","cody.exe","continue.exe","windsurf.exe") OR Processes.parent_process="*@anthropic-ai/claude-code*" OR Processes.parent_process="*github-copilot-cli*" OR Processes.parent_process="*cursor*" OR Processes.parent_process="*aider-chat*") by host Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | rename firstTime as first_time lastTime as last_time | convert ctime(first_time) ctime(last_time) | sort - last_time
```

**Defender KQL:**
```kql
let installers = dynamic(["npm.exe","npx.exe","pnpm.exe","yarn.exe","pip.exe","pip3.exe","uv.exe","poetry.exe"]);
let agent_bins = dynamic(["claude.exe","cursor.exe","aider.exe","copilot.exe","gh-copilot.exe","codeium.exe","cody.exe","continue.exe","windsurf.exe"]);
let agent_cmd_markers = dynamic(["@anthropic-ai/claude-code","github-copilot-cli","aider-chat","cursor-agent","continue.dev","codeium","cody-cli"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ (installers)
| where ProcessCommandLine has_any (" install "," add "," i ","npx ")
| where InitiatingProcessFileName in~ (agent_bins)
   or InitiatingProcessCommandLine has_any (agent_cmd_markers)
   or InitiatingProcessParentFileName in~ (agent_bins)
| extend Pkg = extract(@"(?i)\b(?:install|add|i|npx)\s+(?:--[^\s]+\s+)*([@\w][\w@\-\./]+)", 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName,
          Agent = InitiatingProcessFileName,
          AgentCmd = InitiatingProcessCommandLine,
          Installer = FileName,
          InstallerCmd = ProcessCommandLine,
          Pkg
| order by Timestamp desc
```

### [LLM] PhantomRaven RDD: npm install fetching dependency from non-registry HTTP(S) host

`UC_350_6` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.dest_ip) as dest_ip min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("node.exe","node","npm.exe","npm","npx.exe","npx","pnpm.exe","pnpm","yarn.exe","yarn") AND All_Traffic.dest_port IN (80,443,8080,8443) AND NOT (All_Traffic.dest IN ("registry.npmjs.org","registry.yarnpkg.com","registry.npmmirror.com") OR All_Traffic.dest="*.npmjs.org" OR All_Traffic.dest="*.yarnpkg.com" OR All_Traffic.dest="*.pnpm.io" OR All_Traffic.dest="github.com" OR All_Traffic.dest="*.github.com" OR All_Traffic.dest="raw.githubusercontent.com" OR All_Traffic.dest="codeload.github.com" OR All_Traffic.dest="objects.githubusercontent.com" OR All_Traffic.dest="gitlab.com" OR All_Traffic.dest="*.gitlab.com" OR All_Traffic.dest="bitbucket.org" OR All_Traffic.dest="*.bitbucket.org") by host All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | rename firstTime as first_time lastTime as last_time | convert ctime(first_time) ctime(last_time) | where count >= 1 | sort - last_time
```

**Defender KQL:**
```kql
let installer_procs = dynamic(["npm.exe","npx.exe","pnpm.exe","yarn.exe","node.exe"]);
let registry_hosts = dynamic([
    "registry.npmjs.org","registry.yarnpkg.com","registry.npmmirror.com",
    "registry.pnpm.io","npm.pkg.github.com"
]);
let git_hosts = dynamic([
    "github.com","raw.githubusercontent.com","codeload.github.com",
    "objects.githubusercontent.com","gitlab.com","bitbucket.org"
]);
// 1. Find install commands within the lookback
let InstallProcs = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where (FileName in~ (installer_procs) or InitiatingProcessFileName in~ (installer_procs))
    | where ProcessCommandLine has_any (" install "," i "," add ","npx ","ci ","--save")
       or InitiatingProcessCommandLine has_any (" install "," i "," add ","npx ","ci ","--save")
    | project InstallTime = Timestamp, DeviceId, InstallCmd = ProcessCommandLine,
              InstallerImg = FileName;
// 2. Find network connections from install context to non-allowlisted hosts within 5 min
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (installer_procs)
| where RemoteIPType == "Public"
| where RemotePort in (80, 443, 8080, 8443)
| where isnotempty(RemoteUrl)
| extend Host = tolower(tostring(parse_url(strcat("https://", RemoteUrl)).Host))
| where Host !in~ (registry_hosts) and Host !in~ (git_hosts)
| where not(Host endswith ".npmjs.org") and not(Host endswith ".yarnpkg.com")
  and not(Host endswith ".pnpm.io") and not(Host endswith ".github.com")
  and not(Host endswith ".githubusercontent.com") and not(Host endswith ".gitlab.com")
  and not(Host endswith ".bitbucket.org")
| join kind=inner InstallProcs on DeviceId
| where Timestamp between (InstallTime .. InstallTime + 5m)
| project Timestamp, InstallTime,
          DelaySec = datetime_diff('second', Timestamp, InstallTime),
          DeviceName, InitiatingProcessAccountName,
          Installer = InitiatingProcessFileName,
          InstallCmd, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### Article-specific behavioural hunt — What is Slopsquatting? The AI Package Hallucination Attack Already Happening

`UC_350_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — What is Slopsquatting? The AI Package Hallucination Attack Already Happening ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — What is Slopsquatting? The AI Package Hallucination Attack Already Happening
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 7 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
