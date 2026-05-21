# [HIGH] Popular GitHub Action Tags Redirected to Imposter Commit to Steal CI/CD Credentials

**Source:** The Hacker News, StepSecurity
**Published:** 2026-05-19
**Article:** https://thehackernews.com/2026/05/github-actions-supply-chain-attack.html

## Threat Profile

Back to Blog Product Introducing Secure Registry: install-time defense for the npm supply chain Introducing Secure Registry by StepSecurity: install-time defense for the npm supply chain. Block malicious packages, enforce package cooldowns, and protect CI/CD pipelines, developer machines, and artifact managers from modern software supply chain attacks. Sai Likhith View LinkedIn May 12, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading n…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `83.142.209.194`
- **Domain (defanged):** `git-tanstack.com`
- **Domain (defanged):** `api.masscan.cloud`
- **Domain (defanged):** `filev2.getsession.org`
- **Domain (defanged):** `seed1.getsession.org`
- **SHA256:** `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
- **SHA256:** `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- **SHA256:** `2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df`
- **SHA256:** `1e8538c6e0563d50da0f2e097e979ebd5294ce1defe01d0b9fe361ba3bed1898`
- **SHA256:** `7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b`
- **SHA1:** `e7d582b98ca80690883175470e96f703ef6dc497`
- **SHA1:** `12f35b1081b17d21815b35feb57ab03d02482116`
- **SHA1:** `820fa07a7328b6cf2b417078e103721d4d8f2e79`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1546** — Event Triggered Execution
- **T1554** — Compromise Host Software Binary
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1083** — File and Directory Discovery
- **T1555** — Credentials from Password Stores
- **T1567** — Exfiltration Over Web Service
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1213.003** — Data from Information Repositories: Code Repositories

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] npm/pnpm/yarn install of Mini Shai-Hulud compromised AntV ecosystem versions

`UC_75_3` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.process_name IN ("npm.exe","npm-cli.js","npm.cmd","pnpm.exe","pnpm.cmd","yarn.exe","yarn.cmd","node.exe","npm","pnpm","yarn","node") (Processes.process="*timeago.js@4.1.2*" OR Processes.process="*timeago.js@4.2.2*" OR Processes.process="*timeago-react@3.1.7*" OR Processes.process="*timeago-react@3.2.7*" OR Processes.process="*echarts-for-react@3.0.7*" OR Processes.process="*echarts-for-react@3.1.7*" OR Processes.process="*echarts-for-react@3.2.7*" OR Processes.process="*@antv/g2@5.5.8*" OR Processes.process="*@antv/g2@5.6.8*" OR Processes.process="*@antv/g6@5.2.1*" OR Processes.process="*@antv/g6@5.3.1*" OR Processes.process="*@antv/x6@3.2.7*" OR Processes.process="*@antv/x6@3.3.7*" OR Processes.process="*@antv/l7@2.26.10*" OR Processes.process="*@antv/l7@2.27.10*" OR Processes.process="*@antv/s2@2.8.1*" OR Processes.process="*@antv/s2@2.9.1*" OR Processes.process="*@antv/f2@5.15.0*" OR Processes.process="*@antv/f2@5.16.0*" OR Processes.process="*jest-canvas-mock@2.7.3*" OR Processes.process="*jest-date-mock@1.2.11*" OR Processes.process="*lint-md@0.4.0*" OR Processes.process="*lint-md-cli@0.3.2*" OR Processes.process="*mcp-echarts@0.9.1*" OR Processes.process="*mcp-mermaid@0.6.1*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | drop_dm_object_name(Processes) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","pnpm.exe","yarn.exe","cmd.exe","pwsh.exe","powershell.exe","bash.exe","sh","node","npm","pnpm","yarn")
   or FileName in~ ("node.exe","npm.exe","pnpm.exe","yarn.exe","node","npm","pnpm","yarn")
| where ProcessCommandLine has_any (
    "timeago.js@4.1.2","timeago.js@4.2.2","timeago-react@3.1.7","timeago-react@3.2.7",
    "echarts-for-react@3.0.7","echarts-for-react@3.1.7","echarts-for-react@3.2.7",
    "@antv/g2@5.5.8","@antv/g2@5.6.8","@antv/g6@5.2.1","@antv/g6@5.3.1",
    "@antv/x6@3.2.7","@antv/x6@3.3.7","@antv/l7@2.26.10","@antv/l7@2.27.10",
    "@antv/s2@2.8.1","@antv/s2@2.9.1","@antv/f2@5.15.0","@antv/f2@5.16.0",
    "@antv/g2plot@2.5.35","@antv/g2plot@2.6.35","@antv/graphin@3.1.5","@antv/graphin@3.2.5",
    "@antv/util@3.4.11","@antv/util@3.5.11",
    "jest-canvas-mock@2.7.3","jest-date-mock@1.2.11","size-sensor@1.2.4",
    "lint-md@0.4.0","lint-md-cli@0.3.2","mcp-echarts@0.9.1","mcp-mermaid@0.6.1")
| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] Outbound to t.m-kosche.com fake OpenTelemetry C2

`UC_75_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src_user) as user values(DNS.src) as src from datamodel=Network_Resolution where (DNS.query="t.m-kosche.com" OR DNS.query="*.t.m-kosche.com" OR DNS.query="*.m-kosche.com") by DNS.src DNS.dest DNS.query | drop_dm_object_name(DNS) | append [| tstats summariesonly=true count from datamodel=Web where (Web.url="*t.m-kosche.com*" OR Web.dest="t.m-kosche.com") by Web.src Web.user Web.url Web.dest Web.http_user_agent | drop_dm_object_name(Web)]
```

**Defender KQL:**
```kql
let TargetDomain = "t.m-kosche.com";
union isfuzzy=true
  (DeviceNetworkEvents
   | where Timestamp > ago(30d)
   | where RemoteUrl has TargetDomain or RemoteUrl endswith ".m-kosche.com"
   | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType),
  (DeviceEvents
   | where Timestamp > ago(30d)
   | where ActionType == "DnsQueryResponse"
   | where AdditionalFields has TargetDomain
   | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, ActionType, AdditionalFields)
| order by Timestamp desc
```

### [LLM] Mini Shai-Hulud persistence drop into .claude/settings.json or .vscode/tasks.json by node

`UC_75_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.claude\\settings.json" OR Filesystem.file_path="*/.claude/settings.json" OR Filesystem.file_path="*\\.vscode\\tasks.json" OR Filesystem.file_path="*/.vscode/tasks.json") (Filesystem.process_name="node.exe" OR Filesystem.process_name="node" OR Filesystem.process_name="npm.exe" OR Filesystem.process_name="npm" OR Filesystem.process_name="pnpm.exe" OR Filesystem.process_name="pnpm" OR Filesystem.process_name="yarn.exe" OR Filesystem.process_name="yarn") Filesystem.action="modified" OR Filesystem.action="created" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.action | drop_dm_object_name(Filesystem) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath endswith @"\.claude\settings.json" or FolderPath endswith "/.claude/settings.json"
      or FolderPath endswith @"\.vscode\tasks.json"   or FolderPath endswith "/.vscode/tasks.json")
| where InitiatingProcessFileName in~ ("node.exe","node","npm.exe","npm","pnpm.exe","pnpm","yarn.exe","yarn")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, ActionType, SHA256
| order by Timestamp desc
```

### [LLM] Mini Shai-Hulud node process fans out across cloud/credential file paths

`UC_75_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true dc(Filesystem.file_path) as path_count values(Filesystem.file_path) as files min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.process_name="node.exe" OR Filesystem.process_name="node" OR Filesystem.process_name="npm.exe" OR Filesystem.process_name="npm" OR Filesystem.process_name="pnpm.exe" OR Filesystem.process_name="pnpm" OR Filesystem.process_name="yarn.exe" OR Filesystem.process_name="yarn") (Filesystem.file_path="*\\.aws\\credentials" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*\\.aws\\config" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*\\.kube\\config" OR Filesystem.file_path="*/.kube/config" OR Filesystem.file_path="*\\.npmrc" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*\\.docker\\config.json" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*\\.config\\gcloud\\*" OR Filesystem.file_path="*/.config/gcloud/*" OR Filesystem.file_path="*\\.azure\\*" OR Filesystem.file_path="*/.azure/*" OR Filesystem.file_path="*\\.ssh\\id_*" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*\\.netrc" OR Filesystem.file_path="*/.netrc" OR Filesystem.file_path="*\\.vault-token" OR Filesystem.file_path="*/.vault-token" OR Filesystem.file_path="*\\.gitconfig" OR Filesystem.file_path="*/.gitconfig" OR Filesystem.file_path="*\\AppData\\Roaming\\Bitcoin\\wallet.dat" OR Filesystem.file_path="*/.bitcoin/wallet.dat" OR Filesystem.file_path="*\\Ethereum\\keystore\\*" OR Filesystem.file_path="*/.ethereum/keystore/*" OR Filesystem.file_path="*\\Roaming\\Solana\\*" OR Filesystem.file_path="*/.config/solana/*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_guid | where path_count >= 5 | drop_dm_object_name(Filesystem) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CredPaths = dynamic([
  @"\.aws\credentials", "/.aws/credentials", @"\.aws\config", "/.aws/config",
  @"\.kube\config", "/.kube/config",
  @"\.npmrc", "/.npmrc",
  @"\.docker\config.json", "/.docker/config.json",
  @"\.config\gcloud\", "/.config/gcloud/",
  @"\.azure\", "/.azure/",
  @"\.ssh\id_", "/.ssh/id_",
  @"\.netrc", "/.netrc",
  @"\.vault-token", "/.vault-token",
  @"\.gitconfig", "/.gitconfig",
  @"\Bitcoin\wallet.dat", "/.bitcoin/wallet.dat",
  @"\Ethereum\keystore", "/.ethereum/keystore",
  @"\Solana\", "/.config/solana/",
  @"\.config\rclone\rclone.conf", "/.config/rclone/rclone.conf"
]);
DeviceFileEvents
| where Timestamp > ago(3d)
| where InitiatingProcessFileName in~ ("node.exe","node","npm.exe","npm","pnpm.exe","pnpm","yarn.exe","yarn")
| extend MatchedPath = tostring(CredPaths[indexof_regex(tolower(FolderPath), strcat_array(CredPaths, "|"))])
| where FolderPath has_any (CredPaths)
| summarize PathsTouched = dcount(FolderPath), Paths = make_set(FolderPath, 20), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine
| where PathsTouched >= 5
| order by PathsTouched desc
```

### [LLM] GitHub repo created with reversed Shai-Hulud worm description by stolen token

`UC_75_7` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`github_audit` action="repo.create" OR action="repo.update" OR action="public" 
| eval _description=lower(coalesce(description, repo_description, repository.description)) 
| eval _name=lower(coalesce(repo, repository.name, name)) 
| where match(_description, "niaga\s*og\s*ew\s*ereh\s*:?\s*duluh-iahs") OR match(_description, "shai-hulud:\s*here\s*we\s*go\s*again") OR match(_name, "(arrakis|sandworm|fremen|muad'?dib|paul-atreides|harkonnen|spice|melange|gom-jabbar|kwisatz|shai-hulud)") 
| stats min(_time) as firstSeen max(_time) as lastSeen values(_name) as repos values(actor) as actors values(actor_ip) as ip count by org 
| convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "GitHub"
| where ActionType in ("repo.create","RepositoryCreated","Create repository","repo.public","public_repository")
| extend RepoName = tostring(RawEventData.repo), RepoDesc = tolower(tostring(coalesce(RawEventData.description, RawEventData.repository.description, AdditionalFields.description)))
| where RepoDesc has "niaga og ew ereh" or RepoDesc has "duluh-iahs" or RepoDesc has "shai-hulud: here we go again"
   or RepoName has_any ("arrakis","sandworm","fremen","muaddib","muad-dib","paul-atreides","harkonnen","spice","melange","kwisatz","shai-hulud","gom-jabbar")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, ActionType, RepoName, RepoDesc, RawEventData
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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `83.142.209.194`, `git-tanstack.com`, `api.masscan.cloud`, `filev2.getsession.org`, `seed1.getsession.org`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`, `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`, `2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df`, `1e8538c6e0563d50da0f2e097e979ebd5294ce1defe01d0b9fe361ba3bed1898`, `7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b`, `e7d582b98ca80690883175470e96f703ef6dc497`, `12f35b1081b17d21815b35feb57ab03d02482116`, `820fa07a7328b6cf2b417078e103721d4d8f2e79`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
