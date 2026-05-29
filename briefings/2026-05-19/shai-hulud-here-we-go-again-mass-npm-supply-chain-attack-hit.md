# [CRIT] Shai-Hulud: Here We Go Again. Mass npm Supply Chain Attack Hits the AntV Ecosystem

**Source:** StepSecurity
**Published:** 2026-05-19
**Article:** https://www.stepsecurity.io/blog/shai-hulud-here-we-go-again-mass-npm-supply-chain-attack-hits-the-antv-ecosystem

## Threat Profile

Back to Blog Threat Intel Shai-Hulud: Here We Go Again. Mass npm Supply Chain Attack Hits the AntV Ecosystem A new wave of the Mini Shai-Hulud worm has compromised packages across Alibaba's AntV data visualization ecosystem, echarts-for-react, timeago.js, and dozens more. Stolen CI/CD secrets are being dumped to thousands of public GitHub repositories as the attack continues to spread. Sai Likhith View LinkedIn May 19, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `t.m-kosche.com`
- **SHA256:** `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c`
- **SHA256:** `fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1001.003** — Data Obfuscation: Protocol Impersonation
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1555** — Credentials from Password Stores
- **T1083** — File and Directory Discovery
- **T1546** — Event Triggered Execution
- **T1176** — Browser Extensions
- **T1554** — Compromise Client Software Binary
- **T1567** — Exfiltration Over Web Service
- **T1098** — Account Manipulation
- **T1485** — Data Destruction

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Shai-Hulud C2 beacon to t.m-kosche.com (OpenTelemetry decoy)

`UC_109_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Network_Traffic.dest_ip) as dest_ip values(Network_Traffic.src) as src values(Network_Traffic.app) as app from datamodel=Network_Traffic where Network_Traffic.dest =~ "*kosche.com*" OR Network_Traffic.dest="t.m-kosche.com" by Network_Traffic.src Network_Traffic.dest Network_Traffic.dest_port | `drop_dm_object_name(Network_Traffic)` | append [| tstats summariesonly=t count from datamodel=Network_Resolution where Network_Resolution.DNS.query="t.m-kosche.com" OR Network_Resolution.DNS.query="*.m-kosche.com" by Network_Resolution.DNS.src Network_Resolution.DNS.query | `drop_dm_object_name(DNS)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 30d;
let C2Hosts = dynamic(["t.m-kosche.com","m-kosche.com"]);
union
  (DeviceNetworkEvents
   | where Timestamp > ago(LookbackDays)
   | where RemoteUrl has_any (C2Hosts) or RemoteUrl endswith ".m-kosche.com"
   | project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
             InitiatingProcessFileName, InitiatingProcessCommandLine,
             InitiatingProcessParentFileName, InitiatingProcessAccountName, ReportId),
  (DeviceEvents
   | where Timestamp > ago(LookbackDays)
   | where ActionType == "DnsQueryResponse"
   | where AdditionalFields has_any (C2Hosts)
   | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName,
             InitiatingProcessCommandLine, InitiatingProcessParentFileName,
             InitiatingProcessAccountName, ReportId)
| extend SuspiciousParent = iff(InitiatingProcessFileName has_any ("node.exe","npm.cmd","npx.cmd","yarn.cmd","pnpm.cmd","Runner.Worker.exe","Runner.Listener.exe"), true, false)
| order by Timestamp desc
```

### [LLM] TruffleHog spawned by Node/npm lifecycle on dev workstation or CI runner

`UC_109_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.process_name="trufflehog" OR Processes.process_name="trufflehog.exe" OR Processes.process="*trufflehog*") (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node" OR Processes.parent_process_name="npm.cmd" OR Processes.parent_process_name="npx.cmd" OR Processes.parent_process_name="yarn.cmd" OR Processes.parent_process_name="pnpm.cmd" OR Processes.parent_process_name="Runner.Worker.exe") by host Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 30d;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where FileName =~ "trufflehog.exe" or FileName =~ "trufflehog"
   or ProcessCommandLine has_any ("trufflehog filesystem","trufflehog git","trufflehog github","trufflehog --json")
| where InitiatingProcessFileName in~ ("node.exe","node","npm.cmd","npx.cmd","yarn.cmd","pnpm.cmd","corepack.exe","Runner.Worker.exe","Runner.Listener.exe","bash.exe","sh")
   or InitiatingProcessCommandLine has_any ("npm install","yarn install","pnpm install","npx ","@antv/","timeago.js","echarts-for-react")
| project Timestamp, DeviceName, AccountName,
          ProcessCommandLine, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          InitiatingProcessAccountName, ReportId
| order by Timestamp desc
```

### [LLM] Process fan-out reading 130+ cloud-credential / wallet paths in short window

`UC_109_12` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(Filesystem.file_path) as paths dc(Filesystem.file_path) as distinct_paths min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.aws\\credentials*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*\\.aws\\config*" OR Filesystem.file_path="*/.config/gcloud/*" OR Filesystem.file_path="*\\gcloud\\application_default_credentials.json" OR Filesystem.file_path="*\\.azure\\*" OR Filesystem.file_path="*/.azure/*" OR Filesystem.file_path="*\\.kube\\config*" OR Filesystem.file_path="*/.kube/config*" OR Filesystem.file_path="*\\.vault-token" OR Filesystem.file_path="*/.vault-token" OR Filesystem.file_path="*\\.npmrc" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*\\.git-credentials" OR Filesystem.file_path="*/.git-credentials" OR Filesystem.file_path="*\\.docker\\config.json" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*\\.ssh\\id_*" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*\\AppData\\*\\Ethereum\\keystore\\*" OR Filesystem.file_path="*\\Solana\\id.json" OR Filesystem.file_path="*\\Exodus\\*" OR Filesystem.file_path="*\\Electrum\\wallets\\*") by host Filesystem.user Filesystem.process_guid Filesystem.process_name span=10m | `drop_dm_object_name(Filesystem)` | where distinct_paths >= 8
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
let WindowMin = 5m;
let CredPaths = dynamic([
  "\\.aws\\credentials","/.aws/credentials","\\.aws\\config","/.aws/config",
  "/.config/gcloud/credentials.json","/.config/gcloud/application_default_credentials.json","\\gcloud\\application_default_credentials.json",
  "\\.azure\\","/.azure/","accessTokens.json",
  "\\.kube\\config","/.kube/config",
  "\\.vault-token","/.vault-token",
  "\\.npmrc","/.npmrc",".yarnrc",".yarnrc.yml",
  "\\.git-credentials","/.git-credentials",
  "\\.docker\\config.json","/.docker/config.json",
  "\\.ssh\\id_","/.ssh/id_",
  "\\Ethereum\\keystore\\","\\Solana\\id.json","\\Exodus\\","\\Electrum\\wallets\\","\\MetaMask\\",
  ".env",".env.local",".env.production",".pypirc",".pgpass",".my.cnf",
  "netrc",".netrc"
]);
DeviceFileEvents
| where Timestamp > ago(LookbackDays)
| where ActionType in ("FileCreated","FileModified","FileRenamed","FileOpened")
| extend MatchedPath = tostring(extract_all(@"(?i)(\.aws\\credentials|/\.aws/credentials|\.aws\\config|/\.aws/config|/\.config/gcloud|gcloud\\application_default_credentials\.json|\.azure\\|/\.azure/|accessTokens\.json|\.kube\\config|/\.kube/config|\.vault-token|\.npmrc|\.yarnrc|\.git-credentials|\.docker\\config\.json|/\.docker/config\.json|\.ssh\\id_|/\.ssh/id_|Ethereum\\keystore|Solana\\id\.json|Exodus|Electrum\\wallets|MetaMask|\.env|\.pypirc|\.pgpass|\.my\.cnf|netrc)", FolderPath))
| where array_length(todynamic(MatchedPath)) > 0
| summarize DistinctCredPaths = dcount(FolderPath),
            SamplePaths = make_set(FolderPath, 20),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
  by DeviceName, InitiatingProcessId, InitiatingProcessFileName,
     InitiatingProcessCommandLine, InitiatingProcessParentFileName,
     InitiatingProcessAccountName, bin(Timestamp, WindowMin)
| where DistinctCredPaths >= 8   // 8 = ~6x the 90-day P99 for a single dev-tool process; tune per env
| where InitiatingProcessFileName !in~ ("explorer.exe","OneDrive.exe","Code.exe","WindowsTerminal.exe")
| order by FirstSeen desc
```

### [LLM] Persistence backdoor: node/npm writes to Claude Code or VS Code user config

`UC_109_13` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.claude\\*" OR Filesystem.file_path="*/.claude/*" OR Filesystem.file_path="*\\AppData\\Roaming\\Code\\User\\settings.json" OR Filesystem.file_path="*\\.vscode\\extensions\\*" OR Filesystem.file_path="*/Library/Application Support/Code/User/settings.json" OR Filesystem.file_path="*/.config/Code/User/settings.json" OR Filesystem.file_path="*\\.vscode\\settings.json" OR Filesystem.file_path="*/.vscode/settings.json" OR Filesystem.file_path="*\\claude.json" OR Filesystem.file_path="*claude_desktop_config.json") (Filesystem.process_name="node.exe" OR Filesystem.process_name="node" OR Filesystem.process_name="npm.cmd" OR Filesystem.process_name="npx.cmd" OR Filesystem.process_name="yarn.cmd" OR Filesystem.process_name="pnpm.cmd") (Filesystem.action="created" OR Filesystem.action="modified") by host Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 30d;
DeviceFileEvents
| where Timestamp > ago(LookbackDays)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath matches regex @"(?i)(\\\.claude\\|/\.claude/|\\AppData\\Roaming\\Code\\User\\settings\.json|/Library/Application Support/Code/User/settings\.json|/\.config/Code/User/settings\.json|\\\.vscode\\(settings\.json|extensions\\)|/\.vscode/(settings\.json|extensions/)|claude_desktop_config\.json|\\claude\.json)"
| where InitiatingProcessFileName in~ ("node.exe","node","npm.cmd","npx.cmd","yarn.cmd","pnpm.cmd","corepack.exe","Runner.Worker.exe","bash.exe","sh")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessAccountName, ReportId
| order by Timestamp desc
```

### [LLM] GitHub repo created with reversed Shai-Hulud signature in description

`UC_109_14` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`github_audit` (action="repo.create" OR action="repo.update" OR action="public_repo.created") (description="*niagA oG eW ereH :duluH-iahS*" OR description="*Shai-Hulud: Here We Go Again*" OR repository_name="*Arrakis*" OR repository_name="*Muad*Dib*" OR repository_name="*Fremen*" OR repository_name="*Atreides*" OR repository_name="*Harkonnen*" OR repository_name="*Sandworm*" OR repository_name="*Bene*Gesserit*" OR repository_name="*Kwisatz*") | stats min(_time) as firstTime max(_time) as lastTime values(repository_name) as repos values(description) as descriptions count by actor_login org | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 30d;
CloudAppEvents
| where Timestamp > ago(LookbackDays)
| where Application has "GitHub"
| where ActionType in~ ("Create repository","Update repository","repo.create","repo.update","public_repo.created")
| extend Description = tostring(parse_json(RawEventData).description),
         RepoName    = tostring(parse_json(RawEventData).repository),
         Visibility  = tostring(parse_json(RawEventData).visibility)
| where Description has_any ("niagA oG eW ereH :duluH-iahS","Shai-Hulud: Here We Go Again","Sha1-Hulud: The Second Coming")
   or RepoName matches regex @"(?i)(Arrakis|Muad.?Dib|Fremen|Atreides|Harkonnen|Sandworm|Bene.?Gesserit|Kwisatz|Caladan|Sardaukar|Chani|Stilgar|Spice)"
| project Timestamp, AccountObjectId, AccountDisplayName, IPAddress, CountryCode,
          ActionType, RepoName, Description, Visibility, UserAgent, RawEventData
```

### [LLM] Compromised AntV / Shai-Hulud npm package version landed in node_modules

`UC_109_15` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_hash="a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c" OR Filesystem.file_hash="fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142" OR Filesystem.file_path="*\\node_modules\\timeago.js\\package.json" OR Filesystem.file_path="*/node_modules/timeago.js/package.json" OR Filesystem.file_path="*\\node_modules\\@antv\\*\\package.json" OR Filesystem.file_path="*/node_modules/@antv/*/package.json" OR Filesystem.file_path="*\\node_modules\\echarts-for-react\\package.json" OR Filesystem.file_path="*\\node_modules\\@lint-md\\*\\package.json") by host Filesystem.user Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 30d;
let BadHashes = dynamic([
  "a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c",
  "fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142"
]);
let BadPkgVersions = dynamic([
  "timeago.js@4.1.2","timeago.js@4.2.2",
  "timeago-react@3.1.7","timeago-react@3.2.7",
  "echarts-for-react@3.0.7","echarts-for-react@3.1.7","echarts-for-react@3.2.7",
  "jest-canvas-mock@2.5.3","jest-canvas-mock@2.6.3","jest-canvas-mock@2.7.3",
  "jest-date-mock@1.0.11","jest-date-mock@1.1.11","jest-date-mock@1.2.11",
  "size-sensor@1.0.4","size-sensor@1.1.4","size-sensor@1.2.4",
  "canvas-nest.js@2.1.4","canvas-nest.js@2.2.4",
  "@antv/g2@5.5.8","@antv/g2@5.6.8",
  "@antv/g6@5.2.1","@antv/g6@5.3.1",
  "@antv/f2@5.15.0","@antv/f2@5.16.0",
  "@antv/s2@2.8.1","@antv/s2@2.9.1",
  "@antv/x6@3.2.7","@antv/x6@3.3.7",
  "@antv/l7@2.26.10","@antv/l7@2.27.10"
]);
union
  (DeviceFileEvents
   | where Timestamp > ago(LookbackDays)
   | where SHA256 in (BadHashes)
   | project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
             InitiatingProcessFileName, InitiatingProcessCommandLine,
             InitiatingProcessAccountName, MatchReason = "sha256"),
  (DeviceFileEvents
   | where Timestamp > ago(LookbackDays)
   | where FolderPath matches regex @"(?i)node_modules[\\/](@antv[\\/][^\\/]+|timeago\.js|timeago-react|echarts-for-react|jest-canvas-mock|jest-date-mock|size-sensor|canvas-nest\.js|filesize\.js|onfire\.js|relationship\.js|ribbon\.js|slice\.js|word-width|lint-md|lint-md-cli|mcp-echarts|mcp-mermaid|@lint-md[\\/][^\\/]+)[\\/]package\.json$"
   | where ActionType in ("FileCreated","FileModified")
   | extend PkgJsonPath = FolderPath
   | project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
             InitiatingProcessFileName, InitiatingProcessCommandLine,
             InitiatingProcessAccountName, MatchReason = "path-of-compromised-package")
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

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### Phishing-link click correlated to endpoint execution

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Phishing-link click that drives endpoint execution within 60s ```
| tstats `summariesonly` earliest(_time) AS click_time
    from datamodel=Web
    where Web.action="allowed"
    by Web.src, Web.user, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| rename user AS recipient, dest AS clicked_domain, url AS clicked_url
| join type=inner recipient
    [| tstats `summariesonly` count
         from datamodel=Email.All_Email
         where All_Email.action="delivered" AND All_Email.url!="-"
         by All_Email.recipient, All_Email.src_user, All_Email.url, All_Email.subject
     | `drop_dm_object_name(All_Email)`
     | rex field=url "https?://(?<email_domain>[^/]+)"
     | rename recipient AS recipient]
| join type=inner src
    [| tstats `summariesonly` earliest(_time) AS exec_time
         values(Processes.process) AS exec_cmd, values(Processes.process_name) AS exec_proc
         from datamodel=Endpoint.Processes
         where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                                   "outlook.exe","brave.exe","arc.exe")
           AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                                            "rundll32.exe","regsvr32.exe","wscript.exe",
                                            "cscript.exe","bitsadmin.exe","certutil.exe",
                                            "curl.exe","wget.exe")
         by Processes.dest, Processes.user
     | `drop_dm_object_name(Processes)`
     | rename dest AS src]
| eval delta_sec = exec_time - click_time
| where delta_sec >= 0 AND delta_sec <= 60
| table click_time, exec_time, delta_sec, recipient, src, src_user, subject,
        clicked_domain, clicked_url, exec_proc, exec_cmd
| sort - click_time
```

**Defender KQL:**
```kql
// Phishing-link click that drives endpoint execution within 60s.
// Far higher fidelity than "every clicked URL" — most legitimate clicks
// never spawn a non-browser child process, so the join eliminates the
// 99% of noise that makes a raw click query unactionable.
let LookbackDays = 7d;
let SuspectClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(LookbackDays)
        | where DeliveryAction == "Delivered"
        | where EmailDirection == "Inbound"
        | project NetworkMessageId, Subject, SenderFromAddress, SenderFromDomain,
                  RecipientEmailAddress, EmailTimestamp = Timestamp
      ) on NetworkMessageId
    | join kind=leftouter (
        EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId, Url
    | project ClickTime = Timestamp, AccountUpn, IPAddress, Url, UrlDomain,
              Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
              ActionType;
// Correlate to a non-browser child process spawned within 60 seconds on
// the recipient's device.
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                         "outlook.exe","brave.exe","arc.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                        "rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe",
                        "bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| join kind=inner SuspectClicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + 60s)
| project ClickTime, ProcessTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountName, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, ActionType,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by ClickTime desc
```

### Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)

`UC_FAKECAPTCHA` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Shai-Hulud: Here We Go Again. Mass npm Supply Chain Attack Hits the AntV Ecosyst

`UC_109_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Shai-Hulud: Here We Go Again. Mass npm Supply Chain Attack Hits the AntV Ecosyst ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("timeago.js","canvas-nest.js","filesize.js","onfire.js","relationship.js","ribbon.js","slice.js","bun.exe","index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/rancher/k3s/k3s.yaml*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("timeago.js","canvas-nest.js","filesize.js","onfire.js","relationship.js","ribbon.js","slice.js","bun.exe","index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Shai-Hulud: Here We Go Again. Mass npm Supply Chain Attack Hits the AntV Ecosyst
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("timeago.js", "canvas-nest.js", "filesize.js", "onfire.js", "relationship.js", "ribbon.js", "slice.js", "bun.exe", "index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/rancher/k3s/k3s.yaml", "/dev/null") or FileName in~ ("timeago.js", "canvas-nest.js", "filesize.js", "onfire.js", "relationship.js", "ribbon.js", "slice.js", "bun.exe", "index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `t.m-kosche.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c`, `fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 16 use case(s) fired, 27 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
