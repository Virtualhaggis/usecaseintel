# [CRIT] Popular GitHub Action Tags Redirected to Imposter Commit to Steal CI/CD Credentials

**Source:** The Hacker News, Aikido, StepSecurity
**Published:** 2026-05-19
**Article:** https://thehackernews.com/2026/05/github-actions-supply-chain-attack.html

## Threat Profile

Back to Blog Threat Intel Shai-Hulud: Here We Go Again. Mass npm Supply Chain Attack Hits the AntV Ecosystem A new wave of the Mini Shai-Hulud worm has compromised packages across Alibaba's AntV data visualization ecosystem, echarts-for-react, timeago.js, and dozens more. Stolen CI/CD secrets are being dumped to thousands of public GitHub repositories as the attack continues to spread. Sai Likhith View LinkedIn May 19, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `t.m-kosche.com`
- **SHA256:** `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c`
- **SHA1:** `1916faa365f2788b6e193514872d51a242876569`
- **SHA1:** `7cb42f57561c321ecb09b4552802ae0ac55b3a7a`
- **SHA1:** `dc3d62a2181beb9f326952a2d212900c94f2e13d`

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

`UC_38_10` · phase: **delivery** · confidence: **High**

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

`UC_38_11` · phase: **c2** · confidence: **High**

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

`UC_38_12` · phase: **install** · confidence: **High**

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

`UC_38_13` · phase: **actions** · confidence: **High**

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

`UC_38_14` · phase: **actions** · confidence: **High**

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

### Article-specific behavioural hunt — Popular GitHub Action Tags Redirected to Imposter Commit to Steal CI/CD Credenti

`UC_38_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Popular GitHub Action Tags Redirected to Imposter Commit to Steal CI/CD Credenti ```
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
// Article-specific bespoke detection — Popular GitHub Action Tags Redirected to Imposter Commit to Steal CI/CD Credenti
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
  - file hash IOC(s): `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c`, `1916faa365f2788b6e193514872d51a242876569`, `7cb42f57561c321ecb09b4552802ae0ac55b3a7a`, `dc3d62a2181beb9f326952a2d212900c94f2e13d`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 15 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
