# [CRIT] Grafana GitHub Breach Exposes Source Code via TanStack npm Attack

**Source:** The Hacker News, BleepingComputer, Aikido
**Published:** 2026-05-20
**Article:** https://thehackernews.com/2026/05/grafana-github-breach-exposes-source.html

## Threat Profile

Blog Vulnerabilities & Threats Mini Shai-Hulud strikes again: npm worm compromises hundreds of @antv packages Mini Shai-Hulud strikes again: npm worm compromises hundreds of @antv packages Written by Sooraj Shah Published on: May 19, 2026 Mini Shai-Hulud is back again.
The npm supply chain campaign we have been tracking since April has launched another wave, this time compromising major packages in Alibaba's @antv suite along with echarts-for-react and timeago.js . Our malware team detected a la…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `t.m-kosche.com`
- **Domain (defanged):** `filev2.getsession.org`
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
- **T1204.002** — Malicious File
- **T1105** — Ingress Tool Transfer
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1552.001** — Credentials In Files
- **T1552.004** — Private Keys
- **T1555.005** — Password Managers
- **T1528** — Steal Application Access Token
- **T1021.007** — Remote Services: Cloud Services
- **T1651** — Cloud Administration Command
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1568** — Dynamic Resolution
- **T1485** — Data Destruction
- **T1657** — Financial Theft
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Malicious durabletask PyPI package install (versions 1.4.1-1.4.3)

`UC_33_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip","pip3","python","python3","poetry","uv") AND Processes.process="*durabletask*" AND (Processes.process="*1.4.1*" OR Processes.process="*1.4.2*" OR Processes.process="*1.4.3*")) by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Trojanized durabletask install — TeamPCP Mini Shai-Hulud
let bad_versions = dynamic(["durabletask==1.4.1","durabletask==1.4.2","durabletask==1.4.3","durabletask-1.4.1","durabletask-1.4.2","durabletask-1.4.3"]);
let ProcessHits = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("pip","pip3","python","python3","poetry","uv")
    | where ProcessCommandLine has "durabletask"
    | where ProcessCommandLine matches regex @"durabletask[\s=<>~!\-_]+1\.4\.[123](\D|$)"
       or ProcessCommandLine has_any (bad_versions)
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, EvidenceType="ProcessExec";
let FileHits = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has "site-packages"
    | where FolderPath matches regex @"durabletask[-_]1\.4\.[123]"
       or FileName matches regex @"durabletask[-_]1\.4\.[123]"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, EvidenceType="FileWrite";
union ProcessHits, FileHits
| order by Timestamp desc
```

### [LLM] Python interpreter fetches rope.pyz dropper from check.git-service.com

`UC_33_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where ((All_Traffic.dest IN ("check.git-service.com","t.m-kosche.com") OR All_Traffic.dest_ip="83.142.209.194") AND All_Traffic.app IN ("python","python3","curl","wget","pip","pip3")) by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_ip All_Traffic.app All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// rope.pyz second-stage retrieval — TeamPCP C2 domains
let c2_domains = dynamic(["check.git-service.com","t.m-kosche.com"]);
let c2_ips = dynamic(["83.142.209.194"]);
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where (RemoteUrl has_any (c2_domains)) or (RemoteIP in (c2_ips))
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort, EvidenceType="NetworkConnect";
let RopeFile = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "rope.pyz"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName="", RemoteUrl=FileOriginUrl, RemoteIP=tostring(FileOriginIP), RemotePort=int(null), EvidenceType="FileDrop";
union NetHits, RopeFile
| order by Timestamp desc
```

### [LLM] Linux Python stealer harvesting cloud, vault, SSH and password-manager secrets

`UC_33_12` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(Filesystem.file_path) as paths_touched dc(Filesystem.file_path) as path_count from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("python","python3") (Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.bash_history" OR Filesystem.file_path="*/.zsh_history" OR Filesystem.file_path="*/.vault-token" OR Filesystem.file_path="*/1Password*" OR Filesystem.file_path="*/Bitwarden*" OR Filesystem.file_path="*/op/config") by Filesystem.dest Filesystem.user Filesystem.process_guid _time span=5m | `drop_dm_object_name(Filesystem)` | where path_count>=3
```

**Defender KQL:**
```kql
// rope.pyz infostealer cred-harvest fan-out — Linux
let cred_globs = dynamic([
    "/.aws/credentials","/.aws/config",
    "/.ssh/id_rsa","/.ssh/id_ed25519","/.ssh/id_ecdsa","/.ssh/known_hosts",
    "/.docker/config.json","/.dockercfg",
    "/.bash_history","/.zsh_history",
    "/.vault-token",
    "/.config/op","/.config/1Password","/.config/Bitwarden",
    "/.netrc","/.kube/config"
]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName in ((DeviceInfo | where OSPlatform in ("Linux","linux") | distinct DeviceName))
   or InitiatingProcessFolderPath startswith "/"
| where InitiatingProcessFileName in~ ("python","python3")
| where ActionType in ("FileAccessed","FileCreated","FileModified","FileRenamed")
| extend FullPath = strcat(FolderPath, "/", FileName)
| where FullPath has_any (cred_globs)
| summarize PathsTouched = make_set(FullPath, 50), DistinctPaths = dcount(FullPath), Count = count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
          by DeviceName, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName, bin(Timestamp, 5m)
| where DistinctPaths >= 3
| order by LastSeen desc
```

### [LLM] Mini Shai-Hulud worm propagation via AWS SSM SendCommand fan-out

`UC_33_13` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`cloudtrail` eventName=SendCommand eventSource=ssm.amazonaws.com requestParameters.documentName=AWS-RunShellScript (requestParameters.parameters.commands{}="*rope.pyz*" OR requestParameters.parameters.commands{}="*check.git-service.com*" OR requestParameters.parameters.commands{}="*t.m-kosche.com*" OR requestParameters.parameters.commands{}="*curl*") | stats min(_time) as firstTime max(_time) as lastTime dc(requestParameters.instanceIds{}) as instance_count values(requestParameters.instanceIds{}) as instances values(sourceIPAddress) as srcIPs by userIdentity.arn userIdentity.userName userIdentity.accessKeyId | where instance_count>=3 | convert ctime(firstTime) ctime(lastTime)
```

### [LLM] FIRESCALE backup-C2 lookup via GitHub commit-message search

`UC_33_14` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Web.Web where (Web.url="*api.github.com/search/commits*FIRESCALE*" OR Web.url="*api.github.com*q=FIRESCALE*" OR Web.url="*api.github.com*FIRESCALE*") by Web.src Web.user Web.url Web.app _time | `drop_dm_object_name(Web)`
```

**Defender KQL:**
```kql
// FIRESCALE dead-drop resolver — GitHub commit-search query
let PrimaryUrlHit = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has "api.github.com"
    | where RemoteUrl has "FIRESCALE" or RemoteUrl has "search/commits"
    | where RemoteUrl has "FIRESCALE"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, EvidenceType="NetEvent";
let CmdHit = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has "api.github.com"
    | where ProcessCommandLine has "FIRESCALE" or (ProcessCommandLine has "search/commits" and ProcessCommandLine has_any ("q=","FIRESCALE"))
    | project Timestamp, DeviceName, InitiatingProcessFileName=FileName, InitiatingProcessCommandLine=ProcessCommandLine, RemoteUrl="", RemoteIP="", EvidenceType="Process";
union PrimaryUrlHit, CmdHit
| order by Timestamp desc
```

### [LLM] Locale-gated destructive payload: python parent spawns rm -rf / on Linux

`UC_33_15` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3") AND (Processes.process_name IN ("rm","sh","bash","dash")) AND (Processes.process="*rm * -rf */*" OR Processes.process="*rm -rf /" OR Processes.process="*rm -rf /*" OR Processes.process="*--no-preserve-root*") by Processes.dest Processes.user Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Locale-gated destructive payload — python -> rm -rf /
let RmHits = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("python","python3")
    | where FileName in~ ("rm","sh","bash","dash","zsh")
    | where ProcessCommandLine matches regex @"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)(\s+--no-preserve-root)?\s+(/(\s|$|\*)|/\*)"
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName, EvidenceType="rm_rf";
let AudioHits = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("python","python3")
    | where FileName in~ ("aplay","paplay","mpg123","ffplay","play")
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName, EvidenceType="audio_taunt";
let LocaleHits = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("python","python3")
    | where ProcessCommandLine has_any ("he_IL","fa_IR","LANG=he","LANG=fa","locale -a","localectl")
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName, EvidenceType="locale_check";
union RmHits, AudioHits, LocaleHits
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

### Article-specific behavioural hunt — Grafana GitHub Breach Exposes Source Code via TanStack npm Attack

`UC_33_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Grafana GitHub Breach Exposes Source Code via TanStack npm Attack ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("timeago.js","canvas-nest.js","index.js","router_init.js","filesize.js","onfire.js","relationship.js","ribbon.js","slice.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("timeago.js","canvas-nest.js","index.js","router_init.js","filesize.js","onfire.js","relationship.js","ribbon.js","slice.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Grafana GitHub Breach Exposes Source Code via TanStack npm Attack
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("timeago.js", "canvas-nest.js", "index.js", "router_init.js", "filesize.js", "onfire.js", "relationship.js", "ribbon.js", "slice.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("timeago.js", "canvas-nest.js", "index.js", "router_init.js", "filesize.js", "onfire.js", "relationship.js", "ribbon.js", "slice.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `t.m-kosche.com`, `filev2.getsession.org`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c`, `1916faa365f2788b6e193514872d51a242876569`, `7cb42f57561c321ecb09b4552802ae0ac55b3a7a`, `dc3d62a2181beb9f326952a2d212900c94f2e13d`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 16 use case(s) fired, 29 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
