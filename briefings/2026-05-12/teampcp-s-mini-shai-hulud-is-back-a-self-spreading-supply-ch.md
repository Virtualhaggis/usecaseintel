# [CRIT] TeamPCP's Mini Shai-Hulud Is Back: A Self-Spreading Supply Chain Attack Compromises TanStack npm Packages

**Source:** StepSecurity
**Published:** 2026-05-12
**Article:** https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem

## Threat Profile

Back to Blog Threat Intel TeamPCP's Mini Shai-Hulud Is Back: A Self-Spreading Supply Chain Attack Compromises TanStack npm Packages TeamPCP has launched a new wave of their Mini Shai-Hulud worm. The self-propagating malware, which spreads by stealing CI/CD secrets, compromised several @tanstack npm packages, collectively downloaded millions of times per week. Ashish Kurmi View LinkedIn May 11, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents L…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45321`
- **IPv4 (defanged):** `83.142.209.194`
- **Domain (defanged):** `git-tanstack.com`
- **Domain (defanged):** `api.masscan.cloud`
- **Domain (defanged):** `litter.catbox.moe`
- **Domain (defanged):** `filev2.getsession.org`
- **SHA256:** `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
- **SHA256:** `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- **SHA256:** `2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df`
- **SHA256:** `1e8538c6e0563d50da0f2e097e979ebd5294ce1defe01d0b9fe361ba3bed1898`
- **SHA1:** `e7d582b98ca80690883175470e96f703ef6dc497`
- **SHA1:** `12f35b1081b17d21815b35feb57ab03d02482116`
- **SHA1:** `820fa07a7328b6cf2b417078e103721d4d8f2e79`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1543.001** — Persistence (article-specific)
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1568** — Dynamic Resolution
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546** — Event Triggered Execution
- **T1567.002** — Exfiltration to Cloud Storage
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1552.001** — Unsecured Credentials: Credentials in Files
- **T1555** — Credentials from Password Stores
- **T1083** — File and Directory Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Mini Shai-Hulud npm Worm C2 callback to Session Protocol CDN and masscan.cloud

`UC_236_9` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("seed1.getsession.org","filev2.getsession.org","api.masscan.cloud","*.getsession.org","*.masscan.cloud") by DNS.src DNS.dest DNS.query DNS.answer | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("seed1.getsession.org","filev2.getsession.org","api.masscan.cloud") by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CampaignHosts = dynamic(["seed1.getsession.org","filev2.getsession.org","api.masscan.cloud"]);
let NetHits = DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has_any (CampaignHosts) or tostring(parse_url(RemoteUrl).Host) in~ (CampaignHosts)
  | project Timestamp, DeviceName, AccountUpn=InitiatingProcessAccountUpn, Indicator=coalesce(RemoteUrl, RemoteIP), Source="network", InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName;
let EvHits = DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType in ("DnsQueryResponse","ConnectionSuccess","ConnectionFailed","NetworkConnectionEvents")
  | where RemoteUrl has_any (CampaignHosts) or AdditionalFields has_any (CampaignHosts)
  | project Timestamp, DeviceName, AccountUpn=InitiatingProcessAccountUpn, Indicator=coalesce(RemoteUrl, tostring(AdditionalFields)), Source="device-event", InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName=tostring(parse_json(""));
NetHits
| union EvHits
| order by Timestamp desc
```

### TeamPCP Mini Shai-Hulud stealer payload hash match (SHA256/SHA1)

`UC_236_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_sha256 IN ("ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c","0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa","2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96","7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process Processes.process_sha256 | `drop_dm_object_name(Processes)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c","0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa","2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96","7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b","79ac49eedf774dd4b0cfa308722bc463cfe5885c","de0fac2e4500dabe0009e67214ff5f5447ce83dd","bbbca2ddaa5d8feaa63e36b76fdaad77386f024f") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let StealerSha256 = dynamic(["ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c","0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa","2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96","7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b"]);
let StealerSha1 = dynamic(["79ac49eedf774dd4b0cfa308722bc463cfe5885c","de0fac2e4500dabe0009e67214ff5f5447ce83dd","bbbca2ddaa5d8feaa63e36b76fdaad77386f024f"]);
let ProcHits = DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA256 in~ (StealerSha256) or SHA1 in~ (StealerSha1) or InitiatingProcessSHA256 in~ (StealerSha256) or InitiatingProcessSHA1 in~ (StealerSha1)
  | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, Source="DeviceProcessEvents";
let FileHits = DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA256 in~ (StealerSha256) or SHA1 in~ (StealerSha1)
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, Source="DeviceFileEvents";
let ImgHits = DeviceImageLoadEvents
  | where Timestamp > ago(30d)
  | where SHA256 in~ (StealerSha256) or SHA1 in~ (StealerSha1)
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, Source="DeviceImageLoadEvents";
ProcHits | union FileHits, ImgHits
| order by Timestamp desc
```

### Mini Shai-Hulud router_init.js dropped at npm package root in node_modules

`UC_236_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="router_init.js" Filesystem.file_path="*node_modules*" (Filesystem.file_size>1000000 OR Filesystem.file_size="*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed")
| where FileName =~ "router_init.js"
| where FolderPath has "node_modules"
| where FileSize > 1000000  // clean tarball baseline is no router_init.js; compromised version is ~2.3MB single line
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","npm","node","pnpm.exe","yarn.exe","bun.exe","bun","corepack.exe")
   or InitiatingProcessParentFileName in~ ("node.exe","npm.exe","pnpm.exe","yarn.exe","bun.exe","corepack.exe")
| project Timestamp, DeviceName, FolderPath, FileName, FileSize, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Mini Shai-Hulud dead-drop git commit authored as claude@users.noreply.github.com

`UC_236_12` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="git.exe" OR Processes.process_name="git") (Processes.process="*claude@users.noreply.github.com*" OR Processes.process="*-c user.email=claude@users.noreply.github.com*" OR Processes.process="*GIT_AUTHOR_EMAIL=claude@users.noreply.github.com*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("git.exe","git") or InitiatingProcessFileName in~ ("git.exe","git")
| where ProcessCommandLine has "claude@users.noreply.github.com"
   or InitiatingProcessCommandLine has "claude@users.noreply.github.com"
   or (ProcessCommandLine has "commit" and ProcessCommandLine has_any ("--author","user.email"))
| extend DuneBranchHint = extract(@"(?i)dependabot[-_/]+(arrakis|fremen|paul|atreides|harkonnen|leto|muad'dib|muaddib|shai-hulud|stilgar|gurney|duncan|chani|jessica|spice|melange|sardaukar|bene-gesserit|kwisatz)", 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, DuneBranchHint
| order by Timestamp desc
```

### Node/npm/Bun process enumerating cloud, wallet, AI, and messaging credential file paths

`UC_236_13` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count dc(Filesystem.file_path) as DistinctPaths min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("node.exe","node","npm.exe","npm","pnpm.exe","yarn.exe","bun.exe","bun") (Filesystem.file_path="*\\.aws\\credentials*" OR Filesystem.file_path="*\\.aws\\config*" OR Filesystem.file_path="*\\.npmrc*" OR Filesystem.file_path="*\\.config\\gh\\hosts.yml*" OR Filesystem.file_path="*\\.config\\gcloud\\*" OR Filesystem.file_path="*\\.azure\\accessTokens.json*" OR Filesystem.file_path="*\\.kube\\config*" OR Filesystem.file_path="*\\.docker\\config.json*" OR Filesystem.file_path="*\\.ssh\\id_*" OR Filesystem.file_path="*\\AppData\\Roaming\\Claude*" OR Filesystem.file_path="*\\AppData\\Roaming\\Cursor*" OR Filesystem.file_path="*\\AppData\\Roaming\\Code\\User\\globalStorage*" OR Filesystem.file_path="*wallet.dat*" OR Filesystem.file_path="*\\Local\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\*" OR Filesystem.file_path="*\\.env*" OR Filesystem.file_path="*\\Slack\\Cookies*" OR Filesystem.file_path="*\\Discord\\Local Storage\\leveldb\\*" OR Filesystem.file_path="*\\Telegram Desktop\\tdata\\*") by Filesystem.dest Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where DistinctPaths >= 6 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CredPaths = dynamic([
  @"\.aws\credentials", @"\.aws\config", @".npmrc", @"\.config\gh\hosts.yml",
  @"\.config\gcloud\", @"\.azure\accessTokens.json", @"\.kube\config",
  @"\.docker\config.json", @"\.ssh\id_", @"\AppData\Roaming\Claude",
  @"\AppData\Roaming\Cursor", @"\AppData\Roaming\Code\User\globalStorage",
  "wallet.dat", @"\Local Extension Settings\", @"\Slack\Cookies",
  @"\Discord\Local Storage\leveldb", @"\Telegram Desktop\tdata",
  ".env", @"\Local\Programs\Ollama", @"\.netrc"
]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileAccessed","FileCreated","FileRenamed","FileModified")
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","pnpm.exe","yarn.exe","bun.exe","corepack.exe")
| where FolderPath has_any (CredPaths) or FileName has_any (CredPaths)
| where InitiatingProcessParentFileName !in~ ("code.exe","cursor.exe","claude.exe")  // strip dev IDEs auto-reading own settings
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), DistinctPaths=dcount(FolderPath), SamplePaths=make_set(strcat(FolderPath,"\\",FileName), 10)
          by DeviceName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessAccountName
| where DistinctPaths >= 6   // empirical: stealer fan-out >> any single legit operation
| order by LastSeen desc
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

### Article-specific behavioural hunt — TeamPCP's Mini Shai-Hulud Is Back: A Self-Spreading Supply Chain Attack Compromi

`UC_236_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — TeamPCP's Mini Shai-Hulud Is Back: A Self-Spreading Supply Chain Attack Compromi ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("bun.exe","npm-cli.js","install.js","opensearch_init.js","tanstack_runner.js","router_init.js","payload_5.py","payload_1.sh","token-monitor.sh","router_runtime.js","node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/var/run/secrets/kubernetes.io/serviceaccount/token*" OR Filesystem.file_path="*/etc/rancher/k3s/k3s.yaml*" OR Filesystem.file_path="*/var/lib/docker/containers/*" OR Filesystem.file_path="*/Library/LaunchAgents/*" OR Filesystem.file_path="*/Library/LaunchAgents/com.user.gh-token-monitor.plist*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("bun.exe","npm-cli.js","install.js","opensearch_init.js","tanstack_runner.js","router_init.js","payload_5.py","payload_1.sh","token-monitor.sh","router_runtime.js","node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — TeamPCP's Mini Shai-Hulud Is Back: A Self-Spreading Supply Chain Attack Compromi
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("bun.exe", "npm-cli.js", "install.js", "opensearch_init.js", "tanstack_runner.js", "router_init.js", "payload_5.py", "payload_1.sh", "token-monitor.sh", "router_runtime.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/var/run/secrets/kubernetes.io/serviceaccount/token", "/etc/rancher/k3s/k3s.yaml", "/var/lib/docker/containers/", "/Library/LaunchAgents/", "/Library/LaunchAgents/com.user.gh-token-monitor.plist", "/dev/null") or FileName in~ ("bun.exe", "npm-cli.js", "install.js", "opensearch_init.js", "tanstack_runner.js", "router_init.js", "payload_5.py", "payload_1.sh", "token-monitor.sh", "router_runtime.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `83.142.209.194`, `git-tanstack.com`, `api.masscan.cloud`, `litter.catbox.moe`, `filev2.getsession.org`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-45321`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`, `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`, `2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df`, `1e8538c6e0563d50da0f2e097e979ebd5294ce1defe01d0b9fe361ba3bed1898`, `e7d582b98ca80690883175470e96f703ef6dc497`, `12f35b1081b17d21815b35feb57ab03d02482116`, `820fa07a7328b6cf2b417078e103721d4d8f2e79`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
