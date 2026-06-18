# [CRIT] North Korean Hackers Are Turning Developer Tools Into Malware Delivery Channels

**Source:** The Hacker News
**Published:** 2026-06-15
**Article:** https://thehackernews.com/2026/06/north-korean-hackers-are-turning.html

## Threat Profile

North Korean Hackers Are Turning Developer Tools Into Malware Delivery Channels 
 Ravie Lakshmanan  Jun 15, 2026 Malware / Supply Chain Attack 
Cybersecurity researchers have flagged two malicious cyber campaigns that exhibit similarities with a persistent North Korean threat cluster known as Contagious Interview (aka Famous Chollima, HexagonalRodent, and Void Dokkaebi).
According to a report published by Proofpoint, the threat actor has been found orchestrating phishing campaigns using develo…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `23.137.105.75`
- **IPv4 (defanged):** `170.205.29.83`
- **IPv4 (defanged):** `170.205.30.227`
- **Domain (defanged):** `empowerpharmacy.space`
- **Domain (defanged):** `nxlog.tech`
- **Domain (defanged):** `ondofinance.tech`
- **Domain (defanged):** `valorecuiting.online`
- **Domain (defanged):** `migadyn.info`
- **Domain (defanged):** `contacttrixauvex.ink`
- **Domain (defanged):** `trixauvex.org`
- **Domain (defanged):** `pulsynk.org`
- **Domain (defanged):** `mailtrixauvex.ink`
- **Domain (defanged):** `mailpulsynk.xyz`
- **Domain (defanged):** `mailpredicttogether.ink`
- **Domain (defanged):** `predicttocareer.space`
- **Domain (defanged):** `onoplanoai.ink`
- **Domain (defanged):** `trixauvexnet.ink`
- **Domain (defanged):** `recruitvex.us`
- **Domain (defanged):** `nowurisch.fit`
- **Domain (defanged):** `hyperdevpipline.org`
- **Domain (defanged):** `nemesistrade.work`
- **Domain (defanged):** `ceronet.work`
- **Domain (defanged):** `deep-ai-guard.store`
- **Domain (defanged):** `ceronetwork.org`
- **Domain (defanged):** `culyrax.us`
- **Domain (defanged):** `elsavora.us`
- **Domain (defanged):** `optixauvex.us`
- **SHA256:** `35813f4401d3ad77b618275473a556eb47bfa6f4b7439dd8943b19f81aa7252e`
- **SHA256:** `c935808147f0236c81483d7bbeda4b9d602f3595d5d4057f8115d39e222d1c4b`
- **SHA256:** `4c0d9b802c075be79e9edb52d88f8dd72e6904f5c58267213745818470945c78`
- **SHA256:** `62761f38ed194c59abe15c49f09f0ebc431ac852c965180c9327ed84d3a454fb`
- **SHA256:** `d3ebce2f05fe91a8260e87fd11a6ea17c156703d081b3f91d9bbe5fd6aeedc10`
- **SHA256:** `91b9381d19b2e6a2db5cc0307167979b502731cb3fb50da684479e9ed35261aa`
- **SHA256:** `6cf9f7b2aa456a0b438600588df869b38d8007e28f01fa96022f9d8059f120b0`
- **SHA256:** `2812e0847d472cb8870c94f463331dbe53b84135132b9bf5f6d84c2382be628f`
- **SHA256:** `52886aab179f26421678ff23af1b0fabf0a17ffbb534369cdbbac8008cbed8e7`
- **SHA256:** `d5e9288693aa745dc89368deac677e7ea1ec81e663283af30838cdae189b7a7e`
- **SHA256:** `734699773e53d995f20d485eb61261033d9d00b4332b39ca26071bcd60cd352f`
- **SHA256:** `e1bf1b29e6fa3525d7f32f429290a88d6ea2890e61c06574b8ff6372aa5d0667`
- **SHA256:** `a2b9a769df84d9d3a4694bb0252a2c6a5e5f5d1a85a04565362737092bbb3a86`
- **SHA256:** `bb10adac5b0124efedfe71102c1d5638135ec9e1cde8c8cb3353c5ed91bb9f81`
- **SHA256:** `339907b44f161f57ff30819f422c552382ff437b3ae437463b4222cfe86bd943`
- **SHA256:** `808e7154b7af2bc7a4b28d577297c55f77221c355191cbe00f9f1810b6d4a619`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1059.003** — Windows Command Shell
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1505** — Server Software Component
- **T1546** — Event Triggered Execution
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059.007** — JavaScript
- **T1059.004** — Unix Shell
- **T1056.002** — GUI Input Capture

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### VS Code / Cursor auto-executing shell via tasks.json runOn:folderOpen (Contagious Interview / UNK_DeadDrop)

`UC_74_14` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("Code.exe","Cursor.exe","code.exe","cursor.exe")) (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","cscript.exe","wscript.exe","curl.exe","wget.exe","bash.exe","sh.exe") OR Processes.process IN ("*curl *| sh*","*wget *| sh*","*iwr *iex*","*Invoke-Expression*","*tasks.json*","*eslint-check*","*folderOpen*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where NOT match(process,"(?i)\\\\node_modules\\\\")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("Code.exe","Cursor.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","cscript.exe","wscript.exe","curl.exe","wget.exe","bash.exe","sh.exe","node.exe")
   or ProcessCommandLine has_any ("eslint-check","runOn","folderOpen","| sh","| bash","IEX","Invoke-Expression","DownloadString","curl -s","wget -q")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Windows VBScript loader spawning CMD to install malicious VSIX (UNK_DeadDrop Windows chain)

`UC_74_15` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.process_name IN ("code.exe","code-cli.exe","cursor.exe") Processes.process IN ("*--install-extension*","*.vsix*") (Processes.parent_process_name IN ("cmd.exe","wscript.exe","cscript.exe","powershell.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
let VsixInstall = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("code.exe","code-cli.exe","Cursor.exe")
| where ProcessCommandLine has "--install-extension"
   or ProcessCommandLine has ".vsix";
VsixInstall
| where InitiatingProcessFileName in~ ("cmd.exe","wscript.exe","cscript.exe","powershell.exe","pwsh.exe")
| where InitiatingProcessParentFileName !in~ ("explorer.exe","Code.exe","Cursor.exe")
| project Timestamp, DeviceName, AccountName,
          GrandParent = InitiatingProcessParentFileName,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
          Child = FileName, ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### C2 callback to UNK_DeadDrop infrastructure (23.137.105.75:5173 and named domains)

`UC_74_16` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as process from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("23.137.105.75","170.205.29.83","170.205.30.227") OR (All_Traffic.dest_ip="23.137.105.75" AND All_Traffic.dest_port=5173)) by All_Traffic.src All_Traffic.user | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
let C2_IPs = dynamic(["23.137.105.75","170.205.29.83","170.205.30.227"]);
let C2_Domains = dynamic(["empowerpharmacy.space","nxlog.tech","ondofinance.tech","valorecuiting.online","migadyn.info","contacttrixauvex.ink","trixauvex.org","pulsynk.org","mailtrixauvex.ink","mailpulsynk.xyz","mailpredicttogether.ink","predicttocareer.space","onoplanoai.ink","trixauvexnet.ink","recruitvex.us","nowurisch.fit","hyperdevpipline.org","nemesistrade.work","ceronet.work","deep-ai-guard.store"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (C2_IPs)
   or (RemoteIP == "23.137.105.75" and RemotePort == 5173)
   or RemoteUrl has_any (C2_Domains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### Malicious VS Code extension marketplace install (ByteBinTools / ToolCraft / OLDev jupyter VSIX)

`UC_74_17` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("ByteBinTools.jupyter-powerdev-2026.6.8.vsix","ToolCraft.jupyter-powertools-3.21.0.vsix","OLDev.markdown-mode-devtools-2.1.0.vsix") OR Filesystem.file_path IN ("*\\.vscode\\extensions\\bytebintools.jupyter-powerdev*","*\\.vscode\\extensions\\toolcraft.jupyter-powertools*","*\\.vscode\\extensions\\oldev.markdown-mode-devtools*")) by Filesystem.dest Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ (
    "ByteBinTools.jupyter-powerdev-2026.6.8.vsix",
    "ToolCraft.jupyter-powertools-3.21.0.vsix",
    "OLDev.markdown-mode-devtools-2.1.0.vsix")
   or FolderPath has_any (
    @"\.vscode\extensions\bytebintools.jupyter-powerdev",
    @"\.vscode\extensions\toolcraft.jupyter-powertools",
    @"\.vscode\extensions\oldev.markdown-mode-devtools")
   or SHA256 in ("35813f4401d3ad77b618275473a556eb47bfa6f4b7439dd8943b19f81aa7252e",
                 "c935808147f0236c81483d7bbeda4b9d602f3595d5d4057f8115d39e222d1c4b",
                 "4c0d9b802c075be79e9edb52d88f8dd72e6904f5c58267213745818470945c78",
                 "62761f38ed194c59abe15c49f09f0ebc431ac852c965180c9327ed84d3a454fb",
                 "d3ebce2f05fe91a8260e87fd11a6ea17c156703d081b3f91d9bbe5fd6aeedc10")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, FolderPath, SHA256
| order by Timestamp desc
```

### Git hook auto-execution post-clone (Contagious Interview .githooks/pre-commit)

`UC_74_18` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*\\.githooks\\pre-commit*","*/.githooks/pre-commit*","*\\.githooks\\post-checkout*","*/.githooks/post-checkout*")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let HookFiles = DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has ".githooks"
   and FileName in~ ("pre-commit","post-checkout","post-merge","post-clone")
| where InitiatingProcessFileName !in~ ("git.exe","GitHubDesktop.exe")
   or InitiatingProcessCommandLine has_any ("clone","fetch","pull")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine;
let HookExec = DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("git.exe","git-bash.exe","sh.exe","bash.exe")
   and InitiatingProcessCommandLine has_any ("pre-commit","post-checkout",".githooks")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","cscript.exe","wscript.exe","curl.exe","wget.exe","node.exe","python.exe","python3.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine;
HookFiles | union HookExec | order by Timestamp desc
```

### DPRK npm supply-chain install (redeem-onchain-sdk / nicegui / period-newline Axios follow-up)

`UC_74_19` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.process_name IN ("npm.exe","npm-cli.js","yarn.exe","pnpm.exe","node.exe") (Processes.process IN ("*redeem-onchain-sdk*","*nicegui@0.1.4*","*period-newline*")) by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
let BadPackages = dynamic(["redeem-onchain-sdk","period-newline","nicegui@0.1.4"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe")
| where ProcessCommandLine has_any (BadPackages)
| union (
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has_any (@"\node_modules\redeem-onchain-sdk",@"\node_modules\period-newline",@"\node_modules\nicegui")
    | where FileName in~ ("package.json","index.js","postinstall.js")
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              FolderPath, FileName, SHA256)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Overlord macOS / Linux loader — osascript fake security prompt + curl to staging

`UC_74_20` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.os IN ("Darwin","Linux","macOS") (Processes.process_name="osascript" Processes.process="*display dialog*" Processes.process="*password*" Processes.process="*with hidden answer*") OR (Processes.process_name IN ("curl","wget") Processes.process IN ("*hyperdevpipline.org*","*nemesistrade.work*","*ceronet.work*","*recruitvex.us*","*deep-ai-guard.store*","*23.137.105.75*")) by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceName has_any ("mac","linux") or InitiatingProcessFolderPath has_any ("/Users/","/home/","/tmp/")
| where (FileName == "osascript"
        and ProcessCommandLine has "display dialog"
        and ProcessCommandLine has "with hidden answer"
        and ProcessCommandLine has_any ("password","security","authorize"))
     or (FileName in ("curl","wget")
        and ProcessCommandLine has_any ("hyperdevpipline.org","nemesistrade.work","ceronet.work","recruitvex.us","deep-ai-guard.store","23.137.105.75","nxlog.tech","ondofinance.tech"))
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
          Child = FileName, ChildCmd = ProcessCommandLine, SHA256
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

### Email attachment opened from external sender

`UC_PHISH_ATTACH` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.file_name!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.file_name, All_Email.subject
| rename All_Email.recipient as user
| join type=inner user
    [| tstats `summariesonly` count
        from datamodel=Endpoint.Processes
        where Processes.parent_process_name IN ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
          AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
        by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
     | rename Processes.user as user]
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let MalAttachments = EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | project NetworkMessageId, RecipientEmailAddress,
              AttachmentFileName = FileName, AttachmentSHA256 = SHA256;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                      "mshta.exe","rundll32.exe","regsvr32.exe")
| join kind=inner MalAttachments on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AttachmentFileName, AttachmentSHA256
```

### Office app spawning script/LOLBin child process

`UC_OFFICE_CHILD` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `23.137.105.75`, `170.205.29.83`, `170.205.30.227`, `empowerpharmacy.space`, `nxlog.tech`, `ondofinance.tech`, `valorecuiting.online`, `migadyn.info` _(+19 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `35813f4401d3ad77b618275473a556eb47bfa6f4b7439dd8943b19f81aa7252e`, `c935808147f0236c81483d7bbeda4b9d602f3595d5d4057f8115d39e222d1c4b`, `4c0d9b802c075be79e9edb52d88f8dd72e6904f5c58267213745818470945c78`, `62761f38ed194c59abe15c49f09f0ebc431ac852c965180c9327ed84d3a454fb`, `d3ebce2f05fe91a8260e87fd11a6ea17c156703d081b3f91d9bbe5fd6aeedc10`, `91b9381d19b2e6a2db5cc0307167979b502731cb3fb50da684479e9ed35261aa`, `6cf9f7b2aa456a0b438600588df869b38d8007e28f01fa96022f9d8059f120b0`, `2812e0847d472cb8870c94f463331dbe53b84135132b9bf5f6d84c2382be628f` _(+8 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 21 use case(s) fired, 30 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
