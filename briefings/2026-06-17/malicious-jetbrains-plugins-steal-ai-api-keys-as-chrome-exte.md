# [CRIT] Malicious JetBrains Plugins Steal AI API Keys as Chrome Extensions Capture Chatbot Chats

**Source:** The Hacker News
**Published:** 2026-06-17
**Article:** https://thehackernews.com/2026/06/malicious-jetbrains-plugins-steal-ai.html

## Threat Profile

Malicious JetBrains Plugins Steal AI API Keys as Chrome Extensions Capture Chatbot Chats 
 Ravie Lakshmanan  Jun 17, 2026 Supply Chain Security / AI Security 
Cybersecurity researchers have flagged a "coordinated malware campaign" on the JetBrains Marketplace that has published no less than 15 malicious plugins capable of exfiltrating artificial intelligence (AI) provider keys.
"Every plugin poses as an AI coding assistant built on DeepSeek and other large language models, offering chat, commi…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `39.107.60.51`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1567** — Exfiltration Over Web Service
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1056.003** — Web Portal Capture
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### JetBrains IDE outbound to malicious AI-plugin exfil IP 39.107.60.51

`UC_3_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_ports values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="39.107.60.51" by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.process All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | where match(process, "(?i)(idea64|idea|pycharm64|pycharm|webstorm64|phpstorm64|rubymine64|clion64|goland64|datagrip64|rider64|fleet|appcode)\.exe$") OR match(app, "(?i)jetbrains|intellij|pycharm|webstorm|phpstorm|rubymine|clion|goland|datagrip|rider|fleet")
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "39.107.60.51"
| where InitiatingProcessFileName in~ ("idea64.exe","idea.exe","pycharm64.exe","pycharm.exe","webstorm64.exe","phpstorm64.exe","rubymine64.exe","clion64.exe","goland64.exe","datagrip64.exe","rider64.exe","fleet.exe","appcode.exe")
    or InitiatingProcessFolderPath has_any (@"\JetBrains\", "jetbrains")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### Malicious Chrome adblocker extension install (PromptSnatcher IDs)

`UC_3_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files values(Filesystem.process) as process from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\Extensions\\iojpcjjdfhlcbgjnpngcmaojmlokmeii\\*" OR Filesystem.file_path="*\\Extensions\\jcbjcocinigpbgfpnhlpagidbmlngnnn\\*") by Filesystem.dest Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(180d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath has_any (@"\Extensions\iojpcjjdfhlcbgjnpngcmaojmlokmeii\", @"\Extensions\jcbjcocinigpbgfpnhlpagidbmlngnnn\")
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Files = make_set(FileName, 25), Writers = make_set(InitiatingProcessFileName, 5) by DeviceName, InitiatingProcessAccountName, ExtensionId = extract(@"\\Extensions\\([a-z]{32})\\", 1, FolderPath)
| order by FirstSeen desc
```

### JetBrains plugin install matching Aikido malicious DeepSeek/CodeGPT plugin set

`UC_3_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files values(Filesystem.process) as process from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\JetBrains\\*\\plugins\\*" OR Filesystem.file_path="*\\.IntelliJIdea*\\config\\plugins\\*" OR Filesystem.file_path="*\\.PyCharm*\\config\\plugins\\*" OR Filesystem.file_path="*\\.WebStorm*\\config\\plugins\\*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | search file_path IN ("*DeepSeek Junit*","*DeepSeek Git Commit*","*DeepSeek FindBugs*","*DeepSeek AI Chat*","*DeepSeek Dev AI*","*DeepSeek AI Coding*","*AI FindBugs*","*AI Git Commitor*","*AI Coder Review*","*DeepSeek Coder AI*","*AI Coder Assistant*","*DeepSeek Code Review*","*CodeGPT AI Assistant*","*DeepSeek AI Assist*","*Coding Simple Tool*")
```

**Defender KQL:**
```kql
let MaliciousPluginNames = dynamic(["DeepSeek Junit Test","DeepSeek Git Commit","DeepSeek FindBugs","DeepSeek AI Chat","DeepSeek Dev AI","DeepSeek AI Coding","AI FindBugs","AI Git Commitor","AI Coder Review","DeepSeek Coder AI","AI Coder Assistant","DeepSeek Code Review","CodeGPT AI Assistant","DeepSeek AI Assist","Coding Simple Tool"]);
let MaliciousPluginIds = dynamic(["org.sm.yms.toolkit","com.json.simple.kit","org.bug.find.tools","org.translate.ai.simple","com.yy.test.ai.simple","com.dev.ai.toolkit","com.json.view.simple","com.my.git.ai.kit","org.check.ai.ds","com.review.tool.code","org.code.assist.dev.tool","com.coder.ai.dpt","com.my.code.tools","ord.cp.code.ai.kit","com.dp.git.ai.tool"]);
DeviceFileEvents
| where Timestamp > ago(240d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath has "plugins" and (FolderPath has @"\JetBrains\" or FolderPath has @"\.IntelliJIdea" or FolderPath has @"\.PyCharm" or FolderPath has @"\.WebStorm" or FolderPath has @"\.PhpStorm" or FolderPath has @"\.GoLand" or FolderPath has @"\.RubyMine" or FolderPath has @"\.CLion" or FolderPath has @"\.DataGrip" or FolderPath has @"\.Rider")
| where FolderPath has_any (MaliciousPluginNames) or FileName has_any (MaliciousPluginIds) or FolderPath has_any (MaliciousPluginIds)
| summarize FirstSeen = min(Timestamp), Files = make_set(FileName, 50) by DeviceName, InitiatingProcessAccountName, FolderPath, InitiatingProcessFileName
| order by FirstSeen desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `39.107.60.51`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 7 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
