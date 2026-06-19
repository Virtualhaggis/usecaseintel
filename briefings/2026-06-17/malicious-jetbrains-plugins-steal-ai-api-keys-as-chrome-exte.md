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
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1119** — Automated Collection
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1547.014** — Boot or Logon Autostart Execution: Active Setup
- **T1505.003** — Server Software Component

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### JetBrains IDE plaintext HTTP egress to public IP (LLMjacking exfil pattern)

`UC_85_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.app) as app values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic where All_Traffic.dest="39.107.60.51" by All_Traffic.dest All_Traffic.dest_port All_Traffic.transport | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let JetBrainsProcs = dynamic(["idea64.exe","idea.exe","pycharm64.exe","webstorm64.exe","phpstorm64.exe","clion64.exe","rider64.exe","goland64.exe","datagrip64.exe","rustrover64.exe","rubymine64.exe","appcode.exe","studio64.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "39.107.60.51"
| extend IsJetBrainsHost = InitiatingProcessFileName in~ (JetBrainsProcs)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol, IsJetBrainsHost
| order by Timestamp desc
```

### Malicious JetBrains Marketplace plugin package-ID dropped under user plugins dir

`UC_85_5` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*\\JetBrains\\*\\plugins\\*org.sm.yms.toolkit*","*\\JetBrains\\*\\plugins\\*com.json.simple.kit*","*\\JetBrains\\*\\plugins\\*org.bug.find.tools*","*\\JetBrains\\*\\plugins\\*org.translate.ai.simple*","*\\JetBrains\\*\\plugins\\*com.yy.test.ai.simple*","*\\JetBrains\\*\\plugins\\*com.dev.ai.toolkit*","*\\JetBrains\\*\\plugins\\*com.json.view.simple*","*\\JetBrains\\*\\plugins\\*com.my.git.ai.kit*","*\\JetBrains\\*\\plugins\\*org.check.ai.ds*","*\\JetBrains\\*\\plugins\\*com.review.tool.code*","*\\JetBrains\\*\\plugins\\*org.code.assist.dev.tool*","*\\JetBrains\\*\\plugins\\*com.coder.ai.dpt*","*\\JetBrains\\*\\plugins\\*com.my.code.tools*","*\\JetBrains\\*\\plugins\\*ord.cp.code.ai.kit*","*\\JetBrains\\*\\plugins\\*com.dp.git.ai.tool*") by host Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let MaliciousPkgIds = dynamic(["org.sm.yms.toolkit","com.json.simple.kit","org.bug.find.tools","org.translate.ai.simple","com.yy.test.ai.simple","com.dev.ai.toolkit","com.json.view.simple","com.my.git.ai.kit","org.check.ai.ds","com.review.tool.code","org.code.assist.dev.tool","com.coder.ai.dpt","com.my.code.tools","ord.cp.code.ai.kit","com.dp.git.ai.tool"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "JetBrains" and FolderPath has "plugins"
| where FolderPath has_any (MaliciousPkgIds) or FileName has_any (MaliciousPkgIds)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath, SHA256, ActionType
| order by Timestamp desc
```

### Malicious Chrome ad-blocker extension installed (Smart Adblocker / Adblock for Browser)

`UC_85_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\Chrome\\User Data\\*\\Extensions\\iojpcjjdfhlcbgjnpngcmaojmlokmeii\\*" OR Filesystem.file_path="*\\Chrome\\User Data\\*\\Extensions\\jcbjcocinigpbgfpnhlpagidbmlngnnn\\*") by host Filesystem.file_path | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let BadExtIds = dynamic(["iojpcjjdfhlcbgjnpngcmaojmlokmeii","jcbjcocinigpbgfpnhlpagidbmlngnnn"]);
DeviceFileEvents
| where Timestamp > ago(90d)
| where FolderPath has_any ("\\Chrome\\User Data\\","/Chrome/Default/Extensions/","/google-chrome/Default/Extensions/","/Application Support/Google/Chrome/Default/Extensions/")
| where FolderPath has_any (BadExtIds)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath, ActionType
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count() by DeviceName, InitiatingProcessAccountName, FolderPath
| order by LastSeen desc
```

### JetBrains IDE process initiates plaintext HTTP POST to external IP

`UC_85_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic where All_Traffic.app IN ("idea64.exe","idea.exe","pycharm64.exe","webstorm64.exe","phpstorm64.exe","clion64.exe","rider64.exe","goland64.exe","datagrip64.exe","rustrover64.exe","rubymine64.exe") All_Traffic.dest_port=80 NOT (All_Traffic.dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16")) by host All_Traffic.app All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
let JetBrainsProcs = dynamic(["idea64.exe","idea.exe","pycharm64.exe","webstorm64.exe","phpstorm64.exe","clion64.exe","rider64.exe","goland64.exe","datagrip64.exe","rustrover64.exe","rubymine64.exe","appcode.exe","studio64.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (JetBrainsProcs)
| where RemotePort == 80
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol
| summarize Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Destinations=make_set(RemoteIP, 50) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName
| order by LastSeen desc
```

### JetBrains plugin manifest dropped under user-writable plugins directory by non-IDE process

`UC_85_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("plugin.xml") Filesystem.file_path="*\\JetBrains\\*\\plugins\\*" NOT Filesystem.process_name IN ("idea64.exe","idea.exe","pycharm64.exe","webstorm64.exe","phpstorm64.exe","clion64.exe","rider64.exe","goland64.exe","datagrip64.exe","rustrover64.exe","rubymine64.exe","toolbox.exe") by host Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let JetBrainsProcs = dynamic(["idea64.exe","idea.exe","pycharm64.exe","webstorm64.exe","phpstorm64.exe","clion64.exe","rider64.exe","goland64.exe","datagrip64.exe","rustrover64.exe","rubymine64.exe","toolbox.exe","appcode.exe","studio64.exe"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "plugin.xml"
| where FolderPath has "JetBrains" and FolderPath has "plugins"
| where InitiatingProcessFileName !in~ (JetBrainsProcs)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath, FileName, ActionType
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `39.107.60.51`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
