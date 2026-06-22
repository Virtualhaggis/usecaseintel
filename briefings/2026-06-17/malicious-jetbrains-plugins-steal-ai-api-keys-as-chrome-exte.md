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
- **T1041** — Exfiltration Over C2 Channel
- **T1552** — Unsecured Credentials
- **T1176.002** — IDE Extensions
- **T1176.001** — Browser Extensions

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### JetBrains IDE exfiltrating AI API keys to Aikido C2 39.107.60.51

`UC_102_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="39.107.60.51" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process_name
| drop_dm_object_name(All_Traffic)
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "39.107.60.51"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### Malicious DeepSeek/CodeGPT JetBrains plugin written to IDE plugins directory

`UC_102_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\JetBrains\\*\\plugins\\*" (Filesystem.file_path="*DeepSeek*" OR Filesystem.file_path="*CodeGPT*" OR Filesystem.file_path="*AI Coder*" OR Filesystem.file_path="*AI FindBugs*" OR Filesystem.file_path="*AI Git Commitor*" OR Filesystem.file_path="*Coding Simple Tool*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name
| drop_dm_object_name(Filesystem)
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\JetBrains\" and FolderPath has @"\plugins\"
| where FolderPath has_any ("DeepSeek","CodeGPT","AI Coder","AI FindBugs","AI Git Commitor","Coding Simple Tool")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### PromptSnatcher malicious Chrome ad-blocker extension installed by ID

`UC_102_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*iojpcjjdfhlcbgjnpngcmaojmlokmeii*" OR Filesystem.file_path="*jcbjcocinigpbgfpnhlpagidbmlngnnn*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name
| drop_dm_object_name(Filesystem)
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any ("iojpcjjdfhlcbgjnpngcmaojmlokmeii","jcbjcocinigpbgfpnhlpagidbmlngnnn")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

### PromptSnatcher Chrome extension exfiltrating AI chats to c.smartadblocker.com / c.abforbrowser.com

`UC_102_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*smartadblocker.com" OR DNS.query="*abforbrowser.com") by DNS.src DNS.query
| drop_dm_object_name(DNS)
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("smartadblocker.com","abforbrowser.com")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
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

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
