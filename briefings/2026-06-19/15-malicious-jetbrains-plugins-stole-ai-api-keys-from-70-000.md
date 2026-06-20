# [HIGH] 15 Malicious JetBrains Plugins Stole AI API Keys from 70,000 Developers

**Source:** StepSecurity
**Published:** 2026-06-19
**Article:** https://www.stepsecurity.io/blog/jetbrains-malicious-plugins-ai-api-key-theft

## Threat Profile

Back to Blog Threat Intel 15 Malicious JetBrains Plugins Stole AI API Keys from 70,000 Developers A coordinated 8-month supply chain attack planted credential-stealing code inside fake AI coding assistants on the JetBrains Marketplace, quietly exfiltrating OpenAI, DeepSeek, and SiliconFlow API keys to an attacker-controlled server in Beijing -- which our investigation found still operational today. Ashish Kurmi View LinkedIn June 18, 2026
Share on X Share on X Share on LinkedIn Share on Facebook…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `39.107.60.51`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1505.003** — Server Software Component: IDE Plugin (analogue)
- **T1573** — Encrypted Channel (negation pattern)
- **T1562.001** — Impair Defenses: Disable or Modify Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### JetBrains IDE outbound connection to malicious plugin C2 (39.107.60.51)

`UC_9_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="39.107.60.51" by All_Traffic.src All_Traffic.src_user All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process_name All_Traffic.bytes_out
| `drop_dm_object_name("All_Traffic")`
| eval is_jb_ide=if(match(lower(coalesce(process_name,app,"")),"(idea(64)?|pycharm(64)?|webstorm(64)?|phpstorm(64)?|rubymine(64)?|clion(64)?|goland(64)?|rider(64)?|datagrip(64)?|fleet|studio(64)?|aqua(64)?|rustrover(64)?)\.exe$"),1,0)
| sort - is_jb_ide firstTime
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(240d)
| where RemoteIP == "39.107.60.51"
| extend IsJetBrainsIDE = InitiatingProcessFileName has_any ("idea64.exe","idea.exe","pycharm64.exe","pycharm.exe","webstorm64.exe","phpstorm64.exe","rubymine64.exe","clion64.exe","goland64.exe","rider64.exe","datagrip64.exe","fleet.exe","studio64.exe","aqua64.exe","rustrover64.exe","dataspell64.exe","mps64.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, LocalIP, IsJetBrainsIDE
| order by IsJetBrainsIDE desc, Timestamp desc
```

### HTTP exfil signature: POST to /api/software/ on 39.107.60.51

`UC_9_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.user_agent) as user_agents values(Web.http_method) as methods from datamodel=Web.Web where (Web.dest="39.107.60.51" OR Web.url="*39.107.60.51*") AND (Web.url="*/api/software/*" OR Web.http_method="POST") by Web.src Web.user Web.url Web.dest
| `drop_dm_object_name("Web")`
| sort - firstTime
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(240d)
| where (RemoteIP == "39.107.60.51" or RemoteUrl has "39.107.60.51")
| where RemotePort == 80 or RemoteUrl has "/api/software/"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort
| order by Timestamp desc
```

### Malicious JetBrains plugin folder or JAR present in plugins directory

`UC_9_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_hash) as sha256 from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\JetBrains\\*\\plugins\\*" OR Filesystem.file_path="*/JetBrains/*/plugins/*" by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name("Filesystem")`
| eval bad_plugin = case(
    match(file_path, "(?i)(DeepSeek Junit Test|DeepSeek Git Commit|DeepSeek FindBugs|DeepSeek AI Chat|DeepSeek Dev AI|DeepSeek AI Coding|AI FindBugs|AI Git Commitor|AI Coder Review|DeepSeek Coder AI|AI Coder Assistant|DeepSeek Code Review|CodeGPT AI Assistant|DeepSeek AI Assist)"), "display-name",
    match(file_path, "(?i)(org\.sm\.yms\.toolkit|com\.json\.simple\.kit|org\.bug\.find\.tools|org\.translate\.ai\.simple|com\.yy\.test\.ai\.simple|com\.dev\.ai\.toolkit|com\.json\.view\.simple|com\.my\.git\.ai\.kit|org\.check\.ai\.ds|com\.review\.tool\.code|org\.code\.assist\.dev\.tool|com\.coder\.ai\.dpt|com\.my\.code\.tools|ord\.cp\.code\.ai\.kit)"), "plugin-id",
    1==1, null)
| where isnotnull(bad_plugin)
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let bad_display_names = dynamic(["DeepSeek Junit Test","DeepSeek Git Commit","DeepSeek FindBugs","DeepSeek AI Chat","DeepSeek Dev AI","DeepSeek AI Coding","AI FindBugs","AI Git Commitor","AI Coder Review","DeepSeek Coder AI","AI Coder Assistant","DeepSeek Code Review","CodeGPT AI Assistant","DeepSeek AI Assist"]);
let bad_plugin_ids = dynamic(["org.sm.yms.toolkit","com.json.simple.kit","org.bug.find.tools","org.translate.ai.simple","com.yy.test.ai.simple","com.dev.ai.toolkit","com.json.view.simple","com.my.git.ai.kit","org.check.ai.ds","com.review.tool.code","org.code.assist.dev.tool","com.coder.ai.dpt","com.my.code.tools","ord.cp.code.ai.kit"]);
DeviceFileEvents
| where Timestamp > ago(240d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has @"\JetBrains\" and FolderPath has @"\plugins\"
| where FolderPath has_any (bad_display_names) or FileName has_any (bad_display_names) or FolderPath has_any (bad_plugin_ids) or FileName has_any (bad_plugin_ids)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath, SHA256, FileSize
| order by Timestamp desc
```

### JetBrains IDE plaintext HTTP (port 80) egress to external host

`UC_9_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as destinations dc(All_Traffic.dest) as dest_count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=80 AND All_Traffic.dest_category!="internal" by All_Traffic.src All_Traffic.app All_Traffic.process_name All_Traffic.dest
| `drop_dm_object_name("All_Traffic")`
| eval is_jb_ide=if(match(lower(coalesce(process_name,app,"")),"(idea(64)?|pycharm(64)?|webstorm(64)?|phpstorm(64)?|rubymine(64)?|clion(64)?|goland(64)?|rider(64)?|datagrip(64)?|fleet|studio(64)?|aqua(64)?|rustrover(64)?)\.exe$"),1,0)
| where is_jb_ide=1
| convert ctime(firstTime) ctime(lastTime)
| sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("idea64.exe","idea.exe","pycharm64.exe","pycharm.exe","webstorm64.exe","phpstorm64.exe","rubymine64.exe","clion64.exe","goland64.exe","rider64.exe","datagrip64.exe","fleet.exe","studio64.exe","aqua64.exe","rustrover64.exe","dataspell64.exe")
| where RemotePort == 80
| where RemoteIPType == "Public"
| where not (RemoteUrl has_any ("jetbrains.com","intellij.net","plugins.jetbrains.com"))
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), ConnCount = count(), SampleUrls = make_set(RemoteUrl, 5) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP
| order by FirstSeen desc
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

### Article-specific behavioural hunt — 15 Malicious JetBrains Plugins Stole AI API Keys from 70,000 Developers

`UC_9_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — 15 Malicious JetBrains Plugins Stole AI API Keys from 70,000 Developers ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/Library/Application*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — 15 Malicious JetBrains Plugins Stole AI API Keys from 70,000 Developers
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/Library/Application"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `39.107.60.51`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
