# [MED] Malicious JetBrains Marketplace plugins steal AI API keys from developers

**Source:** BleepingComputer
**Published:** 2026-06-16
**Article:** https://www.bleepingcomputer.com/news/security/malicious-jetbrains-marketplace-plugins-steal-ai-api-keys-from-developers/

## Threat Profile

Malicious JetBrains Marketplace plugins steal AI API keys from developers 
By Lawrence Abrams 
June 16, 2026
05:54 PM
0 
At least 15 malicious plugins found on the JetBrains Marketplace were designed to steal AI API keys from developers.
The campaign, discovered by Aikido Security, includes plugins that act as AI coding assistants, code-review tools, and Git utilities powered by popular AI services such as OpenAI, DeepSeek, and SiliconFlow.
"We detected a coordinated malware campaign on the JetB…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `39.107.60.51`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service
- **T1095** — Non-Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Malicious JetBrains Marketplace plugin install by ID (Aikido campaign)

`UC_26_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\JetBrains\\*\\plugins\\*" AND (Filesystem.file_path="*ord.cp.code.ai.kit*" OR Filesystem.file_path="*org.sm.yms.toolkit*" OR Filesystem.file_path="*com.json.simple.kit*" OR Filesystem.file_path="*org.bug.find.tools*" OR Filesystem.file_path="*org.translate.ai.simple*" OR Filesystem.file_path="*com.yy.test.ai.simple*" OR Filesystem.file_path="*com.dev.ai.toolkit*" OR Filesystem.file_path="*com.json.view.simple*" OR Filesystem.file_path="*com.my.git.ai.kit*" OR Filesystem.file_path="*org.check.ai.ds*" OR Filesystem.file_path="*com.review.tool.code*" OR Filesystem.file_path="*org.code.assist.dev.tool*" OR Filesystem.file_path="*com.coder.ai.dpt*" OR Filesystem.file_path="*com.my.code.tools*" OR Filesystem.file_path="*com.dp.git.ai.tool*") by host Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MaliciousPluginIds = dynamic(["ord.cp.code.ai.kit","org.sm.yms.toolkit","com.json.simple.kit","org.bug.find.tools","org.translate.ai.simple","com.yy.test.ai.simple","com.dev.ai.toolkit","com.json.view.simple","com.my.git.ai.kit","org.check.ai.ds","com.review.tool.code","org.code.assist.dev.tool","com.coder.ai.dpt","com.my.code.tools","com.dp.git.ai.tool"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\JetBrains\" and FolderPath has @"\plugins\"
| where FolderPath has_any (MaliciousPluginIds) or FileName has_any (MaliciousPluginIds)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### JetBrains IDE outbound to attacker C2 39.107.60.51 over plaintext HTTP

`UC_26_2` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src_ip) as src_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="39.107.60.51" AND (All_Traffic.app IN ("idea64.exe","pycharm64.exe","webstorm64.exe","phpstorm64.exe","clion64.exe","goland64.exe","rubymine64.exe","datagrip64.exe","rider64.exe","androidstudio64.exe","studio64.exe") OR All_Traffic.process_name IN ("idea64.exe","pycharm64.exe","webstorm64.exe","phpstorm64.exe","clion64.exe","goland64.exe","rubymine64.exe","datagrip64.exe","rider64.exe","androidstudio64.exe","studio64.exe")) by host All_Traffic.user All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let JetBrainsBins = dynamic(["idea64.exe","idea.exe","pycharm64.exe","pycharm.exe","webstorm64.exe","webstorm.exe","phpstorm64.exe","phpstorm.exe","clion64.exe","clion.exe","goland64.exe","goland.exe","rubymine64.exe","rubymine.exe","datagrip64.exe","datagrip.exe","rider64.exe","rider.exe","androidstudio64.exe","studio64.exe","java.exe","javaw.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "39.107.60.51"
| where InitiatingProcessFileName has_any (JetBrainsBins)
   or InitiatingProcessParentFileName has_any (JetBrainsBins)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Outbound HTTP request to URI path /api/software/key (plugin exfil endpoint)

`UC_26_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.dest) as dest values(Web.http_method) as http_method values(Web.user) as user from datamodel=Web.Web where Web.url="*/api/software/key*" by host Web.src Web.dest Web.app Web.user | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "/api/software/key" or AdditionalFields has "/api/software/key"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, AdditionalFields
| order by Timestamp desc
```

### JetBrains IDE plaintext HTTP to bare-IP destination (no domain) — plugin exfil shape

`UC_26_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=80 AND (All_Traffic.app IN ("idea64.exe","pycharm64.exe","webstorm64.exe","phpstorm64.exe","clion64.exe","goland64.exe","rubymine64.exe","datagrip64.exe","rider64.exe","studio64.exe") OR All_Traffic.process_name IN ("idea64.exe","pycharm64.exe","webstorm64.exe","phpstorm64.exe","clion64.exe","goland64.exe","rubymine64.exe","datagrip64.exe","rider64.exe","studio64.exe")) by host All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)` | where match(dest,"^\d+\.\d+\.\d+\.\d+$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let JetBrainsBins = dynamic(["idea64.exe","idea.exe","pycharm64.exe","pycharm.exe","webstorm64.exe","webstorm.exe","phpstorm64.exe","phpstorm.exe","clion64.exe","clion.exe","goland64.exe","goland.exe","rubymine64.exe","rubymine.exe","datagrip64.exe","datagrip.exe","rider64.exe","rider.exe","studio64.exe","javaw.exe","java.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any (JetBrainsBins) or InitiatingProcessParentFileName has_any (JetBrainsBins)
| where RemotePort == 80
| where RemoteIPType == "Public"
| where isempty(RemoteUrl) or RemoteUrl matches regex @"^https?://\d+\.\d+\.\d+\.\d+(/|:|$)"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, AdditionalFields
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `39.107.60.51`


## Why this matters

Severity classified as **MED** based on: IOCs present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
