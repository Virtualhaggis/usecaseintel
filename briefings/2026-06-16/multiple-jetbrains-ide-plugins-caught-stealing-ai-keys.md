# [HIGH] Multiple JetBrains IDE plugins caught stealing AI keys

**Source:** Aikido
**Published:** 2026-06-16
**Article:** https://www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys

## Threat Profile

Blog Vulnerabilities & Threats Multiple JetBrains IDE plugins caught stealing AI keys Multiple JetBrains IDE plugins caught stealing AI keys Written by Ilyas Makari Published on: Jun 16, 2026 We detected a coordinated malware campaign on the JetBrains Marketplace. At least 15 IDE plugins, published under seven vendor accounts, share the same hidden behavior. Each one exfiltrates the AI provider API key that you stored into its settings, and together they have been installed close to 70,000 times…

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
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1528** — Steal Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### JetBrains IDE plugin AI-key exfil: endpoint egress to C2 39.107.60.51

`UC_272_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="39.107.60.51" by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.app, All_Traffic.user, All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "39.107.60.51"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, Protocol,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### JetBrains AI-key stealer HTTP exfil: cleartext POST to /api/software/ path

`UC_272_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/api/software/*" OR Web.dest="39.107.60.51") AND Web.http_method="POST" by Web.src, Web.dest, Web.url, Web.http_method, Web.http_user_agent, Web.user
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "HttpConnectionInspected"
| where RemoteUrl has "/api/software/" or RemoteUrl has "39.107.60.51"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

### Malicious JetBrains Marketplace plugin install (15 DeepSeek/CodeGPT clone IDs)

`UC_272_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.file_path="*\\JetBrains\\*\\plugins\\*" AND (Endpoint.Filesystem.file_path="*DeepSeek Junit Test*" OR Endpoint.Filesystem.file_path="*DeepSeek Git Commit*" OR Endpoint.Filesystem.file_path="*DeepSeek FindBugs*" OR Endpoint.Filesystem.file_path="*DeepSeek AI Chat*" OR Endpoint.Filesystem.file_path="*DeepSeek Dev AI*" OR Endpoint.Filesystem.file_path="*DeepSeek AI Coding*" OR Endpoint.Filesystem.file_path="*AI FindBugs*" OR Endpoint.Filesystem.file_path="*AI Git Commitor*" OR Endpoint.Filesystem.file_path="*AI Coder Review*" OR Endpoint.Filesystem.file_path="*DeepSeek Coder AI*" OR Endpoint.Filesystem.file_path="*AI Coder Assistant*" OR Endpoint.Filesystem.file_path="*DeepSeek Code Review*" OR Endpoint.Filesystem.file_path="*CodeGPT AI Assistant*" OR Endpoint.Filesystem.file_path="*DeepSeek AI Assist*" OR Endpoint.Filesystem.file_path="*Coding Simple Tool*") by Endpoint.Filesystem.dest, Endpoint.Filesystem.file_path, Endpoint.Filesystem.file_name, Endpoint.Filesystem.user
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(90d)
| where FolderPath has "JetBrains" and FolderPath has "plugins"
| where FolderPath has_any (
    "DeepSeek Junit Test","DeepSeek Git Commit","DeepSeek FindBugs",
    "DeepSeek AI Chat","DeepSeek Dev AI","DeepSeek AI Coding",
    "AI FindBugs","AI Git Commitor","AI Coder Review","DeepSeek Coder AI",
    "AI Coder Assistant","DeepSeek Code Review","CodeGPT AI Assistant",
    "DeepSeek AI Assist","Coding Simple Tool")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Files=make_set(FileName, 20)
          by DeviceName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
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

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
