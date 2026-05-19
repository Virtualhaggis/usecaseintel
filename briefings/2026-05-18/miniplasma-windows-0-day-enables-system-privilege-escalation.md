# [HIGH] MiniPlasma Windows 0-Day Enables SYSTEM Privilege Escalation on Fully Patched Systems

**Source:** The Hacker News, Cyber Security News
**Published:** 2026-05-18
**Article:** https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html

## Threat Profile

Home Cyber Attack News 
Four Malicious npm Packages Steal SSH Keys, Cloud Credentials, and Crypto Wallets 
By Guru Baran 
May 18, 2026 
Four malicious npm packages capable of stealing SSH keys, cloud credentials, cryptocurrency wallets, and environment variables, while one variant quietly transforms infected machines into a DDoS botnet .
The campaign appears to be the work of a single threat actor deploying multiple infostealer variants simultaneously through a coordinated typosquatting operatio…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `80.200.28.28`
- **Domain (defanged):** `87e0bbc636999b.lhr.life`
- **Domain (defanged):** `b94b6bcfa27554.lhr.life`
- **Domain (defanged):** `edcf8b03c84634.lhr.life`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1059** — Command and Scripting Interpreter
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1572** — Protocol Tunneling
- **T1567** — Exfiltration Over Web Service
- **T1041** — Exfiltration Over C2 Channel
- **T1571** — Non-Standard Port
- **T1059.007** — JavaScript
- **T1567.001** — Exfiltration to Code Repository
- **T1552.001** — Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Malicious npm Package Install - Shai-Hulud Typosquat Campaign (chalk-tempalte / axios-util)

`UC_22_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe","cmd.exe","powershell.exe","pwsh.exe","bash.exe") AND (Processes.process="*chalk-tempalte*" OR Processes.process="*@deadcode09284814/axios-util*" OR Processes.process="*axios-utils*" OR Processes.process="*axois-utils*" OR Processes.process="*color-style-utils*") by host user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe","cmd.exe","powershell.exe","pwsh.exe","bash.exe")
| where ProcessCommandLine has_any ("chalk-tempalte","@deadcode09284814/axios-util","axios-utils","axois-utils","color-style-utils")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] Outbound C2 to localhost.run Tunnel (lhr.life) Subdomains - Shai-Hulud Copycat

`UC_22_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where (DNS.query IN ("87e0bbc636999b.lhr.life","b94b6bcfa27554.lhr.life","edcf8b03c84634.lhr.life") OR DNS.query="*.lhr.life") by host DNS.src DNS.query DNS.answer DNS.record_type | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let ioc_domains = dynamic(["87e0bbc636999b.lhr.life","b94b6bcfa27554.lhr.life","edcf8b03c84634.lhr.life"]);
union isfuzzy=true
(DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has_any (ioc_domains) or RemoteUrl endswith ".lhr.life"
  | project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
            InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
(DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
  | where QueryName has_any (ioc_domains) or QueryName endswith ".lhr.life"
  | project Timestamp, DeviceName, ActionType, RemoteUrl=QueryName,
            InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName)
| order by Timestamp desc
```

### [LLM] Network Egress to 80.200.28.28:2222 - Axios-Util Infostealer C2

`UC_22_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic where All_Traffic.dest_ip="80.200.28.28" AND All_Traffic.dest_port=2222 by host All_Traffic.src All_Traffic.src_user All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.transport | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "80.200.28.28" and RemotePort == 2222
| project Timestamp, DeviceName, ActionType, Protocol, RemoteIP, RemotePort, LocalIP, LocalPort,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessAccountUpn
| order by Timestamp desc
```

### [LLM] Shai-Hulud Marker String Hunt - 'A Mini Sha1-Hulud has Appeared'

`UC_22_9` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
(`endpoint_processes_index` OR `wineventlog_powershell_index` OR `sysmon_index`) "A Mini Sha1-Hulud has Appeared"
| eval matched_field = case(match(_raw, "(?i)A Mini Sha1-Hulud has Appeared"), "raw", true(), "unknown")
| stats count min(_time) as firstTime max(_time) as lastTime values(host) as host values(user) as user values(source) as source values(sourcetype) as sourcetype by matched_field, _raw
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
let marker = "A Mini Sha1-Hulud has Appeared";
union isfuzzy=true
(DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where ProcessCommandLine has marker or InitiatingProcessCommandLine has marker
  | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
            InitiatingProcessFileName, InitiatingProcessCommandLine, Source="ProcessEvents"),
(DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType in ("PowerShellCommand","AmsiScriptDetection","ScriptContent")
  | where AdditionalFields has marker
  | project Timestamp, DeviceName, ActionType, InitiatingProcessFileName,
            InitiatingProcessCommandLine, AdditionalFields, Source="DeviceEvents"),
(DeviceFileEvents
  | where Timestamp > ago(30d)
  | where InitiatingProcessCommandLine has marker
  | project Timestamp, DeviceName, FileName, FolderPath, SHA256,
            InitiatingProcessFileName, InitiatingProcessCommandLine, Source="FileEvents")
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
  - IP / domain IOC(s): `80.200.28.28`, `87e0bbc636999b.lhr.life`, `b94b6bcfa27554.lhr.life`, `edcf8b03c84634.lhr.life`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
