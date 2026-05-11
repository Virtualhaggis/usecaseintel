# [HIGH] JDownloader Downloader Hacked to Infect Users With New Python RAT

**Source:** Cyber Security News
**Published:** 2026-05-11
**Article:** https://cybersecuritynews.com/jdownloader-downloader-hacked/

## Threat Profile

Home Cyber Security News 
JDownloader Downloader Hacked to Infect Users With New Python RAT 
By Tushar Subhra Dutta 
May 11, 2026 
JDownloader, the popular open-source download manager trusted by millions of users worldwide, was at the center of a serious supply chain attack in early May 2026. Attackers quietly compromised the official jdownloader.org website and replaced legitimate installer download links with malicious files carrying a fully functional Python-based remote access trojan. 
Anyo…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `parkspringshotel.com`
- **Domain (defanged):** `douv2quu.php`
- **SHA256:** `6d975c05ef7a164707fa359284a31bfe0b1681fe0319819cb9e2c4eec2a1a8af`
- **SHA256:** `fb1e3fe4d18927ff82cffb3f82a0b4ffb7280c85db5a8a8b6f6a1ac30a7e7ed9`
- **SHA256:** `04cb9f0bca6e0e4ed30bc92726590724bf60938440b3825252657d1b3af45495`
- **SHA256:** `5a6636ce490789d7f26aaa86e50bd65c7330f8e6a7c32418740c1d009fb12ef3`
- **SHA256:** `32891c0080442bf0a0c5658ada2c3845435b4e09b114599a516248723aad7805`
- **SHA256:** `de8b2bdfc61d63585329b8cfca2a012476b46387435410b995aeae5b502bd95e`
- **SHA256:** `e4a20f746b7dd19b8d9601b884e67c8166ea9676b917adea6833b695ba13de16`
- **SHA256:** `4ff7eec9e69b6008b77de1b6e5c0d18aa717f625458d80da610cb170c784e97c`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1036.005** — Masquerading: Match Legitimate Resource Name or Location
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1112** — Modify Registry
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1027.013** — Obfuscated Files or Information: Encrypted/Encoded File
- **T1564.003** — Hide Artifacts: Hidden Window

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] JDownloader supply-chain — malicious installer SHA256 execution/write

`UC_13_8` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("6d975c05ef7a164707fa359284a31bfe0b1681fe0319819cb9e2c4eec2a1a8af","fb1e3fe4d18927ff82cffb3f82a0b4ffb7280c85db5a8a8b6f6a1ac30a7e7ed9","04cb9f0bca6e0e4ed30bc92726590724bf60938440b3825252657d1b3af45495","5a6636ce490789d7f26aaa86e50bd65c7330f8e6a7c32418740c1d009fb12ef3","32891c0080442bf0a0c5658ada2c3845435b4e09b114599a516248723aad7805","de8b2bdfc61d63585329b8cfca2a012476b46387435410b995aeae5b502bd95e","e4a20f746b7dd19b8d9601b884e67c8166ea9676b917adea6833b695ba13de16","4ff7eec9e69b6008b77de1b6e5c0d18aa717f625458d80da610cb170c784e97c") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let JDownloaderMaliciousHashes = dynamic([
  "6d975c05ef7a164707fa359284a31bfe0b1681fe0319819cb9e2c4eec2a1a8af",
  "fb1e3fe4d18927ff82cffb3f82a0b4ffb7280c85db5a8a8b6f6a1ac30a7e7ed9",
  "04cb9f0bca6e0e4ed30bc92726590724bf60938440b3825252657d1b3af45495",
  "5a6636ce490789d7f26aaa86e50bd65c7330f8e6a7c32418740c1d009fb12ef3",
  "32891c0080442bf0a0c5658ada2c3845435b4e09b114599a516248723aad7805",
  "de8b2bdfc61d63585329b8cfca2a012476b46387435410b995aeae5b502bd95e",
  "e4a20f746b7dd19b8d9601b884e67c8166ea9676b917adea6833b695ba13de16",
  "4ff7eec9e69b6008b77de1b6e5c0d18aa717f625458d80da610cb170c784e97c"
]);
union
  ( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (JDownloaderMaliciousHashes)
    | project Timestamp, DeviceName, AccountName,
              FileName, FolderPath, SHA256, ProcessCommandLine,
              Parent = InitiatingProcessFileName,
              ParentCmd = InitiatingProcessCommandLine,
              EventSource = "ProcessCreate" ),
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (JDownloaderMaliciousHashes)
    | project Timestamp, DeviceName,
              AccountName = InitiatingProcessAccountName,
              FileName, FolderPath, SHA256,
              ProcessCommandLine = InitiatingProcessCommandLine,
              Parent = InitiatingProcessFileName,
              ParentCmd = InitiatingProcessCommandLine,
              EventSource = "FileWrite" )
| order by Timestamp desc
```

### [LLM] JDownloader Python RAT C2 callout to parkspringshotel.com / auraguest.lk

`UC_13_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as user_agents from datamodel=Web.Web where (Web.url="*parkspringshotel.com/m/Lu6aeloo.php*" OR Web.url="*auraguest.lk/m/douV2quu.php*" OR Web.dest="parkspringshotel.com" OR Web.dest="auraguest.lk") by Web.src Web.dest Web.user | `drop_dm_object_name(Web)` | append [ | tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as queries from datamodel=Network_Resolution.DNS where (DNS.query="parkspringshotel.com" OR DNS.query="auraguest.lk" OR DNS.query="*.parkspringshotel.com" OR DNS.query="*.auraguest.lk") by DNS.src DNS.dest | `drop_dm_object_name(DNS)` ] | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let C2Hosts   = dynamic(["parkspringshotel.com","auraguest.lk"]);
let C2UrlFragments = dynamic(["parkspringshotel.com/m/Lu6aeloo.php","auraguest.lk/m/douV2quu.php"]);
union
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (C2Hosts) or RemoteUrl has_any (C2UrlFragments)
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              Process = InitiatingProcessFileName,
              ProcessCmd = InitiatingProcessCommandLine,
              RemoteIP, RemotePort, RemoteUrl,
              EventSource = "NetworkConnect" ),
  ( DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Query = tostring(parse_json(AdditionalFields).QueryName)
    | where Query has_any (C2Hosts)
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              Process = InitiatingProcessFileName,
              ProcessCmd = InitiatingProcessCommandLine,
              RemoteIP = "", RemotePort = int(null), RemoteUrl = Query,
              EventSource = "DNSQuery" )
| order by Timestamp desc
```

### [LLM] JDownloader Python RAT loader — HKCU\SOFTWARE\Python write by non-Python parent then pythonw.exe spawn

`UC_13_10` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as reg_time max(_time) as last_reg_time values(Registry.registry_value_name) as reg_values values(Registry.process_path) as loader_paths from datamodel=Endpoint.Registry where (Registry.registry_path="*\\SOFTWARE\\Python\\*" OR Registry.registry_key_name="*\\SOFTWARE\\Python\\*") AND Registry.action IN ("modified","created") AND NOT (Registry.process_name IN ("python.exe","pythonw.exe","py.exe","pyw.exe","msiexec.exe","setup.exe","conda.exe","pip.exe")) AND NOT (Registry.process_path="*\\Python\\*" OR Registry.process_path="*\\Python3*\\*" OR Registry.process_path="*\\Anaconda*\\*") by Registry.dest Registry.user Registry.process_name Registry.process_path Registry.registry_path | `drop_dm_object_name(Registry)` | join type=inner dest [ | tstats summariesonly=t count min(_time) as proc_time max(_time) as last_proc_time values(Processes.process) as pythonw_cmds values(Processes.parent_process_name) as pythonw_parents from datamodel=Endpoint.Processes where Processes.process_name="pythonw.exe" by Processes.dest | `drop_dm_object_name(Processes)` ] | where proc_time >= reg_time AND proc_time <= reg_time + 3600 | convert ctime(reg_time) ctime(proc_time) | sort - reg_time
```

**Defender KQL:**
```kql
let LookbackDays = 30d;
let WindowSec = 3600;
let LegitPythonParents = dynamic(["python.exe","pythonw.exe","py.exe","pyw.exe","msiexec.exe","setup.exe","conda.exe","pip.exe","installer.exe"]);
let LoaderRegWrites =
    DeviceRegistryEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
    | where RegistryKey has @"\SOFTWARE\Python"
    | where InitiatingProcessFileName !in~ (LegitPythonParents)
    | where not(InitiatingProcessFolderPath has @"\Python\")
    | where not(InitiatingProcessFolderPath has @"\Anaconda")
    | where InitiatingProcessAccountName !endswith "$"
    | project RegTime = Timestamp, DeviceId, DeviceName,
              AccountName = InitiatingProcessAccountName,
              LoaderImage = InitiatingProcessFileName,
              LoaderPath  = InitiatingProcessFolderPath,
              LoaderCmd   = InitiatingProcessCommandLine,
              LoaderSha256 = InitiatingProcessSHA256,
              RegistryKey, RegistryValueName, RegistryValueData;
LoaderRegWrites
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(LookbackDays)
    | where FileName =~ "pythonw.exe"
    | project ProcTime = Timestamp, DeviceId,
              PythonwPath = FolderPath,
              PythonwCmd  = ProcessCommandLine,
              PythonwParent = InitiatingProcessFileName,
              PythonwSha256 = SHA256
  ) on DeviceId
| where ProcTime between (RegTime .. RegTime + WindowSec * 1s)
| project RegTime, ProcTime,
          DelaySec = datetime_diff('second', ProcTime, RegTime),
          DeviceName, AccountName,
          LoaderImage, LoaderPath, LoaderCmd, LoaderSha256,
          RegistryKey, RegistryValueName,
          PythonwPath, PythonwCmd, PythonwParent, PythonwSha256
| order by RegTime desc
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

### Article-specific behavioural hunt — JDownloader Downloader Hacked to Infect Users With New Python RAT

`UC_13_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — JDownloader Downloader Hacked to Infect Users With New Python RAT ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("pythonw.exe","jdownloader2setup_unix_nojre.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("pythonw.exe","jdownloader2setup_unix_nojre.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — JDownloader Downloader Hacked to Infect Users With New Python RAT
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("pythonw.exe", "jdownloader2setup_unix_nojre.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("pythonw.exe", "jdownloader2setup_unix_nojre.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `parkspringshotel.com`, `douv2quu.php`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `6d975c05ef7a164707fa359284a31bfe0b1681fe0319819cb9e2c4eec2a1a8af`, `fb1e3fe4d18927ff82cffb3f82a0b4ffb7280c85db5a8a8b6f6a1ac30a7e7ed9`, `04cb9f0bca6e0e4ed30bc92726590724bf60938440b3825252657d1b3af45495`, `5a6636ce490789d7f26aaa86e50bd65c7330f8e6a7c32418740c1d009fb12ef3`, `32891c0080442bf0a0c5658ada2c3845435b4e09b114599a516248723aad7805`, `de8b2bdfc61d63585329b8cfca2a012476b46387435410b995aeae5b502bd95e`, `e4a20f746b7dd19b8d9601b884e67c8166ea9676b917adea6833b695ba13de16`, `4ff7eec9e69b6008b77de1b6e5c0d18aa717f625458d80da610cb170c784e97c`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
