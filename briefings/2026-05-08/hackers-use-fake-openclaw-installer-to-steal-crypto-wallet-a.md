# [HIGH] Hackers Use Fake OpenClaw Installer to Steal Crypto Wallet and Password Manager Credentials

**Source:** Cyber Security News
**Published:** 2026-05-08
**Article:** https://cybersecuritynews.com/hackers-use-fake-openclaw-installer/

## Threat Profile

Home Cyber Security News 
Hackers Use Fake OpenClaw Installer to Steal Crypto Wallet and Password Manager Credentials 
By Tushar Subhra Dutta 
May 8, 2026 
A dangerous new infostealer campaign is targeting some of the most sensitive data people store on their computers. Disguised as a legitimate installer for OpenClaw, a popular open-source personal AI assistant, the malware silently takes over systems and goes after over 250 browser extensions tied to crypto wallets and password managers. The c…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `virtnetwork.exe`
- **Domain (defanged):** `audioeq.exe`
- **Domain (defanged):** `winhealhcare.exe`
- **Domain (defanged):** `onesync.exe`
- **Domain (defanged):** `vicloud.exe`
- **Domain (defanged):** `dbau.exe`
- **Domain (defanged):** `steamhostserver.cc`
- **Domain (defanged):** `serverconect.cc`
- **Domain (defanged):** `transcloud.cc`
- **Domain (defanged):** `onedrivesync.lnk`
- **Domain (defanged):** `manager.exe`
- **SHA256:** `4014048f8e60d39f724d5b1ae34210ffeac151e1f2d4813dbb51c719d4ad7c3a`
- **SHA256:** `f03736fadffcb7bef122d25d6ace8044378d4fa455f7f48081a3b32c80eb4ed2`
- **SHA256:** `f554b6f34fd2710929d74af550ddb50633d36eaf0533f2d0cbbde75670676486`
- **SHA256:** `40fc240febf2441d58a7e2554e4590e172bfefd289a5d9fa6781de38e266b378`
- **SHA256:** `4fcfcb83145223cca6db85e7c840876ec8a56d78efba856ab70287b0e5c8a696`
- **SHA256:** `605096b9729bd8eedab460dbd4baf702029fb59842020a27fc0f99fd2ef63040`
- **SHA256:** `6ae9f9cfa8e638e933ad8b06de7434c395ec68ee9cc4e735069bfb64646bb180`
- **SHA256:** `0c4a9d3579485eaf8801e5ac479cd322ee1e7161b54cc24689b891fa82ba0f1e`
- **SHA256:** `fd67063ffb0bcde44dca5fea09cc0913150161d7cb13cffc2a001a0894f12690`
- **SHA256:** `d5dffba463beae207aee339f88a18cfcd2ea2cd3e36e98d27297d819a1809846`
- **SHA256:** `787a28aff72f2ecd2f5e75baf284e61bda9ab8dd3905822c6f620cce809952e8`
- **SHA256:** `1478ccc61b69cee462ea98621ba53adf2de0ce28355c5c4eafaed6d779c8acda`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1571** — Non-Standard Port
- **T1562.004** — Impair Defenses: Disable or Modify System Firewall
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1547.004** — Boot or Logon Autostart Execution: Winlogon Helper DLL
- **T1102.002** — Web Service: Bidirectional Communication
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] OpenClaw Hologram/Pathfinder Stealth Packer beacon — C:\Users\Public binary to high-port C2

`UC_15_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_ports values(All_Traffic.dest_ip) as dest_ips values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where ((All_Traffic.dest_port>=56001 AND All_Traffic.dest_port<=57002) OR All_Traffic.dest_ip IN ("193.202.84.14","45.55.35.48","185.196.9.98","91.92.242.30","147.45.197.92","94.228.161.88","86.54.42.72","188.114.97.3")) by All_Traffic.src host All_Traffic.user All_Traffic.app | `drop_dm_object_name(All_Traffic)` | join type=inner host [| tstats summariesonly=t values(Processes.process_path) as process_path values(Processes.process_name) as process_name values(Processes.process) as cmdline values(Processes.process_hash) as process_hash from datamodel=Endpoint.Processes where (Processes.process_path="*\\Users\\Public\\*" OR Processes.process_name IN ("svc_service.exe","virtnetwork.exe","onedrive_sync.exe","audioeq.exe","WinHealhCare.exe","OneSync.exe","vicloud.exe","manager.exe","dbau.exe")) by host Processes.process_name Processes.process_path Processes.process Processes.process_hash | `drop_dm_object_name(Processes)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _bins = dynamic(["svc_service.exe","virtnetwork.exe","onedrive_sync.exe","audioeq.exe","WinHealhCare.exe","OneSync.exe","vicloud.exe","manager.exe","dbau.exe"]);
let _ips = dynamic(["193.202.84.14","45.55.35.48","185.196.9.98","91.92.242.30","147.45.197.92","94.228.161.88","86.54.42.72","188.114.97.3"]);
let _hashes = dynamic(["40fc240febf2441d58a7e2554e4590e172bfefd289a5d9fa6781de38e266b378","4fcfcb83145223cca6db85e7c840876ec8a56d78efba856ab70287b0e5c8a696","605096b9729bd8eedab460dbd4baf702029fb59842020a27fc0f99fd2ef63040","6ae9f9cfa8e638e933ad8b06de7434c395ec68ee9cc4e735069bfb64646bb180","0c4a9d3579485eaf8801e5ac479cd322ee1e7161b54cc24689b891fa82ba0f1e","fd67063ffb0bcde44dca5fea09cc0913150161d7cb13cffc2a001a0894f12690","d5dffba463beae207aee339f88a18cfcd2ea2cd3e36e98d27297d819a1809846","787a28aff72f2ecd2f5e75baf284e61bda9ab8dd3905822c6f620cce809952e8","1478ccc61b69cee462ea98621ba53adf2de0ce28355c5c4eafaed6d779c8acda"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where (RemotePort between (56001 .. 57002)) or RemoteIP in (_ips) or InitiatingProcessSHA256 in (_hashes)
| where InitiatingProcessFolderPath has @"\Users\Public\" or InitiatingProcessFileName in~ (_bins)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### [LLM] OpenClaw Hologram persistence quartet — Userinit hijack + WindowsDefenderHelper/NetworkManager autoruns + OneDriveSync.lnk

`UC_15_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as data values(Registry.process_name) as process_name values(Registry.user) as user from datamodel=Endpoint.Registry where (Registry.registry_path="*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" AND NOT Registry.registry_value_data IN ("C:\\Windows\\system32\\userinit.exe,","C:\\Windows\\system32\\userinit.exe")) OR Registry.registry_value_name IN ("WindowsDefenderHelper","NetworkManager","{NetworkManager}") by Registry.dest Registry.registry_path Registry.registry_value_name | `drop_dm_object_name(Registry)` | append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\Start Menu\\Programs\\Startup\\OneDriveSync.lnk" by Filesystem.dest Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _reg = DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where (RegistryKey has @"\Microsoft\Windows NT\CurrentVersion\Winlogon" and RegistryValueName =~ "Userinit"
         and tolower(RegistryValueData) !startswith @"c:\windows\system32\userinit.exe")
   or (RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce")
       and RegistryValueName in~ ("WindowsDefenderHelper","NetworkManager","{NetworkManager}"))
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256;
let _file = DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\Start Menu\Programs\Startup" and FileName =~ "OneDriveSync.lnk"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine;
union _reg, _file
| order by Timestamp desc
```

### [LLM] OpenClaw three-service abuse — Hookdeck + Telegram bot API + Azure DevOps 'sagonbretzpr' from C:\Users\Public binary

`UC_15_11` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.dest) as dest values(Web.user) as user from datamodel=Web.Web where (Web.url="*hkdk.events*" OR Web.url="*api.telegram.org*" OR Web.url="*dev.azure.com/sagonbretzpr*" OR Web.url="*pastebin.com/raw/*" OR Web.url="*snippet.host*") by Web.src host Web.process_name Web.process_path Web.url | `drop_dm_object_name(Web)` | eval is_known_browser=if(match(process_name,"(?i)^(msedge|chrome|firefox|brave|iexplore|opera|safari|teams|outlook|onedrive|code|devenv|git|msbuild|az|kubectl|slack|zoom|powershell_ise)\.exe$"),1,0) | eval is_public_drop=if(match(process_path,"(?i)\\\\Users\\\\Public\\\\") OR match(process_name,"(?i)^(svc_service|virtnetwork|onedrive_sync|audioeq|winhealhcare|onesync|vicloud|manager|dbau)\.exe$"),1,0) | where is_known_browser=0 AND (is_public_drop=1 OR urls LIKE "%dev.azure.com/sagonbretzpr%") | stats min(firstTime) as firstTime max(lastTime) as lastTime values(urls) as urls values(process_name) as process_name values(process_path) as process_path dc(host) as host_count by host user | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _bins = dynamic(["svc_service.exe","virtnetwork.exe","onedrive_sync.exe","audioeq.exe","WinHealhCare.exe","OneSync.exe","vicloud.exe","manager.exe","dbau.exe"]);
let _benign = dynamic(["msedge.exe","chrome.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe","teams.exe","outlook.exe","onedrive.exe","code.exe","devenv.exe","git.exe","msbuild.exe","az.exe","kubectl.exe","slack.exe","zoom.exe","powershell_ise.exe"]);
let _services = dynamic(["hkdk.events","api.telegram.org","dev.azure.com","pastebin.com","snippet.host"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (_services) or RemoteUrl has "sagonbretzpr"
| where (InitiatingProcessFolderPath has @"\Users\Public\") or (InitiatingProcessFileName in~ (_bins)) or ((RemoteUrl has "sagonbretzpr" or RemoteUrl has "hkdk.events") and InitiatingProcessFileName !in~ (_benign))
| summarize Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), URLs=make_set(RemoteUrl, 25), IPs=make_set(RemoteIP, 25) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
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

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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

### Article-specific behavioural hunt — Hackers Use Fake OpenClaw Installer to Steal Crypto Wallet and Password Manager

`UC_15_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Use Fake OpenClaw Installer to Steal Crypto Wallet and Password Manager ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js") OR Processes.process_path="*C:\ProgramData\Microsoft\Windows\Start*" OR Processes.process_path="*%APPDATA%\Roaming\Data\Config\manager*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\ProgramData\Microsoft\Windows\Start*" OR Filesystem.file_path="*%APPDATA%\Roaming\Data\Config\manager*" OR Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\SOFTWARE\\Microsoft\\Windows*" OR Registry.registry_path="*HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDefenderHelper*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Use Fake OpenClaw Installer to Steal Crypto Wallet and Password Manager
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js") or FolderPath has_any ("C:\ProgramData\Microsoft\Windows\Start", "%APPDATA%\Roaming\Data\Config\manager"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\ProgramData\Microsoft\Windows\Start", "%APPDATA%\Roaming\Data\Config\manager") or FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\SOFTWARE\Microsoft\Windows", "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsDefenderHelper")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `virtnetwork.exe`, `audioeq.exe`, `winhealhcare.exe`, `onesync.exe`, `vicloud.exe`, `dbau.exe`, `steamhostserver.cc`, `serverconect.cc` _(+3 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `4014048f8e60d39f724d5b1ae34210ffeac151e1f2d4813dbb51c719d4ad7c3a`, `f03736fadffcb7bef122d25d6ace8044378d4fa455f7f48081a3b32c80eb4ed2`, `f554b6f34fd2710929d74af550ddb50633d36eaf0533f2d0cbbde75670676486`, `40fc240febf2441d58a7e2554e4590e172bfefd289a5d9fa6781de38e266b378`, `4fcfcb83145223cca6db85e7c840876ec8a56d78efba856ab70287b0e5c8a696`, `605096b9729bd8eedab460dbd4baf702029fb59842020a27fc0f99fd2ef63040`, `6ae9f9cfa8e638e933ad8b06de7434c395ec68ee9cc4e735069bfb64646bb180`, `0c4a9d3579485eaf8801e5ac479cd322ee1e7161b54cc24689b891fa82ba0f1e` _(+4 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
