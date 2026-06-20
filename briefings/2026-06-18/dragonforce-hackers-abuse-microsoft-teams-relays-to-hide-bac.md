# [CRIT] DragonForce Hackers Abuse Microsoft Teams Relays to Hide Backdoor.Turn C2 Traffic

**Source:** The Hacker News
**Published:** 2026-06-18
**Article:** https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html

## Threat Profile

DragonForce Hackers Abuse Microsoft Teams Relays to Hide Backdoor.Turn C2 Traffic 
 Ravie Lakshmanan  Jun 18, 2026 Remote Access Trojan / Ransomware 
Threat actors associated with the DragonForce ransomware have been observed using a custom Go-based remote access trojan (RAT) called Backdoor.Turn to conceal command-and-control (C2) traffic inside Microsoft Teams relay infrastructure.
According to findings from Broadcom-owned Symantec and Carbon Black, the backdoor was deployed against a major …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-52271`
- **CVE:** `CVE-2025-61155`
- **CVE:** `CVE-2025-1055`
- **IPv4 (defanged):** `62.164.177.25`
- **IPv4 (defanged):** `192.36.27.51`
- **Domain (defanged):** `projetosmecanicos.com.br`
- **Domain (defanged):** `socialbizsolutions.com`
- **Domain (defanged):** `professionalhomebasedbusiness.com`
- **Domain (defanged):** `safefire.jo`
- **Domain (defanged):** `glanz-gmbh.de`
- **Domain (defanged):** `turnkeyaiagents.com`
- **Domain (defanged):** `comunidadesparentais.com.br`
- **Domain (defanged):** `mysimerp.net`
- **SHA256:** `82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b`
- **SHA256:** `821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6`
- **SHA256:** `b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383`
- **SHA256:** `ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0`
- **SHA256:** `f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b`
- **SHA256:** `142bac0e2148e0d47891b6cd7311195c4acbe33b700fad54a201c52a2bc46219`
- **SHA256:** `8395b621bb4415090f232c59fc41d24ea41a519b58eabe512f3ae7d2fdf049a3`
- **SHA256:** `9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759`
- **SHA256:** `cd078957167e1af4de39aecdb981cd14156fa81d5a9c6ac51e74ae5b6199a12a`
- **SHA256:** `b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877`
- **SHA256:** `d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e`
- **SHA256:** `8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2`
- **SHA256:** `65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951`
- **SHA256:** `6bbf10bcbef7ac5102b54c81137859891a3802dbacd888be90f990d50e18b0b4`
- **SHA256:** `252a8bb2eb9c96c5e6cc7cab822e2ed0d508032f9350351221781684e86c03ab`
- **SHA256:** `8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531`
- **SHA256:** `e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22`
- **SHA256:** `087f002df0a02c8c74f3ba5cd99cf29fb9efff38bf57b3d808e34a5dd4200dd2`
- **SHA256:** `048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c`
- **SHA256:** `6f9fbe29f8cc2788e2bc9d631e0eea2a8e9837076837b55838005a0e654f0a9e`
- **SHA256:** `d0da2832ae1e13a98f7ce7e33a66c1b0d9797b81f69ece134e4462ea55ac923e`
- **SHA256:** `aea26980059ef2ad11e99556a4edfa1f8ec769fa9f06aa573b81bedf319954b5`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1204.002** — User Execution: Malicious File
- **T1105** — Ingress Tool Transfer
- **T1036.005** — Match Legitimate Name or Location
- **T1068** — Exploitation for Privilege Escalation
- **T1562.001** — Disable or Modify Tools
- **T1014** — Rootkit
- **T1055** — Process Injection
- **T1055.002** — Portable Executable Injection
- **T1090.002** — External Proxy
- **T1572** — Protocol Tunneling

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PowerShell drops 'tech support hotfix' ZIP archive (DragonForce Backdoor.Turn delivery)

`UC_63_12` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe") (Processes.process="*Invoke-WebRequest*" OR Processes.process="*DownloadFile*" OR Processes.process="*Start-BitsTransfer*" OR Processes.process="*curl*" OR Processes.process="*wget*") (Processes.process="*.zip*" AND (Processes.process="*hotfix*" OR Processes.process="*support*" OR Processes.process="*patch*" OR Processes.process="*update*")) by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("Invoke-WebRequest","iwr ","DownloadFile","Start-BitsTransfer","Invoke-RestMethod","curl ","wget ")
| where ProcessCommandLine has ".zip"
| where ProcessCommandLine has_any ("hotfix","support","techsupport","patch","update","kb")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Bring-Your-Own-Vulnerable-Driver load (HWAuidoOs2Ec.sys + DragonForce BYOVD set)

`UC_63_13` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("HWAuidoOs2Ec.sys","hwauidos2ec.sys","wsftprm.sys","GameDriverX64.sys","gamedriverx64.sys","K7RKScan.sys","k7rkscan.sys","abyssworker.sys")) by Filesystem.dest Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let BYOVDFiles = dynamic(["HWAuidoOs2Ec.sys","wsftprm.sys","GameDriverX64.sys","K7RKScan.sys","abyssworker.sys"]);
let BYOVDHashes = dynamic(["82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b","821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6","b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383"]);
union
(DeviceFileEvents
  | where Timestamp > ago(30d)
  | where ActionType in ("FileCreated","FileModified","FileRenamed")
  | where FileName in~ (BYOVDFiles) or SHA256 in (BYOVDHashes)
  | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, Source="FileEvent"),
(DeviceImageLoadEvents
  | where Timestamp > ago(30d)
  | where FileName in~ (BYOVDFiles) or SHA256 in (BYOVDHashes)
  | project Timestamp, DeviceName, ActionType="ImageLoad", FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName=InitiatingProcessAccountName, Source="ImageLoad"),
(DeviceRegistryEvents
  | where Timestamp > ago(30d)
  | where RegistryKey has @"\SYSTEM\CurrentControlSet\Services\"
  | where RegistryValueData has_any (BYOVDFiles)
  | project Timestamp, DeviceName, ActionType, FileName=RegistryValueName, FolderPath=RegistryKey, SHA256="", InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, Source="RegistryService")
| order by Timestamp desc
```

### Backdoor.Turn injection - CreateRemoteThread / process access targeting DbgView64.exe

`UC_63_14` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name="DbgView64.exe" by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | where parent_process_name!="explorer.exe" AND parent_process_name!="DbgView.exe"
```

**Defender KQL:**
```kql
// Inject-into-DbgView64.exe — CreateRemoteThread / OpenProcess on the article's named target
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("CreateRemoteThreadApiCall","OpenProcessApiCall","ProcessPrimaryTokenModified","WriteToLsassProcessMemory")
| extend TargetImage = tostring(parse_json(AdditionalFields).TargetImage),
         TargetFileName_x = tostring(parse_json(AdditionalFields).TargetFileName)
| where FileName =~ "DbgView64.exe" or TargetImage endswith @"\DbgView64.exe" or TargetFileName_x =~ "DbgView64.exe"
| where InitiatingProcessFileName !~ "DbgView64.exe"
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, TargetImage, AdditionalFields
| order by Timestamp desc
```

### Backdoor.Turn - DbgView64.exe initiating outbound network connection

`UC_63_15` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.transport) as transport from datamodel=Network_Traffic.All_Traffic where All_Traffic.process_name="DbgView64.exe" by All_Traffic.src All_Traffic.process_name All_Traffic.user | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | where isnotnull(dest_ip)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "DbgView64.exe"
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol, InitiatingProcessAccountName
| order by Timestamp desc
```

### DragonForce Backdoor.Turn - Known C2 IOC contact (IP/domain/SHA256)

`UC_63_16` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as ips values(All_Traffic.dest) as dest from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("62.164.177.25","192.36.27.51") OR All_Traffic.dest IN ("projetosmecanicos.com.br","socialbizsolutions.com","professionalhomebasedbusiness.com","safefire.jo","glanz-gmbh.de","turnkeyaiagents.com","comunidadesparentais.com.br","mysimerp.net") by All_Traffic.src All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let C2IPs = dynamic(["62.164.177.25","192.36.27.51"]);
let C2Domains = dynamic(["projetosmecanicos.com.br","socialbizsolutions.com","professionalhomebasedbusiness.com","safefire.jo","glanz-gmbh.de","turnkeyaiagents.com","comunidadesparentais.com.br","mysimerp.net"]);
let C2Hashes = dynamic(["82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b","821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6","b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383","ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0","f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b","142bac0e2148e0d47891b6cd7311195c4acbe33b700fad54a201c52a2bc46219","8395b621bb4415090f232c59fc41d24ea41a519b58eabe512f3ae7d2fdf049a3","9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759","cd078957167e1af4de39aecdb981cd14156fa81d5a9c6ac51e74ae5b6199a12a","b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877","d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e","8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2","65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951","6bbf10bcbef7ac5102b54c81137859891a3802dbacd888be90f990d50e18b0b4","252a8bb2eb9c96c5e6cc7cab822e2ed0d508032f9350351221781684e86c03ab","8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531","e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22","087f002df0a02c8c74f3ba5cd99cf29fb9efff38bf57b3d808e34a5dd4200dd2","048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c","6f9fbe29f8cc2788e2bc9d631e0eea2a8e9837076837b55838005a0e654f0a9e"]);
union
(DeviceNetworkEvents
  | where Timestamp > ago(90d)
  | where RemoteIP in (C2IPs) or RemoteUrl has_any (C2Domains)
  | project Timestamp, DeviceName, Indicator=iff(RemoteIP in (C2IPs), RemoteIP, RemoteUrl), IndicatorType=iff(RemoteIP in (C2IPs), "IP", "Domain"), InitiatingProcessFileName, InitiatingProcessCommandLine, RemotePort, Protocol),
(DeviceFileEvents
  | where Timestamp > ago(90d)
  | where SHA256 in (C2Hashes)
  | project Timestamp, DeviceName, Indicator=SHA256, IndicatorType="SHA256", InitiatingProcessFileName=InitiatingProcessFileName, InitiatingProcessCommandLine=InitiatingProcessCommandLine, RemotePort=0, Protocol=""),
(DeviceProcessEvents
  | where Timestamp > ago(90d)
  | where SHA256 in (C2Hashes) or InitiatingProcessSHA256 in (C2Hashes)
  | project Timestamp, DeviceName, Indicator=iff(SHA256 in (C2Hashes), SHA256, InitiatingProcessSHA256), IndicatorType="SHA256", InitiatingProcessFileName, InitiatingProcessCommandLine, RemotePort=0, Protocol="")
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

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Article-specific behavioural hunt — DragonForce Hackers Abuse Microsoft Teams Relays to Hide Backdoor.Turn C2 Traffi

`UC_63_11` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — DragonForce Hackers Abuse Microsoft Teams Relays to Hide Backdoor.Turn C2 Traffi ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("hwauidoos2ec.sys","wsftprm.sys","gamedriverx64.sys","k7rkscan.sys","dbgview64.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("hwauidoos2ec.sys","wsftprm.sys","gamedriverx64.sys","k7rkscan.sys","dbgview64.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — DragonForce Hackers Abuse Microsoft Teams Relays to Hide Backdoor.Turn C2 Traffi
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("hwauidoos2ec.sys", "wsftprm.sys", "gamedriverx64.sys", "k7rkscan.sys", "dbgview64.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("hwauidoos2ec.sys", "wsftprm.sys", "gamedriverx64.sys", "k7rkscan.sys", "dbgview64.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `62.164.177.25`, `192.36.27.51`, `projetosmecanicos.com.br`, `socialbizsolutions.com`, `professionalhomebasedbusiness.com`, `safefire.jo`, `glanz-gmbh.de`, `turnkeyaiagents.com` _(+2 more)_

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-52271`, `CVE-2025-61155`, `CVE-2025-1055`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b`, `821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6`, `b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383`, `ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0`, `f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b`, `142bac0e2148e0d47891b6cd7311195c4acbe33b700fad54a201c52a2bc46219`, `8395b621bb4415090f232c59fc41d24ea41a519b58eabe512f3ae7d2fdf049a3`, `9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759` _(+14 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 17 use case(s) fired, 26 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
