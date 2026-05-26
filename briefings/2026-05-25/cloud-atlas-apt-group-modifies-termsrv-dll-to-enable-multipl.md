# [CRIT] Cloud Atlas APT Group Modifies termsrv.dll to Enable Multiple RDP Sessions on Victim Hosts

**Source:** Cyber Security News
**Published:** 2026-05-25
**Article:** https://cybersecuritynews.com/cloud-atlas-apt-group-modifies-termsrv-dll/

## Threat Profile

Home Cyber Security News 
Cloud Atlas APT Group Modifies termsrv.dll to Enable Multiple RDP Sessions on Victim Hosts 
By Tushar Subhra Dutta 
May 25, 2026 
A well-known advanced persistent threat group called Cloud Atlas has been caught using a dangerous technique to hijack Windows systems without alerting anyone on the network. 
The group modifies a core Windows file called termsrv.dll to unlock multiple simultaneous Remote Desktop Protocol (RDP) sessions on a victim’s computer. This lets attac…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2018-0802`
- **IPv4 (defanged):** `194.102.104.207`
- **IPv4 (defanged):** `46.17.45.56`
- **IPv4 (defanged):** `46.17.45.49`
- **IPv4 (defanged):** `46.17.44.125`
- **IPv4 (defanged):** `46.17.44.212`
- **IPv4 (defanged):** `185.22.154.73`
- **IPv4 (defanged):** `194.87.196.163`
- **IPv4 (defanged):** `195.58.49.9`
- **IPv4 (defanged):** `93.125.114.193`
- **IPv4 (defanged):** `93.125.114.57`
- **IPv4 (defanged):** `45.87.219.116`
- **IPv4 (defanged):** `37.228.129.224`
- **IPv4 (defanged):** `185.53.179.136`
- **IPv4 (defanged):** `185.126.239.77`
- **IPv4 (defanged):** `5.181.21.75`
- **IPv4 (defanged):** `146.70.53.171`
- **IPv4 (defanged):** `45.15.65.134`
- **IPv4 (defanged):** `185.250.181.207`
- **IPv4 (defanged):** `81.30.105.71`
- **Domain (defanged):** `tenkoff.org`
- **Domain (defanged):** `cloudguide.in`
- **Domain (defanged):** `goverru.com`
- **Domain (defanged):** `kufar.org`
- **Domain (defanged):** `ultimatecore.net`
- **Domain (defanged):** `spbnews.net`
- **Domain (defanged):** `onedrivesupport.net`
- **Domain (defanged):** `amerikastaj.com`
- **Domain (defanged):** `bigbang.me`
- **Domain (defanged):** `wizzifi.com`
- **Domain (defanged):** `totallegacy.org`
- **Domain (defanged):** `mamurjor.com`
- **Domain (defanged):** `landscapeuganda.com`
- **Domain (defanged):** `lafortunaitalian.co.uk`
- **Domain (defanged):** `kommando.live`
- **Domain (defanged):** `internationalcommoditiesllc.com`
- **Domain (defanged):** `humanitas.si`
- **Domain (defanged):** `fishingflytackle.com`
- **Domain (defanged):** `firsai.tipshub.net`
- **Domain (defanged):** `alnakhlah.com.sa`
- **Domain (defanged):** `allgoodsdirect.com.au`
- **Domain (defanged):** `agenciakharis.com.br`
- **Domain (defanged):** `istochnik.org`
- **Domain (defanged):** `znews.net`
- **Domain (defanged):** `investika-club.com`
- **Domain (defanged):** `paleturquoise-dragonfly-364512.hostingersite.com`
- **MD5:** `1a11b26dd0261ef27a112ce8b361c247`
- **MD5:** `5329f7bff9d0d5db28821b86c26d628f`
- **MD5:** `7a95360b7e0eb5b107a3d231abbc541a`
- **MD5:** `c0d1eaa15a2cefbab9735787575c8d8e`
- **MD5:** `d5b38b252cf212a4a32763de36732d40`
- **MD5:** `3c75cedb1196df5eab91f31411ed4b33`
- **MD5:** `42ac350bfbc5b4eb0fedba16c81919c7`
- **MD5:** `493b901d1b33eb577db64aadd948f9ce`
- **MD5:** `2cabb721681455dae1b6a26709def453`
- **MD5:** `1b39e86eb772a0e40060b672b7f574f1`
- **MD5:** `1d401d6e6fc0b00aaa2c65a0ac0cfd6b`
- **MD5:** `40a562b8600f843b717bc5951b2e3c29`
- **MD5:** `2b4ba4facf8c299749771a3a4369782e`
- **MD5:** `ba9ce06641067742f2afc9691faff1dc`
- **MD5:** `fb0f8027acf1b1e47e07a63d8812ed50`
- **MD5:** `bbf1fa694122e07635deeac11ad712f8`
- **MD5:** `f301aa3d62b5095eec4d8e34201a4769`
- **MD5:** `f9c3bbe108566d1a6b070f9c5fb03160`
- **MD5:** `369b75bdcded16469ede7ab8bedcfae1`
- **MD5:** `9eaae9491f6a50d6df0be393734a44cb`
- **MD5:** `3e6e9df00a764b348ec611ee8504aca0`
- **MD5:** `9bd788f285e32a05e6591d1eb36ebffc`
- **MD5:** `f42085522ec2ebb16edcf814e7c330ad`
- **MD5:** `2042eb5d52f0b535a1ce6b6f954c8c2b`
- **MD5:** `2aa1e9765ef6b00b94a9b6be0041436a`
- **MD5:** `36120f5e9411bcbac7104ef3fa964ed2`
- **MD5:** `5000a353399500bc78381dc95b6ed2dc`
- **MD5:** `579a9952d31cad801a3988dbe7914ce7`
- **MD5:** `867b634588c0fd6b26684d502c15ab03`
- **MD5:** `38fa4306fa4406ba31cf171af4d36e34`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1053.005** — Scheduled Task
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1053.005** — Persistence (article-specific)
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1562.004** — Impair Defenses: Disable or Modify System Firewall
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1572** — Protocol Tunneling
- **T1090** — Proxy
- **T1021.004** — Remote Services: SSH
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1059.001** — Command and Scripting Interpreter: PowerShell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Cloud Atlas termsrv.dll patch enabling concurrent RDP sessions (takeown/icacls/sc)

`UC_2_15` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*takeown*" OR Processes.process="*icacls*" OR Processes.process="*sc *") AND Processes.process="*termsrv.dll*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name IN ("sc.exe","net.exe","powershell.exe") AND Processes.process="*TermService*" AND (Processes.process="*stop*" OR Processes.process="*start*" OR Processes.process="*restart*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)`] | stats values(process) as commands min(firstTime) as firstTime max(lastTime) as lastTime by dest user | where mvcount(commands) > 1 | `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
let Patchers = DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "termsrv.dll"
| where ProcessCommandLine has_any ("takeown", "icacls", "/grant")
| where AccountName !endswith "$"
| project Timestamp, DeviceId, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
let DllWrites = DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has @"\System32\termsrv.dll" and ActionType in ("FileModified","FileCreated","FileRenamed")
| where InitiatingProcessFileName !in~ ("TiWorker.exe","TrustedInstaller.exe","poqexec.exe")
| project Timestamp, DeviceId, ActionType, FolderPath, InitiatingProcessFileName;
Patchers
| join kind=inner (DllWrites) on DeviceId
| where abs(datetime_diff('second', Timestamp, Timestamp1)) <= 600
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, DllWriteAction = ActionType, DllPath = FolderPath, DllWriter = InitiatingProcessFileName
| order by Timestamp desc
```

### [LLM] Cloud Atlas PowerCloud / RevSocks payloads masquerading in Windows system folders

`UC_2_16` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_path IN ("C:\\Windows\\wininet.exe","C:\\Windows\\LiveKernelReports\\update.exe","C:\\Windows\\ime\\imejp\\dicts\\i39884.exe","C:\\Windows\\pla\\reports.exe","C:\\Windows\\pla\\reports\\winlog.exe","C:\\Windows\\System32\\timecontrolsvc\\vmnetdrv64.exe","C:\\Windows\\branding\\scat.exe","C:\\Windows\\PLA\\System\\bounce.exe","C:\\ProgramData\\hp\\client.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
let BadPaths = dynamic([
  @"\Windows\wininet.exe",
  @"\Windows\LiveKernelReports\update.exe",
  @"\Windows\ime\imejp\dicts\i39884.exe",
  @"\Windows\pla\reports.exe",
  @"\Windows\pla\reports\winlog.exe",
  @"\Windows\System32\timecontrolsvc\vmnetdrv64.exe",
  @"\Windows\branding\scat.exe",
  @"\Windows\PLA\System\bounce.exe",
  @"\ProgramData\hp\client.exe"]);
union
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FolderPath has_any (BadPaths)
  | project Timestamp, DeviceName, AccountName, Event="ProcessExec", Path=FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName ),
( DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FolderPath has_any (BadPaths) and ActionType in ("FileCreated","FileModified")
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Event="FileDrop", Path=FolderPath, SHA256, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName )
| order by Timestamp desc
```

### [LLM] Cloud Atlas reverse SSH tunnel via renamed ssh binaries to attacker C2

`UC_2_17` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process_path="C:\\Windows\\PLA\\System\\conhosts.exe" OR All_Traffic.process_path="C:\\Windows\\INF\\BITS\\esentprf.exe" OR All_Traffic.app="conhosts.exe" OR All_Traffic.app="esentprf.exe") AND All_Traffic.direction="outbound" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
let C2ips = dynamic(["194.102.104.207","46.17.45.56","46.17.45.49"]);
let C2domains = dynamic(["tenkoff.org","cloudguide.in","goverru.com","kufar.org","ultimatecore.net","spbnews.net","onedrivesupport.net","amerikastaj.com","bigbang.me"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFolderPath has_any (@"\PLA\System\conhosts.exe", @"\INF\BITS\esentprf.exe")
   or InitiatingProcessFileName in~ ("conhosts.exe","esentprf.exe")
| where RemoteIPType == "Public"
| extend KnownC2 = (RemoteIP in (C2ips)) or (RemoteUrl has_any (C2domains))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, KnownC2
| order by Timestamp desc
```

### [LLM] Cloud Atlas VBS tunnel/keep-alive scripts executed from INF and PLA directories

`UC_2_18` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("wscript.exe","cscript.exe") AND (Processes.process="*\\INF\\Run.vbs*" OR Processes.process="*\\INF\\install.vbs*" OR Processes.process="*\\PLA\\System\\Gen.vbs*" OR Processes.process="*\\PLA\\System\\Kill.vbs*" OR Processes.process="*\\PLA\\System\\Run.vbs*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine has_any (@"\INF\Run.vbs", @"\INF\install.vbs", @"\PLA\System\Gen.vbs", @"\PLA\System\Kill.vbs", @"\PLA\System\Run.vbs")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] Cloud Atlas C2 / SOCKS-proxy / Tor egress to reported infrastructure

`UC_2_19` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("194.102.104.207","46.17.45.56","46.17.45.49","46.17.44.125","46.17.44.212","185.22.154.73","194.87.196.163","195.58.49.99","3.125.114.193","3.125.114.57","45.87.219.116","37.228.129.224","185.53.179.136","185.126.239.77","5.181.21.75","146.70.53.171","45.15.65.134","185.250.181.207","81.30.105.71") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
let C2ips = dynamic(["194.102.104.207","46.17.45.56","46.17.45.49","46.17.44.125","46.17.44.212","185.22.154.73","194.87.196.163","195.58.49.99","3.125.114.193","3.125.114.57","45.87.219.116","37.228.129.224","185.53.179.136","185.126.239.77","5.181.21.75","146.70.53.171","45.15.65.134","185.250.181.207","81.30.105.71"]);
let C2domains = dynamic(["tenkoff.org","cloudguide.in","goverru.com","kufar.org","ultimatecore.net","spbnews.net","onedrivesupport.net","amerikastaj.com","bigbang.me","wizzifi.com","totallegacy.org","mamurjor.com","landscapeuganda.com","kommando.live"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (C2ips) or RemoteUrl has_any (C2domains)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count(), Ports=make_set(RemotePort) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemoteUrl
| order by FirstSeen desc
```

### [LLM] Cloud Atlas PowerShower persistence: PowerShell running googleearth.ps1 from Pictures

`UC_2_20` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe") AND Processes.process="*\\Pictures\\googleearth.ps1*" by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has @"\Pictures\googleearth.ps1"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
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

### Phishing-link click correlated to endpoint execution

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Phishing-link click that drives endpoint execution within 60s ```
| tstats `summariesonly` earliest(_time) AS click_time
    from datamodel=Web
    where Web.action="allowed"
    by Web.src, Web.user, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| rename user AS recipient, dest AS clicked_domain, url AS clicked_url
| join type=inner recipient
    [| tstats `summariesonly` count
         from datamodel=Email.All_Email
         where All_Email.action="delivered" AND All_Email.url!="-"
         by All_Email.recipient, All_Email.src_user, All_Email.url, All_Email.subject
     | `drop_dm_object_name(All_Email)`
     | rex field=url "https?://(?<email_domain>[^/]+)"
     | rename recipient AS recipient]
| join type=inner src
    [| tstats `summariesonly` earliest(_time) AS exec_time
         values(Processes.process) AS exec_cmd, values(Processes.process_name) AS exec_proc
         from datamodel=Endpoint.Processes
         where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                                   "outlook.exe","brave.exe","arc.exe")
           AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                                            "rundll32.exe","regsvr32.exe","wscript.exe",
                                            "cscript.exe","bitsadmin.exe","certutil.exe",
                                            "curl.exe","wget.exe")
         by Processes.dest, Processes.user
     | `drop_dm_object_name(Processes)`
     | rename dest AS src]
| eval delta_sec = exec_time - click_time
| where delta_sec >= 0 AND delta_sec <= 60
| table click_time, exec_time, delta_sec, recipient, src, src_user, subject,
        clicked_domain, clicked_url, exec_proc, exec_cmd
| sort - click_time
```

**Defender KQL:**
```kql
// Phishing-link click that drives endpoint execution within 60s.
// Far higher fidelity than "every clicked URL" — most legitimate clicks
// never spawn a non-browser child process, so the join eliminates the
// 99% of noise that makes a raw click query unactionable.
let LookbackDays = 7d;
let SuspectClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(LookbackDays)
        | where DeliveryAction == "Delivered"
        | where EmailDirection == "Inbound"
        | project NetworkMessageId, Subject, SenderFromAddress, SenderFromDomain,
                  RecipientEmailAddress, EmailTimestamp = Timestamp
      ) on NetworkMessageId
    | join kind=leftouter (
        EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId, Url
    | project ClickTime = Timestamp, AccountUpn, IPAddress, Url, UrlDomain,
              Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
              ActionType;
// Correlate to a non-browser child process spawned within 60 seconds on
// the recipient's device.
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                         "outlook.exe","brave.exe","arc.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                        "rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe",
                        "bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| join kind=inner SuspectClicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + 60s)
| project ClickTime, ProcessTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountName, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, ActionType,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by ClickTime desc
```

### Email attachment opened from external sender

`UC_PHISH_ATTACH` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.file_name!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.file_name, All_Email.subject
| rename All_Email.recipient as user
| join type=inner user
    [| tstats `summariesonly` count
        from datamodel=Endpoint.Processes
        where Processes.parent_process_name IN ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
          AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
        by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
     | rename Processes.user as user]
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let MalAttachments = EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | project NetworkMessageId, RecipientEmailAddress,
              AttachmentFileName = FileName, AttachmentSHA256 = SHA256;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                      "mshta.exe","rundll32.exe","regsvr32.exe")
| join kind=inner MalAttachments on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AttachmentFileName, AttachmentSHA256
```

### Office app spawning script/LOLBin child process

`UC_OFFICE_CHILD` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
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

### Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)

`UC_FAKECAPTCHA` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Cloud Atlas APT Group Modifies termsrv.dll to Enable Multiple RDP Sessions on Vi

`UC_2_14` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Cloud Atlas APT Group Modifies termsrv.dll to Enable Multiple RDP Sessions on Vi ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("termsrv.dll","rdp_new.ps1","googleearth.ps1","wininet.exe","i39884.exe","reports.exe","winlog.exe","vmnetdrv64.exe","scat.exe","bounce.exe","client.exe","run.vbs","install.vbs","gen.vbs","kill.vbs") OR Processes.process_path="*C:\Windows\wininet.exe*" OR Processes.process_path="*C:\Windows\LiveKernelReports\update.exe*" OR Processes.process_path="*C:\Windows\ime\imejp\dicts\i39884.exe*" OR Processes.process_path="*C:\Windows\pla\reports.exe*" OR Processes.process_path="*C:\Windows\pla\reports\winlog.exe*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Windows\wininet.exe*" OR Filesystem.file_path="*C:\Windows\LiveKernelReports\update.exe*" OR Filesystem.file_path="*C:\Windows\ime\imejp\dicts\i39884.exe*" OR Filesystem.file_path="*C:\Windows\pla\reports.exe*" OR Filesystem.file_path="*C:\Windows\pla\reports\winlog.exe*" OR Filesystem.file_path="*C:\Windows\System32\timecontrolsvc\vmnetdrv64.exe*" OR Filesystem.file_path="*C:\Windows\branding\scat.exe*" OR Filesystem.file_path="*C:\Windows\PLA\System\bounce.exe*" OR Filesystem.file_name IN ("termsrv.dll","rdp_new.ps1","googleearth.ps1","wininet.exe","i39884.exe","reports.exe","winlog.exe","vmnetdrv64.exe","scat.exe","bounce.exe","client.exe","run.vbs","install.vbs","gen.vbs","kill.vbs"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Cloud Atlas APT Group Modifies termsrv.dll to Enable Multiple RDP Sessions on Vi
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("termsrv.dll", "rdp_new.ps1", "googleearth.ps1", "wininet.exe", "i39884.exe", "reports.exe", "winlog.exe", "vmnetdrv64.exe", "scat.exe", "bounce.exe", "client.exe", "run.vbs", "install.vbs", "gen.vbs", "kill.vbs") or FolderPath has_any ("C:\Windows\wininet.exe", "C:\Windows\LiveKernelReports\update.exe", "C:\Windows\ime\imejp\dicts\i39884.exe", "C:\Windows\pla\reports.exe", "C:\Windows\pla\reports\winlog.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Windows\wininet.exe", "C:\Windows\LiveKernelReports\update.exe", "C:\Windows\ime\imejp\dicts\i39884.exe", "C:\Windows\pla\reports.exe", "C:\Windows\pla\reports\winlog.exe", "C:\Windows\System32\timecontrolsvc\vmnetdrv64.exe", "C:\Windows\branding\scat.exe", "C:\Windows\PLA\System\bounce.exe") or FileName in~ ("termsrv.dll", "rdp_new.ps1", "googleearth.ps1", "wininet.exe", "i39884.exe", "reports.exe", "winlog.exe", "vmnetdrv64.exe", "scat.exe", "bounce.exe", "client.exe", "run.vbs", "install.vbs", "gen.vbs", "kill.vbs"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `194.102.104.207`, `46.17.45.56`, `46.17.45.49`, `46.17.44.125`, `46.17.44.212`, `185.22.154.73`, `194.87.196.163`, `195.58.49.9` _(+37 more)_

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2018-0802`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `1a11b26dd0261ef27a112ce8b361c247`, `5329f7bff9d0d5db28821b86c26d628f`, `7a95360b7e0eb5b107a3d231abbc541a`, `c0d1eaa15a2cefbab9735787575c8d8e`, `d5b38b252cf212a4a32763de36732d40`, `3c75cedb1196df5eab91f31411ed4b33`, `42ac350bfbc5b4eb0fedba16c81919c7`, `493b901d1b33eb577db64aadd948f9ce` _(+22 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 21 use case(s) fired, 34 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
