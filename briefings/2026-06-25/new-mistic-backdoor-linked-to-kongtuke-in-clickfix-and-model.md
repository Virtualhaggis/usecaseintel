# [CRIT] New Mistic Backdoor Linked to KongTuke in ClickFix and ModeloRAT Campaigns

**Source:** The Hacker News
**Published:** 2026-06-25
**Article:** https://thehackernews.com/2026/06/new-mistic-backdoor-linked-to-kongtuke.html

## Threat Profile

New Mistic Backdoor Linked to KongTuke in ClickFix and ModeloRAT Campaigns 
 Ravie Lakshmanan  Jun 25, 2026 Initial Access Broker / Ransomware 
A new, stealthy backdoor named Mistic has been deployed as part of suspected financially motivated attacks aimed at multiple organizations spanning insurance, education, IT, and professional services sectors since April 2026.
According to Symantec and Carbon Black's Threat Hunter Team, the backdoor, also tracked as MLTBackdoor, is said to be linked to …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `142.93.242.144`
- **IPv4 (defanged):** `144.31.53.78`
- **IPv4 (defanged):** `198.13.159.44`
- **IPv4 (defanged):** `199.91.221.42`
- **Domain (defanged):** `authorized-logins.net`
- **Domain (defanged):** `mail.authorized-logins.net`
- **Domain (defanged):** `php.authorized-logins.net`
- **Domain (defanged):** `sss.authorized-logins.net`
- **Domain (defanged):** `updater-worelos.com`
- **Domain (defanged):** `mails.updater-worelos.com`
- **Domain (defanged):** `defs.updater-worelos.com`
- **Domain (defanged):** `upd-domain-goloro.com`
- **Domain (defanged):** `mailes.upd-domain-goloro.com`
- **Domain (defanged):** `ftps.upd-domain-goloro.com`
- **Domain (defanged):** `upscale-kolo.com`
- **Domain (defanged):** `nano.upscale-kolo.com`
- **Domain (defanged):** `update-fall.com`
- **Domain (defanged):** `sql-updater-service.com`
- **Domain (defanged):** `rotoa-upda-lo.com`
- **Domain (defanged):** `human-check.top`
- **Domain (defanged):** `grande-luna.top`
- **Domain (defanged):** `b6w9m2z5x8q1v3k.top`
- **Domain (defanged):** `w3xasv14culvnqj.top`
- **Domain (defanged):** `carrolc.com`
- **Domain (defanged):** `cwrtwright.com`
- **Domain (defanged):** `mueleer.com`
- **Domain (defanged):** `oeannon.com`
- **Domain (defanged):** `thomphon.com`
- **Domain (defanged):** `thomphon.com/update.msi`
- **Domain (defanged):** `cj06y9v4xab.com`
- **SHA256:** `1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984`
- **SHA256:** `34d798a6c55e57ed0932b6499f4fbcb5454bdfca903307be101a0594b0ac07bc`
- **SHA256:** `3f797a639bc855bc6d5471f327924b62d10900ddec49b970eca6604142bbb4be`
- **SHA256:** `59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712`
- **SHA256:** `8c935feec4bd05d5d918df308be417532fb42608fb989a08eab183e0ae699235`
- **SHA256:** `afd5f1ed45a9867daf3bc64152cef460a06b164c8183e490db39146d4749a82c`
- **SHA256:** `db972979d508e75fe730d3b72c2701470fbdaeaf8ebdd674744754fa44438ca5`
- **SHA256:** `f591275a8f014b29e567529d67c54eb7bb4473db1c38737d6bfd5b3d52c9344e`
- **SHA256:** `fb3630822b70bacb56aa4cec29b5a0e3e9acb3920809e70310a4003385a6d34a`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1071.004** — Application Layer Protocol: DNS
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1620** — Reflective Code Loading

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Mistic backdoor DLL side-load: MpExtMs.exe loading rogue version.dll / EndpointDlp.dll

`UC_10_13` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="MpExtMs.exe" NOT (Processes.process_path IN ("*\\Windows Defender\\*","*\\Windows\\System32\\*","*\\WinSxS\\*")) by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.process_hash
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "MpExtMs.exe"
| where FileName in~ ("version.dll","EndpointDlp.dll")
| where not(FolderPath has @"\Windows Defender\" or FolderPath has @"\Windows\System32\" or FolderPath has @"\WinSxS\")
| project Timestamp, DeviceName, InitiatingProcessFolderPath, InitiatingProcessSHA256, LoadedDll = FileName, LoadedDllPath = FolderPath, SHA256
| order by Timestamp desc
```

### KongTuke ClickFix DNS staging: nslookup TXT queries to Mistic/ModeloRAT domains

`UC_10_14` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="nslookup.exe" (Processes.process="*type=txt*" OR Processes.process="*q=txt*" OR Processes.process="*querytype=txt*") (Processes.process="*updater-worelos.com*" OR Processes.process="*upd-domain-goloro.com*" OR Processes.process="*authorized-logins.net*" OR Processes.process="*upscale-kolo.com*" OR Processes.process="*update-fall.com*" OR Processes.process="*sql-updater-service.com*" OR Processes.process="*rotoa-upda-lo.com*" OR Processes.process="*human-check.top*" OR Processes.process="*grande-luna.top*" OR Processes.parent_process_name="explorer.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "nslookup.exe"
| where ProcessCommandLine has_any ("-type=txt","-q=txt","-querytype=txt","type=txt")
| where ProcessCommandLine has_any ("updater-worelos.com","upd-domain-goloro.com","authorized-logins.net","upscale-kolo.com","update-fall.com","sql-updater-service.com","rotoa-upda-lo.com","human-check.top","grande-luna.top")
   or InitiatingProcessFileName in~ ("explorer.exe","cmd.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Mistic / ModeloRAT C2 beacon to KongTuke domains and IPs

`UC_10_15` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*updater-worelos.com" OR DNS.query="*upd-domain-goloro.com" OR DNS.query="*authorized-logins.net" OR DNS.query="*upscale-kolo.com" OR DNS.query="*update-fall.com" OR DNS.query="*sql-updater-service.com" OR DNS.query="*rotoa-upda-lo.com" OR DNS.query="*human-check.top" OR DNS.query="*grande-luna.top" OR DNS.query="*b6w9m2z5x8q1v3k.top" OR DNS.query="*w3xasv14culvnqj.top" OR DNS.query="*carrolc.com") by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("updater-worelos.com","upd-domain-goloro.com","authorized-logins.net","upscale-kolo.com","update-fall.com","sql-updater-service.com","rotoa-upda-lo.com","human-check.top","grande-luna.top","b6w9m2z5x8q1v3k.top","w3xasv14culvnqj.top","carrolc.com")
   or RemoteIP in ("142.93.242.144","144.31.53.78","198.13.159.44","199.91.221.42")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Backdoor.Mistic loader/payload file hash sweep

`UC_10_16` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984","34d798a6c55e57ed0932b6499f4fbcb5454bdfca903307be101a0594b0ac07bc","3f797a639bc855bc6d5471f327924b62d10900ddec49b970eca6604142bbb4be","59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712","8c935feec4bd05d5d918df308be417532fb42608fb989a08eab183e0ae699235","afd5f1ed45a9867daf3bc64152cef460a06b164c8183e490db39146d4749a82c","db972979d508e75fe730d3b72c2701470fbdaeaf8ebdd674744754fa44438ca5","f591275a8f014b29e567529d67c54eb7bb4473db1c38737d6bfd5b3d52c9344e","fb3630822b70bacb56aa4cec29b5a0e3e9acb3920809e70310a4003385a6d34a") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process_hash
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MisticHashes = dynamic(["1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984","34d798a6c55e57ed0932b6499f4fbcb5454bdfca903307be101a0594b0ac07bc","3f797a639bc855bc6d5471f327924b62d10900ddec49b970eca6604142bbb4be","59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712","8c935feec4bd05d5d918df308be417532fb42608fb989a08eab183e0ae699235","afd5f1ed45a9867daf3bc64152cef460a06b164c8183e490db39146d4749a82c","db972979d508e75fe730d3b72c2701470fbdaeaf8ebdd674744754fa44438ca5","f591275a8f014b29e567529d67c54eb7bb4473db1c38737d6bfd5b3d52c9344e","fb3630822b70bacb56aa4cec29b5a0e3e9acb3920809e70310a4003385a6d34a"]);
union
(DeviceProcessEvents | where Timestamp > ago(30d) | where SHA256 in (MisticHashes) | project Timestamp, DeviceName, Source="Process", FileName, FolderPath, SHA256, InitiatingProcessFileName),
(DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 in (MisticHashes) | project Timestamp, DeviceName, Source="File", FileName, FolderPath, SHA256, InitiatingProcessFileName),
(DeviceImageLoadEvents | where Timestamp > ago(30d) | where SHA256 in (MisticHashes) | project Timestamp, DeviceName, Source="ImageLoad", FileName, FolderPath, SHA256, InitiatingProcessFileName)
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

### Article-specific behavioural hunt — New Mistic Backdoor Linked to KongTuke in ClickFix and ModeloRAT Campaigns

`UC_10_12` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New Mistic Backdoor Linked to KongTuke in ClickFix and ModeloRAT Campaigns ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("mpextms.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("mpextms.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New Mistic Backdoor Linked to KongTuke in ClickFix and ModeloRAT Campaigns
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("mpextms.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("mpextms.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `142.93.242.144`, `144.31.53.78`, `198.13.159.44`, `199.91.221.42`, `authorized-logins.net`, `mail.authorized-logins.net`, `php.authorized-logins.net`, `sss.authorized-logins.net` _(+22 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984`, `34d798a6c55e57ed0932b6499f4fbcb5454bdfca903307be101a0594b0ac07bc`, `3f797a639bc855bc6d5471f327924b62d10900ddec49b970eca6604142bbb4be`, `59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712`, `8c935feec4bd05d5d918df308be417532fb42608fb989a08eab183e0ae699235`, `afd5f1ed45a9867daf3bc64152cef460a06b164c8183e490db39146d4749a82c`, `db972979d508e75fe730d3b72c2701470fbdaeaf8ebdd674744754fa44438ca5`, `f591275a8f014b29e567529d67c54eb7bb4473db1c38737d6bfd5b3d52c9344e` _(+1 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 17 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
