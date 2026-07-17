# [CRIT] ACR Stealer Uses ClickFix Lures to Steal Browser Tokens and Microsoft 365 Files

**Source:** The Hacker News
**Published:** 2026-07-17
**Article:** https://thehackernews.com/2026/07/acr-stealer-uses-clickfix-lures-to.html

## Threat Profile

ACR Stealer Uses ClickFix Lures to Steal Browser Tokens and Microsoft 365 Files 
 Swati Khandelwal  Jul 17, 2026 Malware / Windows Security 
ACR Stealer , an infostealer in circulation since 2024, is walking out of enterprise networks with saved browser passwords, live session tokens, PDFs, Microsoft 365 documents, and files from synced OneDrive and SharePoint folders.
It gets in because someone pasted a command into a Run box and pressed Enter. Microsoft laid out two of the delivery chains on…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `creativecommunityinfo.art`
- **Domain (defanged):** `enhanceblabber.cc`
- **Domain (defanged):** `deep-harborio.com`
- **Domain (defanged):** `auramatrixa.com`
- **Domain (defanged):** `zealpraxis.com`
- **Domain (defanged):** `prism-vertex.com`
- **Domain (defanged):** `prism-matrixs.com`
- **Domain (defanged):** `proton-network.com`
- **Domain (defanged):** `looksta.icu`
- **Domain (defanged):** `quirksturdy.icu`
- **Domain (defanged):** `strainedeasily.icu`
- **Domain (defanged):** `cpppemwjewjoiwejow.sale`
- **Domain (defanged):** `wifihot.icu`
- **Domain (defanged):** `filloco.icu`
- **Domain (defanged):** `raidher.icu`
- **Domain (defanged):** `apigrokcloud.icu`
- **Domain (defanged):** `sphere-api.dialectosphere.in.net`
- **Domain (defanged):** `claude-desktop.gitlab.io`
- **Domain (defanged):** `fairpoint29.com`
- **Domain (defanged):** `primemetricsa.com`
- **SHA256:** `70b5ecc110e074dbca92932c0e840ea3492ea0a43c3f215b71392c12b02213b2`
- **SHA256:** `a14c3ecf5eb3d2543358482e43dc765dbf9ee7a4bec7571f5ecb8829ca719692`
- **SHA256:** `47fa746422f1bf6b7712dc6803378e6a995488007193a7441d790f70d204728f`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1053.005** — Scheduled Task
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1053.005** — Persistence (article-specific)
- **T1218.011** — System Binary Proxy Execution: Rundll32
- **T1105** — Ingress Tool Transfer
- **T1564.003** — Hide Artifacts: Hidden Window
- **T1218.005** — System Binary Proxy Execution: Mshta
- **T1204.002** — User Execution: Malicious File
- **T1566.002** — Phishing: Spearphishing Link
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1070.003** — Indicator Removal: Clear Command History
- **T1102** — Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### rundll32.exe with no command-line parameters making an outbound network connection

`UC_13_10` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name=rundll32.exe by _time Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | eval has_args=if(match(process,"(?i)rundll32\.exe\S*\s+\S"),"yes","no") | where has_args="no" | join type=inner dest [ | tstats `security_content_summariesonly` count as conn_count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_port=443 OR All_Traffic.dest_port=80) by All_Traffic.src | `drop_dm_object_name(All_Traffic)` | rename src as dest ] | table _time dest user process parent_process_name conn_count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "rundll32.exe"
| where RemoteIPType == "Public"
| where not(InitiatingProcessCommandLine matches regex @"(?i)rundll32\.exe\S*\s+\S")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### rundll32.exe loading a DLL from a WebDAV UNC share with GUID directory and export ordinal

`UC_13_11` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=rundll32.exe by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process,"\\\\[^\\]+\\[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\") AND match(process,",\s*#\d") | `security_content_ctime(firstTime)` | table firstTime lastTime dest user process parent_process_name count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has "\\\\" and ProcessCommandLine matches regex @",\s*#\d"
| where ProcessCommandLine matches regex @"\\\\[^\\]+\\[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\"
   or ProcessCommandLine has_any ("dialectosphere.in.net", ".google,#", "05fe317c-0981-4de2-bc8a-930d369db441")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### conhost --headless wrapping a pushd WebDAV mount and rundll32 execution

`UC_13_12` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes where (Processes.process_name=conhost.exe OR Processes.process_name=cmd.exe) by _time Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where (process_name="conhost.exe" AND match(process,"(?i)--headless")) OR (process_name="cmd.exe" AND match(process,"(?i)pushd") AND match(process,"\\\\") AND match(process,"(?i)rundll32")) | table _time dest user process_name process parent_process_name count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "conhost.exe" and ProcessCommandLine has "--headless")
   or (FileName =~ "cmd.exe" and ProcessCommandLine has "pushd" and ProcessCommandLine has "\\\\" and ProcessCommandLine has "rundll32")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### mshta.exe fetching remote HTA content from the Run dialog (ACR fileless chain)

`UC_13_13` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime from datamodel=Endpoint.Processes where Processes.process_name=mshta.exe by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process,"(?i)https?://") OR match(process,"(?i)(javascript|vbscript):") | `security_content_ctime(firstTime)` | table firstTime dest user process parent_process_name count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("http://", "https://", "javascript:", "vbscript:")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### ClickFix Run-dialog paste launching mshta/rundll32/powershell (RunMRU artifact)

`UC_13_14` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\Explorer\\RunMRU*" by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data | `drop_dm_object_name(Registry)` | where match(registry_value_data,"(?i)(mshta|powershell|rundll32|curl|certutil|\\\\|http)") | `security_content_ctime(firstTime)` | table firstTime dest user registry_value_name registry_value_data count
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where RegistryKey has @"\Explorer\RunMRU"
| where RegistryValueData has_any ("mshta", "powershell", "rundll32", "cmd", "curl", "certutil", "\\\\", "http")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### Non-browser process accessing Chrome/Edge Login Data and Web Data stores

`UC_13_15` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="Login Data" OR Filesystem.file_name="Web Data") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where NOT match(process_name,"(?i)(chrome|msedge|browser_broker|elevation_service|msedgewebview2)\.exe") | `security_content_ctime(firstTime)` | table firstTime dest user process_name file_name file_path count
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName in~ ("Login Data", "Web Data")
| where FolderPath has_any (@"\Google\Chrome\User Data", @"\Microsoft\Edge\User Data")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","browser_broker.exe","elevation_service.exe","msedgewebview2.exe","chrome_proxy.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
| order by Timestamp desc
```

### pythonw.exe launching a script from %LocalAppData%\Temp with LOLBin parent

`UC_13_16` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime from datamodel=Endpoint.Processes where Processes.process_name=pythonw.exe by Processes.dest Processes.user Processes.process Processes.process_path Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process_path,"(?i)\\AppData\\Local\\Temp") OR match(process,"(?i)\\AppData\\Local\\Temp") OR match(process,"(?i)LogiOptionsPlus") | where match(parent_process_name,"(?i)(powershell|cmd|rundll32|mshta)\.exe") | `security_content_ctime(firstTime)` | table firstTime dest user process parent_process_name count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "pythonw.exe"
| where FolderPath has @"\AppData\Local\Temp" or ProcessCommandLine has @"\AppData\Local\Temp" or ProcessCommandLine has "LogiOptionsPlus"
| where InitiatingProcessFileName in~ ("powershell.exe","cmd.exe","rundll32.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Hidden scheduled task posing as a software update with PowerShell history clearing

`UC_13_17` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime from datamodel=Endpoint.Processes where (Processes.process_name=schtasks.exe OR Processes.process_name=powershell.exe) by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where (process_name="schtasks.exe" AND match(process,"(?i)/create") AND match(process,"(?i)(update|logioptions|logitech)")) OR match(process,"(?i)(ConsoleHost_history\.txt|Clear-History|Remove-Item.*PSReadLine)") | `security_content_ctime(firstTime)` | table firstTime dest user process_name process parent_process_name count
```

**Defender KQL:**
```kql
let taskcreate = DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("update","Update","LogiOptions","Logitech")
| where InitiatingProcessFileName in~ ("powershell.exe","pythonw.exe","cmd.exe","rundll32.exe")
| project Timestamp, DeviceName, AccountName, Kind="HiddenUpdateTask", ProcessCommandLine, InitiatingProcessFileName;
let histwipe = DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName =~ "ConsoleHost_history.txt"
| where ActionType in ("FileDeleted","FileModified")
| where InitiatingProcessFileName !in~ ("powershell.exe","pwsh.exe","explorer.exe")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Kind="PSHistoryWipe", ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName;
union taskcreate, histwipe
| order by Timestamp desc
```

### Temp-resident Python loader contacting public blockchain RPC / Web3 endpoints (EtherHiding)

`UC_13_18` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime from datamodel=Endpoint.Processes where (Processes.process_name=pythonw.exe OR Processes.process_name=python.exe) by Processes.dest Processes.user Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | where match(process_path,"(?i)\\AppData\\Local") | join type=inner dest [ | tstats `security_content_summariesonly` count as conns from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="*infura.io*" OR All_Traffic.dest="*bsc-dataseed*" OR All_Traffic.dest="*binance.org*" OR All_Traffic.dest="*publicnode.com*" OR All_Traffic.dest="*ankr.com*" OR All_Traffic.dest="*cloudflare-eth.com*" OR All_Traffic.dest="*llamarpc.com*" OR All_Traffic.dest="*drpc.org*") by All_Traffic.src | `drop_dm_object_name(All_Traffic)` | rename src as dest ] | table firstTime dest user process conns
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("pythonw.exe","python.exe")
| where InitiatingProcessFolderPath has @"\AppData\Local"
| where RemoteUrl has_any ("infura.io","bsc-dataseed","binance.org","publicnode.com","ankr.com","cloudflare-eth.com","llamarpc.com","drpc.org","blockpi.network","nodereal.io","blastapi.io","1rpc.io")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Endpoint connections to ACR Stealer / ClickFix campaign payload and C2 domains

`UC_13_19` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="*creativecommunityinfo.art*" OR All_Traffic.dest="*enhanceblabber.cc*" OR All_Traffic.dest="*deep-harborio.com*" OR All_Traffic.dest="*auramatrixa.com*" OR All_Traffic.dest="*zealpraxis.com*" OR All_Traffic.dest="*prism-vertex.com*" OR All_Traffic.dest="*prism-matrixs.com*" OR All_Traffic.dest="*proton-network.com*" OR All_Traffic.dest="*cpppemwjewjoiwejow.sale*" OR All_Traffic.dest="*apigrokcloud.icu*" OR All_Traffic.dest="*fairpoint29.com*" OR All_Traffic.dest="*primemetricsa.com*" OR All_Traffic.dest="*dialectosphere.in.net*" OR All_Traffic.dest="*claude-desktop.gitlab.io*") by All_Traffic.src All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | table firstTime lastTime src dest app count
```

**Defender KQL:**
```kql
let iocDomains = dynamic(["creativecommunityinfo.art","enhanceblabber.cc","deep-harborio.com","auramatrixa.com","zealpraxis.com","prism-vertex.com","prism-matrixs.com","proton-network.com","looksta.icu","quirksturdy.icu","strainedeasily.icu","cpppemwjewjoiwejow.sale","wifihot.icu","filloco.icu","raidher.icu","apigrokcloud.icu","fairpoint29.com","primemetricsa.com","sphere-api.dialectosphere.in.net","claude-desktop.gitlab.io"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (iocDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
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

### Article-specific behavioural hunt — ACR Stealer Uses ClickFix Lures to Steal Browser Tokens and Microsoft 365 Files

`UC_13_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — ACR Stealer Uses ClickFix Lures to Steal Browser Tokens and Microsoft 365 Files ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("conhost.exe","pythonw.exe") OR Processes.process_path="*C:\Windows\system32\rundll32.exe*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Windows\system32\rundll32.exe*" OR Filesystem.file_name IN ("conhost.exe","pythonw.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — ACR Stealer Uses ClickFix Lures to Steal Browser Tokens and Microsoft 365 Files
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("conhost.exe", "pythonw.exe") or FolderPath has_any ("C:\Windows\system32\rundll32.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Windows\system32\rundll32.exe") or FileName in~ ("conhost.exe", "pythonw.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `creativecommunityinfo.art`, `enhanceblabber.cc`, `deep-harborio.com`, `auramatrixa.com`, `zealpraxis.com`, `prism-vertex.com`, `prism-matrixs.com`, `proton-network.com` _(+12 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `70b5ecc110e074dbca92932c0e840ea3492ea0a43c3f215b71392c12b02213b2`, `a14c3ecf5eb3d2543358482e43dc765dbf9ee7a4bec7571f5ecb8829ca719692`, `47fa746422f1bf6b7712dc6803378e6a995488007193a7441d790f70d204728f`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 20 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
