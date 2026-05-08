# [HIGH] Hackers Abuse Signed Logitech Installer to Deploy TCLBANKER Banking Trojan

**Source:** Cyber Security News
**Published:** 2026-05-08
**Article:** https://cybersecuritynews.com/hackers-abuse-signed-logitech-installer-tclbanker/

## Threat Profile

Home Cyber Security News 
Hackers Abuse Signed Logitech Installer to Deploy TCLBANKER Banking Trojan 
By Tushar Subhra Dutta 
May 8, 2026 




A new banking trojan known as TCLBANKER has been quietly making rounds, and its delivery method is as clever as it is concerning. Attackers are using a trojanized version of a legitimate, digitally signed installer to slip malware onto victims’ machines without raising immediate suspicion. 
The campaign, tracked as REF3076, bundles a malicious MSI ins…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `campanha1-api.ef971a42.workers`
- **Domain (defanged):** `mxtestacionamentos.com`
- **Domain (defanged):** `documents.ef971a42.workers.dev`
- **Domain (defanged):** `arquivos-omie.com`
- **Domain (defanged):** `documentos-online.com`
- **Domain (defanged):** `afonsoferragista.com`
- **Domain (defanged):** `doccompartilhe.com`
- **Domain (defanged):** `recebamais.com`
- **SHA256:** `701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626`
- **SHA256:** `8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059`
- **SHA256:** `668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40`
- **SHA256:** `63beb7372098c03baab77e0dfc8e5dca5e0a7420f382708a4df79bed2d900394`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1053.005** — Scheduled Task
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1218.007** — System Binary Proxy Execution: Msiexec
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090.002** — Proxy: External Proxy
- **T1568** — Dynamic Resolution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] TCLBANKER (REF3076) screen_retriever_plugin.dll DLL sideload by Logi AI Prompt Builder

`UC_2_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where (Filesystem.file_name="screen_retriever_plugin.dll" OR Filesystem.file_hash IN ("701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626","8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059","668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40")) by Filesystem.dest Filesystem.user | `drop_dm_object_name(Filesystem)` | where NOT match(file_path,"(?i)\\\\Program Files( \(x86\))?\\\\Logi AI Prompt Builder\\\\") OR file_hash IN ("701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626","8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059","668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// TCLBANKER REF3076 — screen_retriever_plugin.dll sideload
let TCLBankerHashes = dynamic([
    "701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626",
    "8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059",
    "668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40"]);
union isfuzzy=true
    ( DeviceImageLoadEvents
        | where Timestamp > ago(7d)
        | where FileName =~ "screen_retriever_plugin.dll" or SHA256 in (TCLBankerHashes)
        | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
                  EventKind="ImageLoad",
                  LoadedDll=FolderPath, LoadedSha256=SHA256,
                  LoadingProcess=InitiatingProcessFileName,
                  LoadingProcessPath=InitiatingProcessFolderPath,
                  LoadingProcessCmd=InitiatingProcessCommandLine,
                  LoadingProcessSigner=InitiatingProcessVersionInfoCompanyName ),
    ( DeviceFileEvents
        | where Timestamp > ago(7d)
        | where ActionType in ("FileCreated","FileRenamed","FileModified")
        | where FileName =~ "screen_retriever_plugin.dll" or SHA256 in (TCLBankerHashes)
        | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
                  EventKind="FileWrite",
                  LoadedDll=FolderPath, LoadedSha256=SHA256,
                  LoadingProcess=InitiatingProcessFileName,
                  LoadingProcessPath=InitiatingProcessFolderPath,
                  LoadingProcessCmd=InitiatingProcessCommandLine,
                  LoadingProcessSigner=InitiatingProcessVersionInfoCompanyName )
| order by Timestamp desc
```

### [LLM] TCLBANKER REF3076 C2 / phishing infrastructure egress (Cloudflare Workers + mxtestacionamentos)

`UC_2_11` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.url) as url from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="campanha1-api.ef971a42.workers.dev" OR All_Traffic.dest="documents.ef971a42.workers.dev" OR All_Traffic.dest="mxtestacionamentos.com" OR All_Traffic.dest="arquivos-omie.com" OR All_Traffic.dest="documentos-online.com" OR All_Traffic.dest="afonsoferragista.com" OR All_Traffic.dest="doccompartilhe.com" OR All_Traffic.dest="recebamais.com" OR All_Traffic.url IN ("*ef971a42.workers.dev*","*mxtestacionamentos.com*","*arquivos-omie.com*","*documentos-online.com*","*afonsoferragista.com*","*doccompartilhe.com*","*recebamais.com*")) by All_Traffic.src All_Traffic.dest All_Traffic.user | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// TCLBANKER REF3076 — egress to known C2 / phishing infrastructure
let TCLBankerDomains = dynamic([
    "campanha1-api.ef971a42.workers.dev",
    "documents.ef971a42.workers.dev",
    "mxtestacionamentos.com",
    "arquivos-omie.com",
    "documentos-online.com",
    "afonsoferragista.com",
    "doccompartilhe.com",
    "recebamais.com"]);
let TCLBankerSubstrings = dynamic([
    "ef971a42.workers.dev",
    "mxtestacionamentos.com",
    "arquivos-omie.com",
    "documentos-online.com",
    "afonsoferragista.com",
    "doccompartilhe.com",
    "recebamais.com"]);
union isfuzzy=true
    ( DeviceNetworkEvents
        | where Timestamp > ago(14d)
        | where ActionType in ("ConnectionSuccess","ConnectionAttempt","HttpConnectionInspected","ConnectionFound")
        | where tolower(RemoteUrl) in (TCLBankerDomains)
            or RemoteUrl has_any (TCLBankerSubstrings)
        | project Timestamp, DeviceName,
                  AccountName=InitiatingProcessAccountName,
                  Process=InitiatingProcessFileName,
                  ProcessPath=InitiatingProcessFolderPath,
                  ProcessCmd=InitiatingProcessCommandLine,
                  ProcessSha256=InitiatingProcessSHA256,
                  RemoteUrl, RemoteIP, RemotePort, ActionType ),
    ( DeviceEvents
        | where Timestamp > ago(14d)
        | where ActionType == "DnsQueryResponse"
        | extend Q = tolower(tostring(parse_json(AdditionalFields).QueryName))
        | where Q in (TCLBankerDomains) or Q has_any (TCLBankerSubstrings)
        | project Timestamp, DeviceName,
                  AccountName=InitiatingProcessAccountName,
                  Process=InitiatingProcessFileName,
                  ProcessPath=InitiatingProcessFolderPath,
                  ProcessCmd=InitiatingProcessCommandLine,
                  ProcessSha256=InitiatingProcessSHA256,
                  RemoteUrl=Q, RemoteIP="", RemotePort=int(0), ActionType="DnsQuery" )
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

### Article-specific behavioural hunt — Hackers Abuse Signed Logitech Installer to Deploy TCLBANKER Banking Trojan

`UC_2_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Abuse Signed Logitech Installer to Deploy TCLBANKER Banking Trojan ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("screen_retriever_plugin.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("screen_retriever_plugin.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Abuse Signed Logitech Installer to Deploy TCLBANKER Banking Trojan
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("screen_retriever_plugin.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("screen_retriever_plugin.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `campanha1-api.ef971a42.workers`, `mxtestacionamentos.com`, `documents.ef971a42.workers.dev`, `arquivos-omie.com`, `documentos-online.com`, `afonsoferragista.com`, `doccompartilhe.com`, `recebamais.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626`, `8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059`, `668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40`, `63beb7372098c03baab77e0dfc8e5dca5e0a7420f382708a4df79bed2d900394`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
