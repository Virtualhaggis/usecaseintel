# [HIGH] Gone Phishin': npm Packages Serving Custom Credential Harvesting Pages

**Source:** Aikido
**Published:** 2026-01-23
**Article:** https://www.aikido.dev/blog/npm-supply-chain-phishing-campaigns

## Threat Profile

Blog Vulnerabilities & Threats Gone Phishin': npm Packages Serving Custom Credential Harvesting Pages Gone Phishin': npm Packages Serving Custom Credential Harvesting Pages Written by Charlie Eriksen Published on: Jan 23, 2026 At 2026-01-20 18:03 UTC, our system started alerting us to a new npm package called flockiali . Within 26 minutes, the attacker published four versions. Two days later, they went on a publishing spree: opresc , prndn , oprnm , and operni . By the time we looked closer, we'…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `163.123.236.118`
- **IPv4 (defanged):** `34.120.54.55`
- **Domain (defanged):** `login.siemens-energy.icu`
- **Domain (defanged):** `login.siemensergy.icu`
- **Domain (defanged):** `oprsys.deno.dev`
- **SHA256:** `3ceb182fb32a8fb0f0fcf056d6ab8de1cf6e789053f1aadc98ba315ae9a96f0c`
- **SHA256:** `fdb6c79a8d01b528698c53ebd5030f875242e6af93f6ae799dee7f66b452bf3e`
- **SHA256:** `4631584783d84758ae58bc717b08ac67d99dee30985db18b9d2b08df8721348e`
- **SHA256:** `211f88a55e8fe9254f75c358c42bb7e78e014b862de7ea6e8b80ed1f78d13add`
- **SHA256:** `7d7f795ac1fcb5623731a50999f518877fd423a5a98219d0f495c488564a1554`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1566.002** — Phishing: Spearphishing Link
- **T1608.001** — Stage Capabilities: Upload Malware
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1056.003** — Input Capture: Web Portal Capture
- **T1583.001** — Acquire Infrastructure: Domains
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Inbound email or click on jsDelivr URL to flockiali/opresc/prndn/oprnm/operni npm phishing kit

`UC_474_11` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*cdn.jsdelivr.net/npm/flockiali*" OR Web.url="*cdn.jsdelivr.net/npm/opresc*" OR Web.url="*cdn.jsdelivr.net/npm/prndn*" OR Web.url="*cdn.jsdelivr.net/npm/oprnm*" OR Web.url="*cdn.jsdelivr.net/npm/operni*") by Web.src Web.user Web.dest Web.url Web.http_user_agent Web.http_referrer
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let MaliciousJsDelivrPaths = dynamic([
    "cdn.jsdelivr.net/npm/flockiali",
    "cdn.jsdelivr.net/npm/opresc",
    "cdn.jsdelivr.net/npm/prndn",
    "cdn.jsdelivr.net/npm/oprnm",
    "cdn.jsdelivr.net/npm/operni"
]);
let EmailHits = EmailUrlInfo
    | where Timestamp > ago(30d)
    | where Url has_any (MaliciousJsDelivrPaths)
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(30d)
        | where EmailDirection == "Inbound"
      ) on NetworkMessageId
    | project Timestamp, Source="EmailUrlInfo", AccountUpn=RecipientEmailAddress, Url, SenderFromAddress, Subject, NetworkMessageId, DeliveryAction;
let ClickHits = UrlClickEvents
    | where Timestamp > ago(30d)
    | where Url has_any (MaliciousJsDelivrPaths)
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | project Timestamp, Source="UrlClickEvents", AccountUpn, Url, ActionType, IPAddress, NetworkMessageId, SenderFromAddress="", Subject="", DeliveryAction="";
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (MaliciousJsDelivrPaths)
    | project Timestamp, Source="DeviceNetworkEvents", AccountUpn=InitiatingProcessAccountUpn, Url=RemoteUrl, SenderFromAddress="", Subject="", NetworkMessageId="", DeliveryAction="";
union EmailHits, ClickHits, NetHits
| order by Timestamp desc
```

### [LLM] Egress to Siemens Energy typosquat C2 (login.siemens-energy.icu / oprsys.deno.dev / 163.123.236.118)

`UC_474_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.dest IN ("163.123.236.118", "34.120.54.55") OR All_Traffic.dest_host="*siemens-energy.icu" OR All_Traffic.dest_host="*siemensergy.icu" OR All_Traffic.dest_host="*oprsys.deno.dev") by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.user All_Traffic.app All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where (Network_Resolution.DNS.query="*siemens-energy.icu" OR Network_Resolution.DNS.query="*siemensergy.icu" OR Network_Resolution.DNS.query="*oprsys.deno.dev") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` ]
```

**Defender KQL:**
```kql
let C2Hosts = dynamic([
    "login.siemens-energy.icu", "siemens-energy.icu",
    "login.siemensergy.icu", "siemensergy.icu",
    "oprsys.deno.dev"
]);
let C2IPs = dynamic(["163.123.236.118", "34.120.54.55"]);
let PhishingURIPath = "/DIVzTaSF";
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP in (C2IPs)
        or RemoteUrl has_any (C2Hosts)
    | project Timestamp, Source="DeviceNetworkEvents", DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort;
let DnsHits = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Query = tostring(parse_json(AdditionalFields).QueryName)
    | where Query has_any (C2Hosts)
    | project Timestamp, Source="DnsQueryResponse", DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine="", RemoteIP="", RemoteUrl=Query, RemotePort=int(null);
union NetHits, DnsHits
| extend HitFullPhishURL = RemoteUrl has PhishingURIPath
| order by Timestamp desc
```

### [LLM] npm phishing payload SHA256 observed on disk (flockiali/opresc/prndn/oprnm/operni)

`UC_474_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("3ceb182fb32a8fb0f0fcf056d6ab8de1cf6e789053f1aadc98ba315ae9a96f0c", "fdb6c79a8d01b528698c53ebd5030f875242e6af93f6ae799dee7f66b452bf3e", "4631584783d84758ae58bc717b08ac67d99dee30985db18b9d2b08df8721348e", "211f88a55e8fe9254f75c358c42bb7e78e014b862de7ea6e8b80ed1f78d13add", "7d7f795ac1fcb5623731a50999f518877fd423a5a98219d0f495c488564a1554") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let MaliciousHashes = dynamic([
    "3ceb182fb32a8fb0f0fcf056d6ab8de1cf6e789053f1aadc98ba315ae9a96f0c", // flockiali 1.2.6 — Ingeteam target
    "fdb6c79a8d01b528698c53ebd5030f875242e6af93f6ae799dee7f66b452bf3e", // flockiali 1.2.5 — CQFD Composites target
    "4631584783d84758ae58bc717b08ac67d99dee30985db18b9d2b08df8721348e", // opresc — Emagine UAE
    "211f88a55e8fe9254f75c358c42bb7e78e014b862de7ea6e8b80ed1f78d13add", // prndn/oprnm — Amixon
    "7d7f795ac1fcb5623731a50999f518877fd423a5a98219d0f495c488564a1554"  // operni 1.2.7 — CMC America
]);
let FileHits = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (MaliciousHashes)
    | project Timestamp, Source="DeviceFileEvents", DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName, FileOriginUrl, FileOriginReferrerUrl;
let ImgHits = DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (MaliciousHashes)
    | project Timestamp, Source="DeviceImageLoadEvents", DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName=InitiatingProcessAccountName, FileOriginUrl="", FileOriginReferrerUrl="";
union FileHits, ImgHits
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

### Article-specific behavioural hunt — Gone Phishin': npm Packages Serving Custom Credential Harvesting Pages

`UC_474_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Gone Phishin': npm Packages Serving Custom Credential Harvesting Pages ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("min.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("min.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Gone Phishin': npm Packages Serving Custom Credential Harvesting Pages
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("min.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("min.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `163.123.236.118`, `34.120.54.55`, `login.siemens-energy.icu`, `login.siemensergy.icu`, `oprsys.deno.dev`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `3ceb182fb32a8fb0f0fcf056d6ab8de1cf6e789053f1aadc98ba315ae9a96f0c`, `fdb6c79a8d01b528698c53ebd5030f875242e6af93f6ae799dee7f66b452bf3e`, `4631584783d84758ae58bc717b08ac67d99dee30985db18b9d2b08df8721348e`, `211f88a55e8fe9254f75c358c42bb7e78e014b862de7ea6e8b80ed1f78d13add`, `7d7f795ac1fcb5623731a50999f518877fd423a5a98219d0f495c488564a1554`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 14 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
