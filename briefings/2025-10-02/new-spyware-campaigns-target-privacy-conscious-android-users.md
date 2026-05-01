# [CRIT] New spyware campaigns target privacy-conscious Android users in the UAE

**Source:** ESET WeLiveSecurity
**Published:** 2025-10-02
**Article:** https://www.welivesecurity.com/en/eset-research/new-spyware-campaigns-target-privacy-conscious-android-users-uae/

## Threat Profile

New spyware campaigns target privacy-conscious Android users in the UAE 
ESET Research
New spyware campaigns target privacy-conscious Android users in the UAE ESET researchers have discovered campaigns distributing spyware disguised as Android Signal and ToTok apps, targeting users in the United Arab Emirates
Lukas Stefanko 
02 Oct 2025 
 •  
, 
15 min. read 
ESET researchers have uncovered two Android spyware campaigns targeting individuals interested in secure communication apps, namely Signal…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `86.105.18.13`
- **IPv4 (defanged):** `185.7.219.77`
- **IPv4 (defanged):** `152.89.29.73`
- **IPv4 (defanged):** `5.42.221.106`
- **IPv4 (defanged):** `152.89.29.78`
- **IPv4 (defanged):** `185.140.210.66`
- **IPv4 (defanged):** `176.123.7.83`
- **IPv4 (defanged):** `185.27.134.222`
- **IPv4 (defanged):** `185.225.114.70`
- **IPv4 (defanged):** `94.156.128.159`
- **IPv4 (defanged):** `94.156.175.105`
- **IPv4 (defanged):** `103.214.4.135`
- **Domain (defanged):** `signal.ct.ws`
- **Domain (defanged):** `encryption-plug-in-signal.com-ae.net`
- **Domain (defanged):** `totok-pro.io`
- **Domain (defanged):** `store.appupdate.ai`
- **Domain (defanged):** `spiralkey.co`
- **Domain (defanged):** `noblico.net`
- **Domain (defanged):** `ai-messenger.co`
- **Domain (defanged):** `sion.ai`
- **Domain (defanged):** `totokupdate.ai`
- **Domain (defanged):** `app-totok.io`
- **Domain (defanged):** `sgnlapp.info`
- **Domain (defanged):** `ae.net`
- **Domain (defanged):** `totokapp.info`
- **SHA1:** `DE90F6899EEC315F4ED05C2AA052D4FE8B71125A`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1053.005** — Scheduled Task
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1583.001** — Acquire Infrastructure: Domains
- **T1437.001** — Application Layer Protocol: Web Protocols (Mobile)
- **T1407** — Download New Code at Runtime
- **T1105** — Ingress Tool Transfer
- **T1660** — Phishing (Mobile)
- **T1456** — Drive-by Compromise
- **T1404** — Exploitation for Privilege Escalation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ProSpy/ToSpy Android spyware C2 & distribution infrastructure callout (UAE campaign)

`UC_336_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as answer from datamodel=Network_Resolution where DNS.query IN ("signal.ct.ws","encryption-plug-in-signal.com-ae.net","totok-pro.io","store.appupdate.ai","spiralkey.co","noblico.net","ai-messenger.co","sion.ai") by DNS.query DNS.src DNS.dest | `drop_dm_object_name(DNS)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.url) as url from datamodel=Web where Web.url IN ("*signal.ct.ws*","*encryption-plug-in-signal.com-ae.net*","*totok-pro.io*","*store.appupdate.ai*","*spiralkey.co*","*noblico.net*","*ai-messenger.co*","*sion.ai*") OR Web.dest IN ("86.105.18.13","185.7.219.77","152.89.29.73","5.42.221.106","152.89.29.78","185.140.210.66","176.123.7.83","185.27.134.222") by Web.src Web.dest Web.url | `drop_dm_object_name(Web)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let prospy_tospy_domains = dynamic(["signal.ct.ws","encryption-plug-in-signal.com-ae.net","totok-pro.io","store.appupdate.ai","spiralkey.co","noblico.net","ai-messenger.co","sion.ai"]);
let prospy_tospy_ips = dynamic(["86.105.18.13","185.7.219.77","152.89.29.73","5.42.221.106","152.89.29.78","185.140.210.66","176.123.7.83","185.27.134.222"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (prospy_tospy_domains)
   or RemoteIP in (prospy_tospy_ips)
   or tostring(parse_url(RemoteUrl).Host) in~ (prospy_tospy_domains)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, ActionType, ReportId
| union (
  DeviceEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has_any (prospy_tospy_domains) or RemoteIP in (prospy_tospy_ips)
  | project Timestamp, DeviceName, DeviceId, ActionType, RemoteUrl, RemoteIP, ReportId
)
```

### [LLM] ToSpy hardcoded update channel: GET /totok_update/totokversion.php or totok_pro.apk

`UC_336_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.user_agent) as user_agent values(Web.http_method) as method values(Web.url) as url values(Web.dest) as dest from datamodel=Web where (Web.url="*spiralkey.co/totok_update/totokversion.php*" OR Web.url="*spiralkey.co/totok_update/totok_pro.apk*" OR (Web.url="*/totok_update/totokversion.php" OR Web.url="*/totok_update/totok_pro.apk")) by Web.src Web.site Web.url | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(60d)
| where RemoteUrl has "/totok_update/totokversion.php"
     or RemoteUrl has "/totok_update/totok_pro.apk"
     or (RemoteUrl has "spiralkey.co" and RemoteUrl has "totok")
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType, ReportId
```

### [LLM] Trojanised ToTok / Signal Encryption Plugin APK download (ProSpy/ToSpy filename patterns)

`UC_336_9` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.user_agent) as ua values(Web.http_method) as method values(Web.site) as site values(Web.url) as url values(Web.dest) as dest from datamodel=Web where (Web.url="*.apk" OR Web.http_content_type="application/vnd.android.package-archive") AND (Web.url="*totok_pro_release_*" OR Web.url="*totok_pro.apk" OR Web.url="*v1_8_*_totok.apk" OR Web.url="*totok_v1.8.*.apk" OR Web.url="*totok_Version_1_*_*.apk" OR Web.url="*totok_V1.*.apk" OR Web.url="*signal*encryption*plugin*.apk" OR Web.url="*ToTokPro*.apk") AND NOT (Web.site IN ("play.google.com","galaxystore.samsung.com","appgallery.huawei.com","totok.ai")) by Web.src Web.site Web.url Web.dest | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let suspicious_apk_patterns = dynamic(["totok_pro_release_","totok_pro.apk","_totok.apk","totok_v1.","totok_version_1_","totok_v1.9","signal-encryption-plug","signal_encryption_plug","totokpro"]);
let legit_stores = dynamic(["play.google.com","galaxystore.samsung.com","appgallery.huawei.com","totok.ai","signal.org"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl endswith ".apk"
| extend host = tolower(tostring(parse_url(RemoteUrl).Host))
| extend lurl = tolower(RemoteUrl)
| where lurl has_any (suspicious_apk_patterns)
| where not(host in~ (legit_stores))
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, RemoteUrl, RemoteIP, ActionType, ReportId
| union (
  EmailUrlInfo
  | where Timestamp > ago(30d)
  | extend lurl = tolower(Url)
  | where lurl endswith ".apk" and lurl has_any (suspicious_apk_patterns)
  | project Timestamp, NetworkMessageId, Url, UrlDomain, ReportId
)
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
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `86.105.18.13`, `185.7.219.77`, `152.89.29.73`, `5.42.221.106`, `152.89.29.78`, `185.140.210.66`, `176.123.7.83`, `185.27.134.222` _(+17 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `DE90F6899EEC315F4ED05C2AA052D4FE8B71125A`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 10 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
