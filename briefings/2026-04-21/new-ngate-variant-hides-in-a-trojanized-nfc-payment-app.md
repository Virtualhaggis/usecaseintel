# [CRIT] New NGate variant hides in a trojanized NFC payment app

**Source:** ESET WeLiveSecurity
**Published:** 2026-04-21
**Article:** https://www.welivesecurity.com/en/eset-research/new-ngate-variant-hides-in-a-trojanized-nfc-payment-app/

## Threat Profile

New NGate variant hides in a trojanized NFC payment app 
ESET Research
New NGate variant hides in a trojanized NFC payment app ESET researchers discover another iteration of NGate malware, this time possibly developed with the assistance of AI
Lukas Stefanko 
21 Apr 2026 
 •  
, 
10 min. read 
ESET Research has discovered a new variant of the NGate malware family that abuses a legitimate Android application called HandyPay, instead of the previously leveraged NFCGate tool. The threat actors took…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `104.21.91.170`
- **IPv4 (defanged):** `108.165.230.223`
- **Domain (defanged):** `ao.online`

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
- **T1646** — Exfiltration Over C2 Channel
- **T1437.001** — Application Layer Protocol: Web Protocols
- **T1660** — Phishing
- **T1456** — Drive-By Compromise
- **T1417.002** — Input Capture: GUI Input Capture

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] NGate (HandyPay variant) PIN exfil egress to dedicated C&C 108.165.230.223 (BattleHost)

`UC_124_5` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src_ip) as src_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="108.165.230.223" by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.action | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _ngate_c2_ip = "108.165.230.223";
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == _ngate_c2_ip
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","HttpConnectionInspected")
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, ActionType, LocalIP, Protocol
| order by Timestamp desc
```

### [LLM] Access to NGate distribution domain protecaocartao[.]online (HandyPay trojan + APK delivery)

`UC_124_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as method values(Web.http_user_agent) as ua from datamodel=Web.Web where Web.url="*protecaocartao.online*" OR Web.dest="protecaocartao.online" OR Web.dest="104.21.91.170" by Web.src Web.user Web.dest | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as query values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where DNS.query="*protecaocartao.online*" by DNS.src | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) ]
```

**Defender KQL:**
```kql
let _ngate_domain = "protecaocartao.online";
let _ngate_distrib_ip = "104.21.91.170";
union isfuzzy=true
  (DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has _ngate_domain or RemoteIP == _ngate_distrib_ip
    | project Timestamp, Source="NetConn", DeviceName, DeviceId, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, ActionType, FileName=tostring(dynamic(null)), SHA1=tostring(dynamic(null)), FileOriginUrl=tostring(dynamic(null))),
  (DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
    | where QueryName has _ngate_domain
    | project Timestamp, Source="DNS", DeviceName, DeviceId, InitiatingProcessFileName, RemoteIP=tostring(dynamic(null)), RemoteUrl=QueryName, RemotePort=int(null), ActionType, FileName=tostring(dynamic(null)), SHA1=tostring(dynamic(null)), FileOriginUrl=tostring(dynamic(null))),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName endswith ".apk"
    | where FileOriginUrl has _ngate_domain or FileOriginIP == _ngate_distrib_ip
    | project Timestamp, Source="FileDrop", DeviceName, DeviceId, InitiatingProcessFileName, RemoteIP=FileOriginIP, RemoteUrl=FileOriginUrl, RemotePort=int(null), ActionType, FileName, SHA1, FileOriginUrl)
| order by Timestamp desc
```

### [LLM] Trojanized HandyPay / Proteção Cartão APK SHA-1 file drop on managed device

`UC_124_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("48a0de6a43fc6e49318ad6873ea63fe325200dbc","a4f793539480677241ef312150e9c02e324c0aa2","94af94ca818697e1d99123f69965b11ead9f010c") OR Filesystem.file_name IN ("PROTECAO_CARTAO.apk","Rio_de_Prêmios_Pagamento.apk")) by Filesystem.dest Filesystem.user Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _ngate_apk_sha1 = dynamic([
  "48a0de6a43fc6e49318ad6873ea63fe325200dbc",
  "a4f793539480677241ef312150e9c02e324c0aa2",
  "94af94ca818697e1d99123f69965b11ead9f010c"
]);
let _ngate_apk_names = dynamic(["PROTECAO_CARTAO.apk","Rio_de_Prêmios_Pagamento.apk","Rio_de_Premios_Pagamento.apk"]);
DeviceFileEvents
| where Timestamp > ago(60d)
| where (FileName endswith ".apk")
| where tolower(SHA1) in (_ngate_apk_sha1)
   or FileName in~ (_ngate_apk_names)
| project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA1, SHA256, FileSize, FileOriginUrl, FileOriginIP, InitiatingProcessFileName, InitiatingProcessAccountName
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `104.21.91.170`, `108.165.230.223`, `ao.online`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
