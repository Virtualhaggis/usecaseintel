# [HIGH] 28 Fake Call History Apps on Google Play with 7.3M+ Downloads Trick Users to Steal Payments

**Source:** Cyber Security News
**Published:** 2026-05-07
**Article:** https://cybersecuritynews.com/28-fake-call-history-apps-on-google-play-with-7-3m-downloads/

## Threat Profile

Home Cyber Security News 
28 Fake Call History Apps on Google Play with 7.3M+ Downloads Trick Users to Steal Payments 
By Tushar Subhra Dutta 
May 7, 2026 
A new wave of fraudulent Android apps quietly racked up millions of downloads on Google Play before being taken down. These apps, now tracked under the name CallPhantom, promised users something irresistible: the ability to look up the call history of any phone number . What they actually delivered was nothing more than fake data and a very r…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `34.120.160.131`
- **IPv4 (defanged):** `34.120.206.254`
- **Domain (defanged):** `call-history-7cda4-default-rtdb.firebaseio.com`
- **Domain (defanged):** `call-history-ecc1e-default-rtdb.firebaseio.com`
- **Domain (defanged):** `ch-ap-4-default-rtdb.firebaseio.com`
- **Domain (defanged):** `chh1-ac0a3-default-rtdb.firebaseio.com`
- **SHA1:** `799AA5127CA54239D3D4A14367DB3B712012CF14`
- **SHA1:** `56A4FD71D1E4BBA2C5C240BE0D794DCFF709D9EB`
- **SHA1:** `EC5E470753E76614CD28ECF6A3591F08770B7215`
- **SHA1:** `77C8B7BEC79E7D9AE0D0C02DEC4E9AC510429AD8`
- **SHA1:** `9484EFD4C19969F57AFB0C21E6E1A4249C209305`
- **SHA1:** `CE97CA7FEECDCAFC6B8E9BD83A370DFA5C336C0A`
- **SHA1:** `FC3BA2EDAC0BB9801F8535E36F0BCC49ADA5FA5A`
- **SHA1:** `B7B80FA34A41E3259E377C0D843643FF736803B8`
- **SHA1:** `F0A8EBD7C4179636BE752ECCFC6BD9E4CD5C7F2C`
- **SHA1:** `D021E7A0CF45EECC7EE8F57149138725DC77DC9A`
- **SHA1:** `04D2221967FFC4312AFDC9B06A0B923BF3579E93`
- **SHA1:** `CB31ED027FADBFA3BFFDBC8A84EE1A48A0B7C11D`
- **SHA1:** `C840A85B5FBAF1ED3E0F18A10A6520B337A94D4C`
- **SHA1:** `BB6260CA856C37885BF9E952CA3D7E95398DDABF`
- **SHA1:** `55D46813047E98879901FD2416A23ACF8D8828F5`
- **SHA1:** `E23D3905443CDBF4F1B9CA84A6FF250B6D89E093`
- **SHA1:** `89ECEC01CCB15FCDD2F64E07D0E876A9E79DD3CE`
- **SHA1:** `8EC557302145B40FE0898105752FFF5E357D7AC9`
- **SHA1:** `6F72FF58A67EF7AAA79CE2342012326C7B46429D`
- **SHA1:** `28D3F36BD43D48F02C5058EDD1509E4488112154`
- **SHA1:** `47CEE9DED41B953A84FC9F6ED556EC3AF5BD9345`
- **SHA1:** `9199A376B433F888AFE962C9BBD991622E8D39F9`
- **SHA1:** `053A6A723FA2BFDA8A1B113E8A98DD04C6EEF72A`
- **SHA1:** `4B537A7152179BBA19D63C9EF287F1AC366AB5CB`
- **SHA1:** `87F6B2DB155192692BAD1F26F6AEBB04DBF23AAD`
- **SHA1:** `583D0E7113795C7D68686D37CE7A41535CF56960`
- **SHA1:** `45D04E06D8B329A01E680539D798DD3AE68904DA`
- **SHA1:** `34393950A950F5651F3F7811B815B5A21F84A84B`

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
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1437.001** — Application Layer Protocol: Web Protocols (Mobile)
- **T1660** — Phishing (Mobile)
- **T1655.001** — Masquerading: Match Legitimate Name or Location (Mobile)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] CallPhantom Android scam — Firebase RTDB C2 / payment-URL beacon

`UC_15_11` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest) as dest values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("call-history-7cda4-default-rtdb.firebaseio.com","call-history-ecc1e-default-rtdb.firebaseio.com","ch-ap-4-default-rtdb.firebaseio.com","chh1-ac0a3-default-rtdb.firebaseio.com") OR All_Traffic.url IN ("*call-history-7cda4-default-rtdb.firebaseio.com*","*call-history-ecc1e-default-rtdb.firebaseio.com*","*ch-ap-4-default-rtdb.firebaseio.com*","*chh1-ac0a3-default-rtdb.firebaseio.com*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port host | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats `summariesonly` count from datamodel=Web.Web where Web.url IN ("*call-history-7cda4-default-rtdb.firebaseio.com*","*call-history-ecc1e-default-rtdb.firebaseio.com*","*ch-ap-4-default-rtdb.firebaseio.com*","*chh1-ac0a3-default-rtdb.firebaseio.com*") by Web.src Web.user Web.url Web.dest | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
// CallPhantom Firebase RTDB beacons — DNS + Network egress
let CallPhantomDomains = dynamic([
    "call-history-7cda4-default-rtdb.firebaseio.com",
    "call-history-ecc1e-default-rtdb.firebaseio.com",
    "ch-ap-4-default-rtdb.firebaseio.com",
    "chh1-ac0a3-default-rtdb.firebaseio.com"
]);
union isfuzzy=true
    ( DeviceNetworkEvents
        | where Timestamp > ago(30d)
        | where RemoteUrl in~ (CallPhantomDomains)
            or RemoteUrl has_any (CallPhantomDomains)
        | project Timestamp, DeviceName, DeviceId, ActionType,
                  RemoteUrl, RemoteIP, RemotePort, Protocol,
                  InitiatingProcessFileName, InitiatingProcessCommandLine,
                  Source = "DeviceNetworkEvents" ),
    ( DeviceEvents
        | where Timestamp > ago(30d)
        | where ActionType == "DnsQueryResponse"
        | extend QName = tostring(parse_json(AdditionalFields).QueryName)
        | where QName in~ (CallPhantomDomains)
        | project Timestamp, DeviceName, DeviceId, ActionType,
                  QName, InitiatingProcessFileName, InitiatingProcessCommandLine,
                  Source = "DeviceEvents:DnsQueryResponse" )
| order by Timestamp desc
```

### [LLM] CallPhantom APK SHA1 sweep across endpoint and proxy file telemetry

`UC_15_12` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name values(Filesystem.dest) as dest from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("799AA5127CA54239D3D4A14367DB3B712012CF14","56A4FD71D1E4BBA2C5C240BE0D794DCFF709D9EB","EC5E470753E76614CD28ECF6A3591F08770B7215","77C8B7BEC79E7D9AE0D0C02DEC4E9AC510429AD8","9484EFD4C19969F57AFB0C21E6E1A4249C209305","CE97CA7FEECDCAFC6B8E9BD83A370DFA5C336C0A","FC3BA2EDAC0BB9801F8535E36F0BCC49ADA5FA5A","B7B80FA34A41E3259E377C0D843643FF736803B8","F0A8EBD7C4179636BE752ECCFC6BD9E4CD5C7F2C","D021E7A0CF45EECC7EE8F57149138725DC77DC9A","04D2221967FFC4312AFDC9B06A0B923BF3579E93","CB31ED027FADBFA3BFFDBC8A84EE1A48A0B7C11D","C840A85B5FBAF1ED3E0F18A10A6520B337A94D4C","BB6260CA856C37885BF9E952CA3D7E95398DDABF","55D46813047E98879901FD2416A23ACF8D8828F5","E23D3905443CDBF4F1B9CA84A6FF250B6D89E093","89ECEC01CCB15FCDD2F64E07D0E876A9E79DD3CE","8EC557302145B40FE0898105752FFF5E357D7AC9","6F72FF58A67EF7AAA79CE2342012326C7B46429D","28D3F36BD43D48F02C5058EDD1509E4488112154","47CEE9DED41B953A84FC9F6ED556EC3AF5BD9345","9199A376B433F888AFE962C9BBD991622E8D39F9","053A6A723FA2BFDA8A1B113E8A98DD04C6EEF72A","4B537A7152179BBA19D63C9EF287F1AC366AB5CB","87F6B2DB155192692BAD1F26F6AEBB04DBF23AAD","583D0E7113795C7D68686D37CE7A41535CF56960","45D04E06D8B329A01E680539D798DD3AE68904DA","34393950A950F5651F3F7811B815B5A21F84A84B") by host Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// CallPhantom APK SHA1 IOC sweep
let CallPhantomSHA1 = dynamic([
    "799AA5127CA54239D3D4A14367DB3B712012CF14",
    "56A4FD71D1E4BBA2C5C240BE0D794DCFF709D9EB",
    "EC5E470753E76614CD28ECF6A3591F08770B7215",
    "77C8B7BEC79E7D9AE0D0C02DEC4E9AC510429AD8",
    "9484EFD4C19969F57AFB0C21E6E1A4249C209305",
    "CE97CA7FEECDCAFC6B8E9BD83A370DFA5C336C0A",
    "FC3BA2EDAC0BB9801F8535E36F0BCC49ADA5FA5A",
    "B7B80FA34A41E3259E377C0D843643FF736803B8",
    "F0A8EBD7C4179636BE752ECCFC6BD9E4CD5C7F2C",
    "D021E7A0CF45EECC7EE8F57149138725DC77DC9A",
    "04D2221967FFC4312AFDC9B06A0B923BF3579E93",
    "CB31ED027FADBFA3BFFDBC8A84EE1A48A0B7C11D",
    "C840A85B5FBAF1ED3E0F18A10A6520B337A94D4C",
    "BB6260CA856C37885BF9E952CA3D7E95398DDABF",
    "55D46813047E98879901FD2416A23ACF8D8828F5",
    "E23D3905443CDBF4F1B9CA84A6FF250B6D89E093",
    "89ECEC01CCB15FCDD2F64E07D0E876A9E79DD3CE",
    "8EC557302145B40FE0898105752FFF5E357D7AC9",
    "6F72FF58A67EF7AAA79CE2342012326C7B46429D",
    "28D3F36BD43D48F02C5058EDD1509E4488112154",
    "47CEE9DED41B953A84FC9F6ED556EC3AF5BD9345",
    "9199A376B433F888AFE962C9BBD991622E8D39F9",
    "053A6A723FA2BFDA8A1B113E8A98DD04C6EEF72A",
    "4B537A7152179BBA19D63C9EF287F1AC366AB5CB",
    "87F6B2DB155192692BAD1F26F6AEBB04DBF23AAD",
    "583D0E7113795C7D68686D37CE7A41535CF56960",
    "45D04E06D8B329A01E680539D798DD3AE68904DA",
    "34393950A950F5651F3F7811B815B5A21F84A84B"
]);
union isfuzzy=true
    ( DeviceFileEvents
        | where Timestamp > ago(30d)
        | where SHA1 in~ (CallPhantomSHA1)
        | project Timestamp, DeviceName, ActionType, FileName, FolderPath,
                  SHA1, FileOriginUrl, FileOriginReferrerUrl,
                  InitiatingProcessFileName, InitiatingProcessAccountName,
                  Source = "DeviceFileEvents" ),
    ( DeviceProcessEvents
        | where Timestamp > ago(30d)
        | where SHA1 in~ (CallPhantomSHA1)
        | project Timestamp, DeviceName, FileName, FolderPath, SHA1,
                  ProcessCommandLine, AccountName,
                  Source = "DeviceProcessEvents" )
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

### Article-specific behavioural hunt — 28 Fake Call History Apps on Google Play with 7.3M+ Downloads Trick Users to Ste

`UC_15_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — 28 Fake Call History Apps on Google Play with 7.3M+ Downloads Trick Users to Ste ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — 28 Fake Call History Apps on Google Play with 7.3M+ Downloads Trick Users to Ste
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `34.120.160.131`, `34.120.206.254`, `call-history-7cda4-default-rtdb.firebaseio.com`, `call-history-ecc1e-default-rtdb.firebaseio.com`, `ch-ap-4-default-rtdb.firebaseio.com`, `chh1-ac0a3-default-rtdb.firebaseio.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `799AA5127CA54239D3D4A14367DB3B712012CF14`, `56A4FD71D1E4BBA2C5C240BE0D794DCFF709D9EB`, `EC5E470753E76614CD28ECF6A3591F08770B7215`, `77C8B7BEC79E7D9AE0D0C02DEC4E9AC510429AD8`, `9484EFD4C19969F57AFB0C21E6E1A4249C209305`, `CE97CA7FEECDCAFC6B8E9BD83A370DFA5C336C0A`, `FC3BA2EDAC0BB9801F8535E36F0BCC49ADA5FA5A`, `B7B80FA34A41E3259E377C0D843643FF736803B8` _(+20 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 13 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
