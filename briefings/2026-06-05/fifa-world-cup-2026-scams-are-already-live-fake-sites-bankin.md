# [HIGH] FIFA World Cup 2026 Scams Are Already Live: Fake Sites, Banking Malware, and Stolen Logins

**Source:** The Hacker News
**Published:** 2026-06-05
**Article:** https://thehackernews.com/2026/06/fifa-world-cup-2026-scams-are-already.html

## Threat Profile

FIFA World Cup 2026 Scams Are Already Live: Fake Sites, Banking Malware, and Stolen Logins 
 Swati Khandelwal  Jun 05, 2026 Online Security / Malware 
Security researchers and the FBI are warning that a wave of FIFA-themed fraud is already hitting World Cup 2026 fans, days before the June 11 kickoff.
Recent reports describe thousands of lookalike FIFA domains, banking malware hidden inside pirate streaming apps, and at least one operation that copies FIFA's login page well enough to take over …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `148.178.18.23`
- **IPv4 (defanged):** `148.178.18.60`
- **IPv4 (defanged):** `154.86.0.33`
- **IPv4 (defanged):** `207.56.1.93`
- **IPv4 (defanged):** `66.112.212.25`
- **IPv4 (defanged):** `148.178.16.48`
- **IPv4 (defanged):** `148.178.16.5`
- **IPv4 (defanged):** `104.225.235.49`
- **IPv4 (defanged):** `89.208.250.38`
- **IPv4 (defanged):** `65.49.223.138`
- **IPv4 (defanged):** `148.178.22.16`
- **IPv4 (defanged):** `85.121.242.41`
- **IPv4 (defanged):** `216.189.149.193`
- **IPv4 (defanged):** `137.220.224.67`
- **IPv4 (defanged):** `43.98.183.110`
- **Domain (defanged):** `fifa.bio`
- **Domain (defanged):** `fifa.center`
- **Domain (defanged):** `fifa.gold`
- **Domain (defanged):** `fifa.red`
- **Domain (defanged):** `fifa.sale`
- **Domain (defanged):** `fifa.shopping`
- **Domain (defanged):** `fifa.show`
- **Domain (defanged):** `fifa.ski`
- **Domain (defanged):** `fifa.black`
- **Domain (defanged):** `fifa.cafe`
- **Domain (defanged):** `fifa.fund`
- **Domain (defanged):** `fifa.market`
- **Domain (defanged):** `fifa.tax`
- **Domain (defanged):** `fifa.cash`
- **Domain (defanged):** `fifa.city`
- **Domain (defanged):** `fifa.house`
- **Domain (defanged):** `fifa-com.co`
- **Domain (defanged):** `fifa-com.com`
- **Domain (defanged):** `fifa-com.shop`
- **Domain (defanged):** `fifa-com.xyz`
- **Domain (defanged):** `fifa-com.vip`
- **Domain (defanged):** `www-fifa.com`
- **Domain (defanged):** `www-fifaworldcup.com`
- **Domain (defanged):** `wc26-fifa.com`
- **Domain (defanged):** `fifa-26-worldcup.com`
- **Domain (defanged):** `fifa-tickets.vip`
- **Domain (defanged):** `football-ticket.top`
- **Domain (defanged):** `football-ticket.shop`
- **Domain (defanged):** `mm-fifa.top`
- **Domain (defanged):** `pay.zfxupi.net`
- **SHA1:** `3b8bb7631b39f455d31544b55ba97b49ab1888c1`
- **SHA1:** `84ecdca915f1af822ccc8a04479f5179104f353c`
- **SHA1:** `9bd164dd3f50d196c7dff4f6c1b0f1345ac96d9a`

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
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1583.001** — Acquire Infrastructure: Domains
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1437.001** — Application Layer Protocol: Web Protocols (Mobile)
- **T1583.004** — Acquire Infrastructure: Server
- **T1660** — Phishing (Mobile)
- **T1626.001** — Abuse Elevation Control Mechanism: Device Administrator Permissions
- **T1656** — Impersonation
- **T1036.005** — Masquerading: Match Legitimate Resource Name or Location
- **T1608.005** — Stage Capabilities: Link Target

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GHOST STADIUM FIFA lookalike domain resolution (fifa.bio/.center/.gold/.red/.sale/.shopping/.show/.ski)

`UC_89_10` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Network_Resolution.DNS WHERE DNS.query IN ("fifa.bio","fifa.center","fifa.gold","fifa.red","fifa.sale","fifa.shopping","fifa.show","fifa.ski","*.fifa.bio","*.fifa.center","*.fifa.gold","*.fifa.red","*.fifa.sale","*.fifa.shopping","*.fifa.show","*.fifa.ski") BY DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let GhostStadiumDomains = dynamic(["fifa.bio","fifa.center","fifa.gold","fifa.red","fifa.sale","fifa.shopping","fifa.show","fifa.ski"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ConnectionSuccess","DnsConnectionInspected","InboundConnectionAccepted")
| extend HostPart = tolower(tostring(parse_url(RemoteUrl).Host))
| where isnotempty(RemoteUrl)
| where HostPart in (GhostStadiumDomains) or HostPart endswith ".fifa.bio" or HostPart endswith ".fifa.center" or HostPart endswith ".fifa.gold" or HostPart endswith ".fifa.red" or HostPart endswith ".fifa.sale" or HostPart endswith ".fifa.shopping" or HostPart endswith ".fifa.show" or HostPart endswith ".fifa.ski"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, HostPart
| order by Timestamp desc
```

### GHOST STADIUM phishing kit / Android trojan C2 IP egress (8 specific hosts)

`UC_89_11` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime sum(All_Traffic.bytes_out) as bytes_out sum(All_Traffic.bytes_in) as bytes_in FROM datamodel=Network_Traffic.All_Traffic WHERE All_Traffic.dest IN ("148.178.18.23","148.178.18.60","154.86.0.33","207.56.1.93","66.112.212.25","148.178.16.48","148.178.16.5","104.225.235.49") BY All_Traffic.src All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let GhostStadiumC2 = dynamic(["148.178.18.23","148.178.18.60","154.86.0.33","207.56.1.93","66.112.212.25","148.178.16.48","148.178.16.5","104.225.235.49"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in (GhostStadiumC2)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","InboundConnectionAccepted")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### Massiv / Perseus (Cerberus-derived) Android banking trojan APK hash on managed endpoint

`UC_89_12` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem WHERE (Filesystem.file_hash IN ("3b8bb7631b39f455d31544b55ba97b49ab1888c1","84ecdca915f1af822ccc8a04479f5179104f353c","9bd164dd3f50d196c7dff4f6c1b0f1345ac96d9a")) OR (Filesystem.file_name="*.apk" AND Filesystem.file_name IN ("*roja*","*directa*","*stream*","*fifa*","*worldcup*")) BY Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let MassivPerseusHashes = dynamic(["3b8bb7631b39f455d31544b55ba97b49ab1888c1","84ecdca915f1af822ccc8a04479f5179104f353c","9bd164dd3f50d196c7dff4f6c1b0f1345ac96d9a"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA1 in (MassivPerseusHashes) or (FileName endswith ".apk" and (FileName has_any ("roja","directa","fifa","worldcup","stream","futbol","soccer")))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath, SHA1, SHA256, FileOriginUrl, FileOriginReferrerUrl, FileOriginIP
| order by Timestamp desc
```

### GHOST STADIUM PingIdentity SSO clone: external referrer hot-linking fifa.com static assets

`UC_89_13` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.http_referrer) as referrers values(Web.url) as urls FROM datamodel=Web.Web WHERE (Web.url="*fifa.com/*.jpg" OR Web.url="*fifa.com/*.png" OR Web.url="*fifa.com/*.svg" OR Web.url="*fifa.com/*.webp" OR Web.url="*fifa.com/assets/*" OR Web.url="*fifa.com/static/*" OR Web.url="*fifa.com/images/*") AND NOT (Web.http_referrer="*fifa.com*" OR Web.http_referrer="*pingidentity.com*" OR Web.http_referrer="*ping.fifa.com*" OR Web.http_referrer="https://www.google.com/*" OR Web.http_referrer="-" OR Web.http_referrer="") BY Web.src Web.user Web.http_referrer | `drop_dm_object_name(Web)` | rex field=http_referrer "^https?://(?<ref_host>[^/]+)/" | where NOT match(ref_host, "(^|\.)fifa\.com$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected")
| where isnotempty(RemoteUrl)
| extend RemoteUrlLower = tolower(RemoteUrl)
| where RemoteUrlLower has "fifa.com"
| where RemoteUrlLower matches regex @"fifa\.com/.+\.(jpg|jpeg|png|svg|webp|gif|css)(\?|$)"
   or RemoteUrlLower has_any ("fifa.com/assets/","fifa.com/static/","fifa.com/images/","fifa.com/_next/")
| join kind=inner (
    DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType == "BrowserLaunchedToOpenUrl" or AdditionalFields has "Referrer"
    | extend Referrer = tostring(parse_json(AdditionalFields).Referrer)
    | where isnotempty(Referrer) and Referrer !contains "fifa.com" and Referrer !contains "pingidentity.com"
    | project DeviceId, RefTime=Timestamp, Referrer
  ) on DeviceId
| where Timestamp between (RefTime .. RefTime + 30s)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, Referrer, RemoteUrl, RemoteIP
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

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `148.178.18.23`, `148.178.18.60`, `154.86.0.33`, `207.56.1.93`, `66.112.212.25`, `148.178.16.48`, `148.178.16.5`, `104.225.235.49` _(+37 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `3b8bb7631b39f455d31544b55ba97b49ab1888c1`, `84ecdca915f1af822ccc8a04479f5179104f353c`, `9bd164dd3f50d196c7dff4f6c1b0f1345ac96d9a`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 14 use case(s) fired, 26 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
