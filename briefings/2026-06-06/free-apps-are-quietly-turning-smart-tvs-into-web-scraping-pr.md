# [HIGH] Free Apps Are Quietly Turning Smart TVs Into Web-Scraping Proxies for AI

**Source:** The Hacker News
**Published:** 2026-06-06
**Article:** https://thehackernews.com/2026/06/free-apps-are-quietly-turning-smart-tvs.html

## Threat Profile

Free Apps Are Quietly Turning Smart TVs Into Web-Scraping Proxies for AI 
 Swati Khandelwal  Jun 06, 2026 Network Security / IoT Security 
A researcher has reverse-engineered the iOS SDK that Bright Data embeds in consumer apps and documented how it turns devices, including always-on smart TVs, into exit nodes that relay web-scraping traffic for a data business Bright Data markets heavily to the AI industry.
The company, the successor to Luminati, operates what it calls the largest residential…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `proxyjs.brdtnet.com`
- **Domain (defanged):** `proxyjs.luminatinet.com`
- **Domain (defanged):** `proxyjs.bright-sdk.com`
- **Domain (defanged):** `clientsdk.bright-sdk.com`
- **Domain (defanged):** `clientsdk.brdtnet.com`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1090.002** — External Proxy
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1474.003** — Supply Chain Compromise: Compromise Software Supply Chain (mobile)
- **T1496** — Resource Hijacking
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Bright Data SDK control-plane beacon to proxyjs/clientsdk endpoints

`UC_76_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.answer) as answers from datamodel=Network_Resolution where DNS.query IN ("proxyjs.brdtnet.com","proxyjs.luminatinet.com","proxyjs.bright-sdk.com","clientsdk.bright-sdk.com","clientsdk.brdtnet.com") OR DNS.query="*.bright-sdk.com" OR DNS.query="*.brdtnet.com" OR DNS.query="*.luminatinet.com" OR DNS.query="*.luminati.io" by DNS.src DNS.query host
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
// Bright Data residential-proxy SDK control-plane beacon
// Endpoints contacting *.bright-sdk.com / *.brdtnet.com / *.luminatinet.com
let brdControlHosts = dynamic(["proxyjs.brdtnet.com","proxyjs.luminatinet.com","proxyjs.bright-sdk.com","clientsdk.bright-sdk.com","clientsdk.brdtnet.com"]);
let brdSuffixes = dynamic([".bright-sdk.com",".brdtnet.com",".luminatinet.com",".luminati.io"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| where RemoteUrl in~ (brdControlHosts)
    or RemoteUrl has_any (brdSuffixes)
| extend MatchType = case(RemoteUrl in~ (brdControlHosts), "control-plane FQDN",
                          RemoteUrl endswith ".bright-sdk.com", "bright-sdk.com suffix",
                          RemoteUrl endswith ".brdtnet.com", "brdtnet.com suffix",
                          RemoteUrl endswith ".luminatinet.com", "luminatinet.com suffix",
                          RemoteUrl endswith ".luminati.io", "luminati.io suffix",
                          "other")
| project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, MatchType
| order by Timestamp desc
```

### Bright Data partner-app or brdsdk.framework present on managed iOS / mobile inventory

`UC_76_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Endpoint.Processes.dest) as devices from datamodel=Endpoint.Processes where Endpoint.Processes.process IN ("*Petflix*","*PlayWorks*","*CloudTV*","*Longvision*","*brdsdk*","*BrdWebSocketFacade*","*BrdNetwork.DNSResolver*") OR Endpoint.Processes.process_name IN ("*Petflix*","*PlayWorks*","*CloudTV*","*Longvision*") by Endpoint.Processes.dest Endpoint.Processes.process_name
| `drop_dm_object_name("Endpoint.Processes")`
| `security_content_ctime(firstSeen)`
| `security_content_ctime(lastSeen)`
```

**Defender KQL:**
```kql
// Hunt managed fleet for Bright Data SDK partner apps and the brdsdk.framework binary
let brdPartnerApps = dynamic(["Petflix","PlayWorks","CloudTV","Longvision"]);
let brdVendors = dynamic(["PlayWorks Digital","CloudTV","Longvision","Bright Data","Luminati"]);
DeviceTvmSoftwareInventory
| where SoftwareName has_any (brdPartnerApps)
    or SoftwareVendor has_any (brdVendors)
    or SoftwareName contains "brdsdk"
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, OSPlatform, DeviceType, PublicIP, LoggedOnUsers) by DeviceId) on DeviceId
| project DeviceId, DeviceName, OSPlatform, DeviceType, SoftwareVendor, SoftwareName, SoftwareVersion, PublicIP, LoggedOnUsers, EndOfSupportStatus
| union (
    DeviceImageLoadEvents
    | where Timestamp > ago(7d)
    | where FileName contains "brdsdk" or FolderPath contains "brdsdk.framework" or FileName has_any ("BrdWebSocketFacade","BrdNetwork")
    | project DeviceId, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
  )
| order by DeviceName asc
```

### Smart-TV / mobile device acting as residential proxy exit node (high-fan-out HTTPS to unrelated public destinations)

`UC_76_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true 
    dc(All_Traffic.dest) as uniqueDests 
    dc(All_Traffic.dest_ip) as uniqueDstIPs 
    sum(All_Traffic.bytes_out) as bytesOut 
    sum(All_Traffic.bytes_in) as bytesIn 
    count as connCount 
    values(All_Traffic.app) as apps 
    from datamodel=Network_Traffic 
    where All_Traffic.dest_port IN (80,443) AND All_Traffic.action=allowed 
    by All_Traffic.src All_Traffic.src_category _time span=1h
| `drop_dm_object_name("All_Traffic")`
| where uniqueDests > 250 AND bytesOut > 524288000
| eval gbOut = round(bytesOut/1073741824, 2)
| where src_category IN ("iot","smart_tv","mobile","unknown","guest")
| sort - bytesOut
```

**Defender KQL:**
```kql
// Managed iOS / mobile exhibiting residential-proxy egress pattern (covers Defender for iOS estate)
let WindowHrs = 1h;
let MinUniqueRemoteIPs = 100;   // residential browsing rarely fans out to >100 distinct public IPs per hour
let MinSessions = 500;          // SDK polling + scraping job throughput floor
let ManagedMobile = DeviceInfo
    | where Timestamp > ago(24h)
    | where OSPlatform in ("iOS","iPadOS","Android")
    | summarize arg_max(Timestamp, OSPlatform, DeviceType, PublicIP, LoggedOnUsers) by DeviceId, DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where RemotePort in (80, 443, 8080, 8443)
| join kind=inner ManagedMobile on DeviceId
| summarize UniqueRemoteIPs = dcount(RemoteIP),
            UniqueRemoteUrls = dcount(RemoteUrl),
            Sessions = count(),
            SampleUrls = make_set(RemoteUrl, 25),
            SampleProcess = make_set(InitiatingProcessFileName, 10),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
            by DeviceName, DeviceId, OSPlatform, bin(Timestamp, WindowHrs)
| where UniqueRemoteIPs > MinUniqueRemoteIPs and Sessions > MinSessions
| extend MultiUseSig = iff(UniqueRemoteUrls > 200 and array_length(SampleProcess) <= 2, "likely-proxy", "review")
| order by Sessions desc
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
  - IP / domain IOC(s): `proxyjs.brdtnet.com`, `proxyjs.luminatinet.com`, `proxyjs.bright-sdk.com`, `clientsdk.bright-sdk.com`, `clientsdk.brdtnet.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
