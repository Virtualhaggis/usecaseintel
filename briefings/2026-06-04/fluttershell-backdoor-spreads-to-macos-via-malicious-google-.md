# [HIGH] FlutterShell Backdoor Spreads to macOS via Malicious Google and YouTube Ads

**Source:** The Hacker News
**Published:** 2026-06-04
**Article:** https://thehackernews.com/2026/06/fluttershell-backdoor-spreads-to-macos.html

## Threat Profile

FlutterShell Backdoor Spreads to macOS via Malicious Google and YouTube Ads 
 Ravie Lakshmanan  Jun 04, 2026 Malvertising / Browser Security 
Cybersecurity researchers have shed light on a macOS malvertising campaign codenamed Operation FlutterBridge that spreads a new backdoor called FlutterShell .
According to Palo Alto Networks Unit 42, the campaign is said to be the next stage of a previously reported activity cluster dubbed JSCoreRunner (aka FileRipple ) in late August 2025. The cybercrim…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `atsheisdomestic.org`
- **Domain (defanged):** `etoftheappyrince.org`
- **Domain (defanged):** `healightejustb.org`
- **Domain (defanged):** `sinterfumesco.com`
- **Domain (defanged):** `ads-parkpro.com`
- **Domain (defanged):** `adsparkpro.top`
- **Domain (defanged):** `adsparkpro.net`
- **Domain (defanged):** `softwe.art`
- **SHA256:** `021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845`
- **SHA256:** `363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34`
- **SHA256:** `8421c902364980e3d762ec6dbbe6b0f40577c27bd79b48c57d098328b2533109`
- **SHA256:** `644fc49fa1006a2a2acace694e5fb83753164e2617051ece6d9dc9ea32329e70`
- **SHA256:** `9053e8ddaecca1f960c041c944ca8799fc71dc86a4b50d2639ee4e0d2cb82f47`
- **SHA256:** `b60074d1ea2008a581f432f2dee5f84f78668d9dd8e66f75d03c42dabd89bdea`
- **SHA256:** `9425e8e39fa8a7212cdd07f0917cb3dfde38a90b87297de2c82a5850aff1e4de`
- **SHA256:** `30448686ec900d5213d74f08f0d2b7924c5336a29445b2a434aba8d8b19d7530`
- **SHA256:** `48047c34bfd57fe1e24bc538bc2ce9e0ac4c4eb48d3b0c195b414f0379dc0745`

## MITRE ATT&CK Techniques

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
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1176** — Browser Extensions
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1583.001** — Acquire Infrastructure: Domains
- **T1553.002** — Subvert Trust Controls: Code Signing
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.002** — Command and Scripting Interpreter: AppleScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Chrome Preferences tamper on macOS by non-Chrome process (FlutterShell browser hijack)

`UC_16_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*/Library/Application Support/Google/Chrome/Default/Preferences","*/Library/Application Support/Google/Chrome/Default/Secure Preferences","*/Library/Application Support/Google/Chrome/Local State") AND Filesystem.action=modified AND NOT Filesystem.process_name IN ("Google Chrome","Google Chrome Helper","Google Chrome Helper (Renderer)","chrome") by host Filesystem.process_name Filesystem.process_path Filesystem.file_path Filesystem.user | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "/Library/Application Support/Google/Chrome/"
| where FileName in~ ("Preferences","Secure Preferences","Local State")
| where ActionType in ("FileModified","FileCreated","FileRenamed")
| where not(InitiatingProcessFileName has_any ("Google Chrome","Google Chrome Helper","chrome","Keystone"))
| where not(InitiatingProcessFolderPath startswith "/Applications/Google Chrome.app/")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, FileName, FolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] macOS host beaconing to FlutterShell C2 / ad-intermediary domains

`UC_16_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.src) as src values(All_Traffic.app) as process from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("atsheisdomestic.org","etoftheappyrince.org","healightejustb.org","sinterfumesco.com","ads-parkpro.com","adsparkpro.top","adsparkpro.net","softwe.art","*.atsheisdomestic.org","*.etoftheappyrince.org","*.healightejustb.org","*.sinterfumesco.com","*.ads-parkpro.com","*.adsparkpro.top","*.adsparkpro.net","*.softwe.art") by All_Traffic.src All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let c2_domains = dynamic(["atsheisdomestic.org","etoftheappyrince.org","healightejustb.org","sinterfumesco.com","ads-parkpro.com","adsparkpro.top","adsparkpro.net","softwe.art"]);
let net = DeviceNetworkEvents
| where Timestamp > ago(30d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (c2_domains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, RemoteUrl, RemoteIP, RemotePort, ActionType, InitiatingProcessAccountName;
let dns = DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("DnsQueryResponse","InboundConnectionAccepted")
| extend QName = tostring(parse_json(AdditionalFields).QueryName)
| where QName has_any (c2_domains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, QName, RemoteIP, InitiatingProcessAccountName;
union net, dns
| order by Timestamp desc
```

### [LLM] Known FlutterShell SHA256 binary execution on macOS

`UC_16_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_hash IN ("021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845","363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34","8421c902364980e3d762ec6dbbe6b0f40577c27bd79b48c57d098328b2533109","644fc49fa1006a2a2acace694e5fb83753164e2617051ece6d9dc9ea32329e70","9053e8ddaecca1f960c041c944ca8799fc71dc86a4b50d2639ee4e0d2cb82f47","b60074d1ea2008a581f432f2dee5f84f78668d9dd8e66f75d03c42dabd89bdea","9425e8e39fa8a7212cdd07f0917cb3dfde38a90b87297de2c82a5850aff1e4de","30448686ec900d5213d74f08f0d2b7924c5336a29445b2a434aba8d8b19d7530") by host Processes.process_name Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let ioc_hashes = dynamic(["021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845","363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34","8421c902364980e3d762ec6dbbe6b0f40577c27bd79b48c57d098328b2533109","644fc49fa1006a2a2acace694e5fb83753164e2617051ece6d9dc9ea32329e70","9053e8ddaecca1f960c041c944ca8799fc71dc86a4b50d2639ee4e0d2cb82f47","b60074d1ea2008a581f432f2dee5f84f78668d9dd8e66f75d03c42dabd89bdea","9425e8e39fa8a7212cdd07f0917cb3dfde38a90b87297de2c82a5850aff1e4de","30448686ec900d5213d74f08f0d2b7924c5336a29445b2a434aba8d8b19d7530"]);
let proc_hits = DeviceProcessEvents
| where Timestamp > ago(90d)
| where SHA256 in (ioc_hashes) or InitiatingProcessSHA256 in (ioc_hashes)
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessSHA256, AccountName;
let file_hits = DeviceFileEvents
| where Timestamp > ago(90d)
| where SHA256 in (ioc_hashes) or InitiatingProcessSHA256 in (ioc_hashes)
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountName;
union proc_hits, file_hits
| order by Timestamp desc
```

### [LLM] FlutterShell WebView bridge spawns shell on macOS (arbitrary command execution capability)

`UC_16_11` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("PodcastsLounge","PDF-Brain","PDF-Ninja","PodcastsLounge*","PDF-Brain*","PDF-Ninja*") AND Processes.process_name IN ("sh","bash","zsh","osascript","curl","python","python3") by host Processes.parent_process Processes.parent_process_name Processes.process Processes.process_name Processes.user | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where InitiatingProcessFileName in~ ("PodcastsLounge","PDF-Brain","PDF-Ninja")
   or InitiatingProcessFolderPath has_any ("/PodcastsLounge.app/","/PDF-Brain.app/","/PDF-Ninja.app/")
   or InitiatingProcessVersionInfoCompanyName has_any ("AdsParkPro","Advantage Web Marketing","SOFT WE ART","PACIFIC TRADE SOLUTIONS")
| where FileName in~ ("sh","bash","zsh","dash","osascript","curl","python","python3","env")
| extend HasShellArgs = ProcessCommandLine has_any ("-c ","-c\"","-e ","do shell script","printenv","env")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessVersionInfoCompanyName, InitiatingProcessSHA256, FileName, ProcessCommandLine, HasShellArgs
| order by Timestamp desc
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
  - IP / domain IOC(s): `atsheisdomestic.org`, `etoftheappyrince.org`, `healightejustb.org`, `sinterfumesco.com`, `ads-parkpro.com`, `adsparkpro.top`, `adsparkpro.net`, `softwe.art`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845`, `363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34`, `8421c902364980e3d762ec6dbbe6b0f40577c27bd79b48c57d098328b2533109`, `644fc49fa1006a2a2acace694e5fb83753164e2617051ece6d9dc9ea32329e70`, `9053e8ddaecca1f960c041c944ca8799fc71dc86a4b50d2639ee4e0d2cb82f47`, `b60074d1ea2008a581f432f2dee5f84f78668d9dd8e66f75d03c42dabd89bdea`, `9425e8e39fa8a7212cdd07f0917cb3dfde38a90b87297de2c82a5850aff1e4de`, `30448686ec900d5213d74f08f0d2b7924c5336a29445b2a434aba8d8b19d7530` _(+1 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
