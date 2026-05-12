# [CRIT] Global Crackdown Arrests 276, Shuts 9 Crypto Scam Centers, Seizes $701M

**Source:** The Hacker News
**Published:** 2026-05-04
**Article:** https://thehackernews.com/2026/05/global-crackdown-arrests-276-shuts-9.html

## Threat Profile

Global Crackdown Arrests 276, Shuts 9 Crypto Scam Centers, Seizes $701M 
 Ravie Lakshmanan  May 04, 2026 Mobile Security / Financial Crime 
A coordinated international operation involving U.S. and Chinese authorities has arrested at least 276 suspects and shut down nine scam centers used for cryptocurrency investment fraud schemes targeting Americans, resulting in millions of dollars in losses.
The crackdown was led by the Dubai Police, under the United Arab Emirates (UAE) Ministry of Interior…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33626`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-3854`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1566.002** — Phishing: Spearphishing Link
- **T1583.001** — Acquire Infrastructure: Domains
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1437.001** — Application Layer Protocol: Web Protocols (Mobile)
- **T1566.001** — Phishing: Spearphishing Attachment

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vault Viper / Vigorish Viper Android lure-domain access from corporate endpoint

`UC_96_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user values(Web.dest) as dest from datamodel=Web.Web where Web.url IN ("*orgo.cc*","*dkhth.com*","*ngovbr.cc*","*sxjgo.cc*","*rycnair.com*","*vsgo.cc*","*nmxgo.cc*","*idphil.net*","*immigration-kr.net*","*openbank-es.com*","*cedula-registraduria-gov.org*","*nbsvgo.cc*","*lx-yindu.top*","*orbiixtrade.com*") by Web.src Web.user Web.dest Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let VaultViperLureDomains = dynamic(["orgo.cc","dkhth.com","ngovbr.cc","sxjgo.cc","rycnair.com","vsgo.cc","nmxgo.cc","idphil.net","immigration-kr.net","openbank-es.com","cedula-registraduria-gov.org","nbsvgo.cc","lx-yindu.top","orbiixtrade.com"]);
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where isnotempty(RemoteUrl)
    | extend MatchedDomain = tostring(VaultViperLureDomains[toint(0)])
    | mv-apply Lure = VaultViperLureDomains to typeof(string) on (
        where RemoteUrl has tostring(Lure)
        | project MatchedDomain = tostring(Lure)
      )
    | project Timestamp, DeviceName, RemoteIP, RemoteUrl, MatchedDomain,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName;
let ClickHits = UrlClickEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | mv-apply Lure = VaultViperLureDomains to typeof(string) on (
        where Url has tostring(Lure)
        | project MatchedDomain = tostring(Lure)
      )
    | project Timestamp, AccountUpn, Url, MatchedDomain, IPAddress, Workload, IsClickedThrough;
union isfuzzy=true NetHits, ClickHits
| order by Timestamp desc
```

### [LLM] Vault Viper Android banking trojan C2 beacon (IP / domain IOC sweep)

`UC_96_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("103.214.169.197","18.167.169.60","38.47.52.4") OR All_Traffic.dest IN ("vnwd.top","alafrica.xyz","alperu.top","safeapk.xyz","*.vnwd.top","*.alafrica.xyz","*.alperu.top","*.safeapk.xyz") by All_Traffic.src All_Traffic.src_ip All_Traffic.user All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let VaultViperC2Ips = dynamic(["103.214.169.197","18.167.169.60","38.47.52.4"]);
let VaultViperC2Domains = dynamic(["vnwd.top","alafrica.xyz","alperu.top","safeapk.xyz"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","HttpConnectionInspected")
| where RemoteIP in (VaultViperC2Ips)
   or RemoteUrl has_any (VaultViperC2Domains)
| project Timestamp, DeviceName, DeviceId, RemoteIP, RemotePort, RemoteUrl,
          Protocol, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] Inbound email carrying APK or Vault Viper lure URL impersonating bank/government

`UC_96_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Email.subject) as subject values(All_Email.url) as url values(All_Email.file_name) as file_name values(All_Email.recipient) as recipient from datamodel=Email.All_Email where (All_Email.file_name="*.apk" OR All_Email.url IN ("*orgo.cc*","*dkhth.com*","*ngovbr.cc*","*sxjgo.cc*","*rycnair.com*","*vsgo.cc*","*nmxgo.cc*","*idphil.net*","*immigration-kr.net*","*openbank-es.com*","*cedula-registraduria-gov.org*","*nbsvgo.cc*","*lx-yindu.top*","*orbiixtrade.com*","*vnwd.top*","*alafrica.xyz*","*alperu.top*","*safeapk.xyz*")) by All_Email.src_user All_Email.recipient All_Email.subject | `drop_dm_object_name(All_Email)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let VaultViperDomains = dynamic(["orgo.cc","dkhth.com","ngovbr.cc","sxjgo.cc","rycnair.com","vsgo.cc","nmxgo.cc","idphil.net","immigration-kr.net","openbank-es.com","cedula-registraduria-gov.org","nbsvgo.cc","lx-yindu.top","orbiixtrade.com","vnwd.top","alafrica.xyz","alperu.top","safeapk.xyz"]);
let ApkKnownHashes = dynamic([
    "4fff28eecc0ab6303e4948df77671009dda5b93ed3d1cead527b02d1317426bc",
    "39ea88f852b25d3c55d605464a3440bd250a577e3e21f52d1eaf94d15aad5b82",
    "4338ab77d05aeacd7eac5acbe9eed5568778c8e3e9499562816805b54b4d1a6a"]);
let ApkAttachments = EmailAttachmentInfo
    | where Timestamp > ago(30d)
    | where FileName endswith ".apk" or SHA256 in (ApkKnownHashes)
    | project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress,
              FileName, FileType, SHA256, MalwareFilterVerdict;
let LureUrls = EmailUrlInfo
    | where Timestamp > ago(30d)
    | where UrlDomain has_any (VaultViperDomains) or Url has_any (VaultViperDomains)
    | project Timestamp, NetworkMessageId, Url, UrlDomain, UrlLocation;
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| join kind=inner (
    union isfuzzy=true
        (ApkAttachments | extend MatchKind = "APK", Indicator = strcat(FileName, " / ", SHA256)),
        (LureUrls       | extend MatchKind = "LureURL", Indicator = Url)
    | project NetworkMessageId, MatchKind, Indicator
  ) on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress,
          RecipientEmailAddress, Subject, MatchKind, Indicator,
          DeliveryAction, DeliveryLocation
| order by Timestamp desc
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
