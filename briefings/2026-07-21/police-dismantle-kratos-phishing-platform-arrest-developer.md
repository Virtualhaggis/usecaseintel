# [HIGH] Police dismantle Kratos phishing platform, arrest developer

**Source:** BleepingComputer
**Published:** 2026-07-21
**Article:** https://www.bleepingcomputer.com/news/security/police-dismantle-kratos-phishing-platform-arrest-developer/

## Threat Profile

Police dismantle Kratos phishing platform, arrest developer 
By Bill Toulas 
July 21, 2026
07:07 PM
0 
Authorities in Germany and the U.S. dismantled the central infrastructure of Kratos, a phishing-as-a-service (PhaaS) platform with global reach, and its developer was arrested in Indonesia.
During the operation, authorities seized more than 200 servers, effectively disrupting the malicious service and rendering it inoperable.
The action was led by Frankfurt’s Prosecutor General Office (ZIT), Ge…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `41.128.0.142`
- **Domain (defanged):** `abal.my`
- **Domain (defanged):** `starwellmedia.com`
- **Domain (defanged):** `aabiz.de`
- **Domain (defanged):** `aspireglobal.ltd`
- **Domain (defanged):** `buenne.de`
- **Domain (defanged):** `dufllot.sbs`
- **Domain (defanged):** `enerdizerandtron.de`
- **Domain (defanged):** `espaciocf.de`
- **Domain (defanged):** `ihrsupportcenter.de`
- **Domain (defanged):** `ilersls.org`
- **Domain (defanged):** `aaalen.de`
- **Domain (defanged):** `rundwasser.de`
- **Domain (defanged):** `smartcontrolengineer.com`
- **Domain (defanged):** `sonnenbrillenspot.de`
- **Domain (defanged):** `trisrnareprjdocz.com`
- **Domain (defanged):** `dwbud.vilaribit.com`
- **Domain (defanged):** `razen.online`
- **Domain (defanged):** `theoceanac.online`
- **Domain (defanged):** `jumpast.es`
- **Domain (defanged):** `klenpare.com`
- **Domain (defanged):** `uvarnix.cfd`
- **Domain (defanged):** `xavon.sbs`
- **Domain (defanged):** `crm-technik.de`
- **SHA256:** `cd231b895bbcd7154b81df1e065bf02f1ec667b920c8b6d23308cd509833b5ea`
- **SHA256:** `949895df17148c5ea29f190d2619a14b3ec648425b9cc3c5a1423553c16f3898`
- **SHA256:** `9d1a1a5e3b5e5de8a6c76ded7a01fa01709d426232b0048c9ee6ba0c5c1b8b42`
- **SHA256:** `c447e75f1029ed7a5882add16bcd13ad44be3bd47c93c830ff39185e23d25ebb`
- **SHA256:** `a3c298ccf2456989ceb080e661b01c3b00445902ae7bb3e58dad4d846334ff9c`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1566.002** — Phishing: Spearphishing Link
- **T1583.001** — Acquire Infrastructure: Domains
- **T1056.003** — Input Capture: Web Portal Capture
- **T1539** — Steal Web Session Cookie
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Kratos PhaaS network/DNS egress to phishing domains and operator IP 41.128.0.142

`UC_29_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="41.128.0.142" OR All_Traffic.dest IN ("dwbud.vilaribit.com","razen.online","theoceanac.online","jumpast.es","enerdizerandtron.de","abal.my","starwellmedia.com","aabiz.de","aspireglobal.ltd","buenne.de","dufllot.sbs","espaciocf.de","ihrsupportcenter.de","ilersls.org","aaalen.de","rundwasser.de","smartcontrolengineer.com","sonnenbrillenspot.de","trisrnareprjdocz.com","crm-technik.de")) by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_ip, All_Traffic.dest_port | `drop_dm_object_name("All_Traffic")` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let D=dynamic(["dwbud.vilaribit.com","razen.online","theoceanac.online","jumpast.es","enerdizerandtron.de","abal.my","starwellmedia.com","aabiz.de","aspireglobal.ltd","buenne.de","dufllot.sbs","espaciocf.de","ihrsupportcenter.de","ilersls.org","aaalen.de","rundwasser.de","smartcontrolengineer.com","sonnenbrillenspot.de","trisrnareprjdocz.com","crm-technik.de"]); DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP == "41.128.0.142" or RemoteUrl has_any (D) | where InitiatingProcessAccountName !endswith "$" | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine | order by Timestamp desc
```

### Kratos phishing kit web-asset fingerprint (barr.svg + lg.svg / PTT-SOft path)

`UC_29_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true values(Web.url) as urls count from datamodel=Web.Web where (Web.url="*barr.svg*" OR Web.url="*lg.svg*" OR Web.url="*dsa.svg*" OR Web.url="*sid.gif*" OR Web.url="*imag.jpg*" OR Web.url="*/PTT/SOft/*") by Web.src, Web.user, _time span=5m | `drop_dm_object_name("Web")` | eval hasBarr=if(mvcount(mvfilter(match(urls,"barr\.svg")))>0,1,0), hasLg=if(mvcount(mvfilter(match(urls,"lg\.svg")))>0,1,0), hasDsa=if(mvcount(mvfilter(match(urls,"dsa\.svg")))>0,1,0), hasSid=if(mvcount(mvfilter(match(urls,"sid\.gif")))>0,1,0), hasPtt=if(mvcount(mvfilter(match(urls,"/PTT/SOft/")))>0,1,0) | where (hasBarr=1 AND hasLg=1) OR hasPtt=1 OR (hasDsa=1 AND hasSid=1)
```

**Defender KQL:**
```kql
DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteUrl has_any ("barr.svg","lg.svg","dsa.svg","sid.gif","imag.jpg","/PTT/SOft/") | extend Asset=case(RemoteUrl has "barr.svg","barr.svg", RemoteUrl has "lg.svg","lg.svg", RemoteUrl has "dsa.svg","dsa.svg", RemoteUrl has "sid.gif","sid.gif", RemoteUrl has "imag.jpg","imag.jpg","ptt") | summarize Assets=make_set(Asset), Urls=make_set(RemoteUrl), Requests=count() by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 5m) | where (set_has_element(Assets,"barr.svg") and set_has_element(Assets,"lg.svg")) or set_has_element(Assets,"ptt") or (set_has_element(Assets,"dsa.svg") and set_has_element(Assets,"sid.gif")) | order by Timestamp desc
```

### Kratos PhaaS credential-exfil POST to next.php / save.php on phishing host

`UC_29_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Web.url) as urls from datamodel=Web.Web where Web.http_method="POST" AND (Web.url="*next.php*" OR Web.url="*nex.php*" OR Web.url="*n3xt.php*" OR Web.url="*save.php*" OR Web.url="*mini.php*" OR Web.url="*officers*eur.php*") AND (Web.dest IN ("dwbud.vilaribit.com","razen.online","theoceanac.online","jumpast.es","enerdizerandtron.de","abal.my","starwellmedia.com","aabiz.de","aspireglobal.ltd","buenne.de","dufllot.sbs","espaciocf.de","ihrsupportcenter.de","ilersls.org","aaalen.de","rundwasser.de","smartcontrolengineer.com","sonnenbrillenspot.de","trisrnareprjdocz.com","crm-technik.de") OR Web.dest_ip="41.128.0.142") by Web.src, Web.user, Web.dest, Web.dest_ip | `drop_dm_object_name("Web")`
```

**Defender KQL:**
```kql
let D=dynamic(["dwbud.vilaribit.com","razen.online","theoceanac.online","jumpast.es","enerdizerandtron.de","abal.my","starwellmedia.com","aabiz.de","aspireglobal.ltd","buenne.de","dufllot.sbs","espaciocf.de","ihrsupportcenter.de","ilersls.org","aaalen.de","rundwasser.de","smartcontrolengineer.com","sonnenbrillenspot.de","trisrnareprjdocz.com","crm-technik.de"]); DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteUrl has_any ("next.php","nex.php","n3xt.php","save.php","mini.php","officers") | where RemoteUrl has_any (D) or RemoteIP == "41.128.0.142" | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort | order by Timestamp desc
```

### Inbound email with URL to Kratos phishing domain clicked via Safe Links

`UC_29_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
let D=dynamic(["dwbud.vilaribit.com","razen.online","theoceanac.online","jumpast.es","enerdizerandtron.de","abal.my","starwellmedia.com","aabiz.de","aspireglobal.ltd","buenne.de","dufllot.sbs","espaciocf.de","ihrsupportcenter.de","ilersls.org","aaalen.de","rundwasser.de","smartcontrolengineer.com","sonnenbrillenspot.de","trisrnareprjdocz.com","crm-technik.de"]); let Clicks = UrlClickEvents | where Timestamp > ago(30d) | where ActionType in ("ClickAllowed","ClickedThrough") | where Url has_any (D) | project ClickTime=Timestamp, AccountUpn, ClickedUrl=Url, NetworkMessageId, IsClickedThrough; EmailEvents | where Timestamp > ago(30d) | where EmailDirection == "Inbound" | join kind=inner (EmailUrlInfo | where UrlDomain has_any (D) | project NetworkMessageId, Url, UrlDomain) on NetworkMessageId | join kind=leftouter Clicks on NetworkMessageId | project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, UrlDomain, Url, ClickTime, IsClickedThrough | order by Timestamp desc
```

### Microsoft 365 successful sign-in sourced from Kratos operator IP 41.128.0.142

`UC_29_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication.Authentication where Authentication.action="success" AND Authentication.src="41.128.0.142" by Authentication.user, Authentication.app, Authentication.src | `drop_dm_object_name("Authentication")` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
AADSignInEventsBeta | where Timestamp > ago(30d) | where IPAddress == "41.128.0.142" | where ErrorCode == 0 | project Timestamp, AccountUpn, AccountDisplayName, Application, AppDisplayName, IPAddress, Country, City, ClientAppUsed, ConditionalAccessStatus, RiskLevelDuringSignIn | order by Timestamp desc
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
  - IP / domain IOC(s): `41.128.0.142`, `abal.my`, `starwellmedia.com`, `aabiz.de`, `aspireglobal.ltd`, `buenne.de`, `dufllot.sbs`, `enerdizerandtron.de` _(+16 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `cd231b895bbcd7154b81df1e065bf02f1ec667b920c8b6d23308cd509833b5ea`, `949895df17148c5ea29f190d2619a14b3ec648425b9cc3c5a1423553c16f3898`, `9d1a1a5e3b5e5de8a6c76ded7a01fa01709d426232b0048c9ee6ba0c5c1b8b42`, `c447e75f1029ed7a5882add16bcd13ad44be3bd47c93c830ff39185e23d25ebb`, `a3c298ccf2456989ceb080e661b01c3b00445902ae7bb3e58dad4d846334ff9c`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
