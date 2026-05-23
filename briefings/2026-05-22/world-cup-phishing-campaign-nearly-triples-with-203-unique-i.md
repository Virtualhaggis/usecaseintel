# [HIGH] World Cup Phishing Campaign Nearly Triples With 203 Unique IP Addresses

**Source:** Cyber Security News
**Published:** 2026-05-22
**Article:** https://cybersecuritynews.com/world-cup-phishing-campaign-nearly-triples/

## Threat Profile

Home Cyber Security News 
World Cup Phishing Campaign Nearly Triples With 203 Unique IP Addresses 
By Tushar Subhra Dutta 
May 22, 2026 
A large-scale phishing campaign targeting the 2026 FIFA World Cup has grown far beyond what security researchers originally thought. What began as a documented set of 79 fraudulent domains has ballooned into a network of at least 222 domains spread across 203 unique IP addresses, making it nearly three times larger than first reported. 
The campaign is built to…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `38.246.249.74`
- **IPv4 (defanged):** `154.39.81.213`
- **IPv4 (defanged):** `148.178.16.48`
- **IPv4 (defanged):** `154.86.0.33`
- **IPv4 (defanged):** `104.225.235.49`
- **Domain (defanged):** `fifa-com.store`
- **Domain (defanged):** `fifa-com.site`
- **Domain (defanged):** `fifa-com.shop`
- **Domain (defanged):** `fifa-com.one`
- **Domain (defanged):** `dustdigitalsw.shop`
- **Domain (defanged):** `https-fifa.cn`
- **Domain (defanged):** `ww-fifaweb.cn`
- **Domain (defanged):** `fifawebsite.cn`
- **Domain (defanged):** `www-fifaworldcup.one`
- **Domain (defanged):** `www-fifaworldcup.vip`
- **SHA1:** `1b02595c66a13a4a5a523a76de25803bdb950623`
- **SHA1:** `fc1db8def38bb08010bb8f8ac14d5e498ff8ff43`
- **SHA1:** `3b8bb7631b39f455d31544b55ba97b49ab1888c1`
- **SHA1:** `fb0498ab592232747a4d90aa150ee4e0506869ca`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1583.001** — Acquire Infrastructure: Domains
- **T1656** — Impersonation
- **T1587.003** — Develop Capabilities: Digital Certificates

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Connection or DNS lookup to 2026 FIFA World Cup phishing infrastructure (Flare cluster)

`UC_5_8` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("38.246.249.74","154.39.81.213","148.178.16.48","154.86.0.33","104.225.235.49")) by All_Traffic.src All_Traffic.user host All_Traffic.app | `drop_dm_object_name(All_Traffic)` | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as query values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where (DNS.query IN ("fifa-com.store","fifa-com.site","fifa-com.shop","fifa-com.one","dustdigitalsw.shop","https-fifa.cn","ww-fifaweb.cn","fifawebsite.cn","www-fifaworldcup.one","www-fifaworldcup.vip") OR DNS.query="*fifa*" AND DNS.query IN ("*-fifa*","fifa-com*","*fifaworldcup*","*fifaweb*")) by DNS.src DNS.query host | `drop_dm_object_name(DNS)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CampaignIPs = dynamic(["38.246.249.74","154.39.81.213","148.178.16.48","154.86.0.33","104.225.235.49"]);
let CampaignDomains = dynamic(["fifa-com.store","fifa-com.site","fifa-com.shop","fifa-com.one","dustdigitalsw.shop","https-fifa.cn","ww-fifaweb.cn","fifawebsite.cn","www-fifaworldcup.one","www-fifaworldcup.vip"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (CampaignIPs)
   or RemoteUrl has_any (CampaignDomains)
   or (RemoteUrl matches regex @"(?i)(fifa-com\.|-fifa\.|ww-fifa|fifaworldcup\.|fifaweb|https-fifa)")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, ActionType
| order by Timestamp desc
```

### [LLM] FIFA World Cup typosquat domain hit in Defender SafeLinks / email URL telemetry

`UC_5_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Email.recipient) as recipient values(All_Email.subject) as subject values(All_Email.src_user) as sender from datamodel=Email.All_Email where (All_Email.url IN ("*fifa-com.store*","*fifa-com.site*","*fifa-com.shop*","*fifa-com.one*","*dustdigitalsw.shop*","*https-fifa.cn*","*ww-fifaweb.cn*","*fifawebsite.cn*","*fifaworldcup.one*","*fifaworldcup.vip*")) by All_Email.message_id host | `drop_dm_object_name(All_Email)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CampaignDomains = dynamic(["fifa-com.store","fifa-com.site","fifa-com.shop","fifa-com.one","dustdigitalsw.shop","https-fifa.cn","ww-fifaweb.cn","fifawebsite.cn","www-fifaworldcup.one","www-fifaworldcup.vip"]);
let CampaignRegex = @"(?i)(fifa-com\.|-fifa\.cn|ww-fifa|fifaworldcup\.(one|vip)|fifaweb(site)?\.|https-fifa)";
let UrlMatches = EmailUrlInfo
| where Timestamp > ago(30d)
| where Url has_any (CampaignDomains) or Url matches regex CampaignRegex
| project Timestamp, NetworkMessageId, Url, UrlDomain;
UrlMatches
| join kind=inner ( EmailEvents | where Timestamp > ago(30d) ) on NetworkMessageId
| project Timestamp, SenderFromAddress, SenderIPv4, RecipientEmailAddress, Subject, Url, DeliveryAction, ThreatTypes, NetworkMessageId
| join kind=leftouter ( UrlClickEvents | where Timestamp > ago(30d) | where ActionType in ("ClickAllowed","ClickedThrough") | project ClickTime = Timestamp, Url, AccountUpn, IPAddress, IsClickedThrough ) on Url
| order by Timestamp desc
```

### [LLM] TLS certificate fingerprint reuse across FIFA World Cup phishing infrastructure

`UC_5_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(SSL.ssl_cert_common_name) as cn values(SSL.dest) as dest_ip values(SSL.dest_port) as dest_port from datamodel=Certificates.SSL where (SSL.ssl_hash IN ("1b02595c66a13a4a5a523a76de25803bdb950623","fc1db8def38bb08010bb8f8ac14d5e498ff8ff43","3b8bb7631b39f455d31544b55ba97b49ab1888c1","fb0498ab592232747a4d90aa150ee4e0506869ca") OR SSL.ssl_publickey_hash IN ("1b02595c66a13a4a5a523a76de25803bdb950623","fc1db8def38bb08010bb8f8ac14d5e498ff8ff43","3b8bb7631b39f455d31544b55ba97b49ab1888c1","fb0498ab592232747a4d90aa150ee4e0506869ca")) by SSL.src SSL.ssl_hash host | `drop_dm_object_name(SSL)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Defender Advanced Hunting does not expose TLS cert SHA1 directly.
// Closest pivot: enrich DeviceNetworkEvents against the campaign IPs that host these certs.
let CertHostingIPs = dynamic(["38.246.249.74","154.39.81.213","148.178.16.48","154.86.0.33","104.225.235.49"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemotePort in (443, 8443)
| where RemoteIP in (CertHostingIPs)
   or RemoteUrl matches regex @"(?i)(fifa-com\.|-fifa\.cn|ww-fifa|fifaworldcup\.(one|vip)|fifaweb|https-fifa)"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RemoteIP, RemoteUrl, RemotePort
| summarize Sessions=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hosts=dcount(DeviceName) by RemoteIP, RemoteUrl
| order by Sessions desc
```

### [LLM] Newly registered FIFA-themed typosquat lookups by enterprise hosts

`UC_5_11` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where (DNS.query="*fifa*" OR DNS.query="*worldcup*" OR DNS.query="*world-cup*") by DNS.query host | `drop_dm_object_name(DNS)` | rex field=query "\.(?<tld>[a-z]+)$" | search tld IN ("store","shop","site","one","vip","cn","top","online","xyz","icu") OR query="*fifa-com*" OR query="*-fifa*" OR query="www-fifa*" OR query="https-fifa*" | lookup domain_whois_lookup domain AS query OUTPUT registrar create_date | where (registrar IN ("GNAME.COM, INC.","GoDaddy.com, LLC") OR isnull(registrar)) AND firstTime > relative_time(now(),"-90d") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where isnotempty(RemoteUrl)
| where RemoteUrl matches regex @"(?i)(^|\.)(fifa[-_]?(com|web|world|cup|2026)?|world[-_]?cup[-_]?2?0?2?6?)\."
| where not(RemoteUrl endswith "fifa.com")
| where not(RemoteUrl endswith "fifa.gg")
| where not(RemoteUrl endswith "fifa-bookkeeper.com")
| extend TLD = extract(@"\.([a-z]+)$", 1, tolower(RemoteUrl))
| where TLD in ("store","shop","site","one","vip","cn","top","online","xyz","icu","click")
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Hosts = dcount(DeviceName), Hits = count(), SampleHost = any(DeviceName) by RemoteUrl, TLD
| where FirstSeen > ago(30d)
| order by FirstSeen desc
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `38.246.249.74`, `154.39.81.213`, `148.178.16.48`, `154.86.0.33`, `104.225.235.49`, `fifa-com.store`, `fifa-com.site`, `fifa-com.shop` _(+7 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `1b02595c66a13a4a5a523a76de25803bdb950623`, `fc1db8def38bb08010bb8f8ac14d5e498ff8ff43`, `3b8bb7631b39f455d31544b55ba97b49ab1888c1`, `fb0498ab592232747a4d90aa150ee4e0506869ca`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
