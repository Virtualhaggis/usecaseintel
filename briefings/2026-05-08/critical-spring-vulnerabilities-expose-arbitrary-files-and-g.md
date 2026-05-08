# [HIGH] Critical Spring Vulnerabilities Expose Arbitrary Files and GCP Secrets

**Source:** Cyber Security News
**Published:** 2026-05-08
**Article:** https://cybersecuritynews.com/spring-vulnerabilities-expose-arbitrary-file/

## Threat Profile

Home Cyber Security News 
Critical Spring Vulnerabilities Expose Arbitrary Files and GCP Secrets 
By Abinaya 
May 8, 2026 




Spring Cloud Config provides crucial server-side and client-side support for externalized configuration in distributed systems.
Recently, the Spring development team disclosed four security vulnerabilities impacting the Spring Cloud Config Server. 
These flaws range from medium to critical severity, exposing environments to unauthorized arbitrary file access, cloud s…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-40982`
- **CVE:** `CVE-2026-40981`
- **CVE:** `CVE-2026-41002`
- **CVE:** `CVE-2026-41004`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1083** — File and Directory Discovery
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1592.002** — Gather Victim Host Information: Software

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Spring Cloud Config Server directory-traversal probe (CVE-2026-40982)

`UC_4_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as user_agents values(Web.status) as statuses values(Web.http_method) as methods from datamodel=Web where (Web.uri_path="*..%2f*" OR Web.uri_path="*..%2F*" OR Web.uri_path="*..%5c*" OR Web.uri_path="*..%5C*" OR Web.uri_path="*%2e%2e*" OR Web.uri_path="*%2E%2E*" OR Web.uri_path="*..%252f*" OR Web.uri_path="*..%252F*" OR Web.uri_query="*..%2f*" OR Web.uri_query="*%2e%2e*" OR Web.url="*..%2f*" OR Web.url="*%2e%2e*") AND (Web.dest_port IN (8888,8761,8080,8443) OR Web.uri_path="*/master/*" OR Web.uri_path="*/default/*" OR Web.uri_path="*/encrypt*" OR Web.uri_path="*/decrypt*") by Web.src Web.dest Web.dest_port Web.uri_path | `drop_dm_object_name(Web)` | eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S") | sort -count
```

**Defender KQL:**
```kql
// CVE-2026-40982 — Defender XDR doesn't ingest inbound HTTP request URIs, so this is a coarse network proxy: hosts running java + Spring Cloud Config Server that receive bursty external inbound connections on the default config-server ports.
let SpringConfig = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where (FileName has "java" or InitiatingProcessFileName has "java")
      and (ProcessCommandLine has_any ("spring-cloud-config-server","ConfigServerApplication","org.springframework.cloud.config.server")
           or InitiatingProcessCommandLine has_any ("spring-cloud-config-server","ConfigServerApplication","org.springframework.cloud.config.server"))
    | distinct DeviceId, DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess")
| where LocalPort in (8888, 8761, 8080, 8443)
| where DeviceId in ((SpringConfig | project DeviceId))
| where RemoteIPType == "Public"
| summarize Connections = count(),
            DistinctSources = dcount(RemoteIP),
            SampleIPs = make_set(RemoteIP, 25)
            by DeviceName, LocalPort, bin(Timestamp, 15m)
| where DistinctSources >= 5 or Connections > 100   // probe / scanner cadence
| order by Timestamp desc
```

### [LLM] Spring Cloud Config Server externally exposed and unpatched (CVE-2026-40982 / -40981 / -41002 / -41004)

`UC_4_8` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.process_name) as binaries values(Processes.user) as users from datamodel=Endpoint.Processes where (Processes.process_name="java.exe" OR Processes.process_name="java") AND (Processes.process="*spring-cloud-config-server*" OR Processes.process="*ConfigServerApplication*" OR Processes.process="*org.springframework.cloud.config.server*") by Processes.dest | `drop_dm_object_name(Processes)` | eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S") | join type=left dest [| tstats summariesonly=t count as InboundConns dc(All_Traffic.src) as DistinctSrc values(All_Traffic.src) as src_ips from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (8888,8761,8080) AND All_Traffic.action="allowed" by All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | rename dest as dest] | where InboundConns>0
```

**Defender KQL:**
```kql
// Asset hunt — hosts running affected Spring Cloud Config Server with public-internet inbound on default ports
let SpringConfig = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName has "java" or InitiatingProcessFileName has "java"
    | where ProcessCommandLine has_any ("spring-cloud-config-server","ConfigServerApplication","org.springframework.cloud.config.server")
         or InitiatingProcessCommandLine has_any ("spring-cloud-config-server","ConfigServerApplication","org.springframework.cloud.config.server")
    | summarize FirstSeen = min(Timestamp), SampleCmd = any(coalesce(ProcessCommandLine, InitiatingProcessCommandLine)) by DeviceId, DeviceName;
let Listening = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("ListeningConnectionCreated","InboundConnectionAccepted","ConnectionSuccess")
    | where LocalPort in (8888, 8761, 8080, 8443)
    | summarize InboundConns = count(),
                ExternalSources = dcountif(RemoteIP, RemoteIPType == "Public"),
                SampleExternalIPs = make_setif(RemoteIP, RemoteIPType == "Public", 25)
                by DeviceId, LocalPort;
SpringConfig
| join kind=inner Listening on DeviceId
| extend Affected = "CVE-2026-40982 / -40981 / -41002 / -41004"
| project FirstSeen, DeviceName, LocalPort, InboundConns, ExternalSources, SampleExternalIPs, SampleCmd, Affected
| order by ExternalSources desc, InboundConns desc
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

### Article-specific behavioural hunt — Critical Spring Vulnerabilities Expose Arbitrary Files and GCP Secrets

`UC_4_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Critical Spring Vulnerabilities Expose Arbitrary Files and GCP Secrets ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Critical Spring Vulnerabilities Expose Arbitrary Files and GCP Secrets
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-40982`, `CVE-2026-40981`, `CVE-2026-41002`, `CVE-2026-41004`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 9 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
