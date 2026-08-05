# [HIGH] TP-Link patches Omada ZTP flaws allowing hackers to breach networks

**Source:** BleepingComputer
**Published:** 2026-08-04
**Article:** https://www.bleepingcomputer.com/news/security/tp-link-patches-omada-ztp-flaws-allowing-hackers-to-breach-networks/

## Threat Profile

TP-Link patches Omada ZTP flaws allowing hackers to breach networks 
By Bill Toulas 
August 4, 2026
06:18 PM
0 
TP-Link has patched 15 vulnerabilities in the zero-touch provisioning (ZTP) mechanism of its Omada network devices that could be chained with previously disclosed flaws to achieve remote code execution (RCE).
The flaws were uncovered by Forescout’s Vedere Labs researchers, who published the full details at the Black Hat USA security conference earlier today.
Omada is TP-Link’s business…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-7850`
- **CVE:** `CVE-2025-7851`
- **CVE:** `CVE-2025-9289`
- **CVE:** `CVE-2025-9290`
- **CVE:** `CVE-2025-9291`
- **CVE:** `CVE-2025-9292`
- **CVE:** `CVE-2025-9293`
- **CVE:** `CVE-2025-15544`
- **CVE:** `CVE-2025-15627`
- **CVE:** `CVE-2025-15628`
- **CVE:** `CVE-2025-15629`
- **CVE:** `CVE-2025-15630`
- **CVE:** `CVE-2025-15631`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1595.001** — Active Scanning: Scanning IP Blocks
- **T1595.002** — Active Scanning: Vulnerability Scanning
- **T1078.001** — Valid Accounts: Default Accounts
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1189** — Drive-by Compromise

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Internet-sourced enumeration of TP-Link Omada device-adoption ports (29810-29816)

`UC_19_4` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Traffic where (All_Traffic.dest_port>=29810 AND All_Traffic.dest_port<=29816) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port _time span=1h
| `drop_dm_object_name(All_Traffic)`
| where NOT cidrmatch("10.0.0.0/8",src) AND NOT cidrmatch("172.16.0.0/12",src) AND NOT cidrmatch("192.168.0.0/16",src)
| stats sum(count) as conns dc(dest_port) as distinct_ports values(dest_port) as dest_ports min(_time) as firstSeen max(_time) as lastSeen by src dest
| where conns > 20
| sort - conns
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort between (29810 .. 29816)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Private"
| summarize Conns=count(), DistinctPorts=dcount(RemotePort), DestPorts=make_set(RemotePort), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RemoteIP
| where Conns > 20     // 20 = enumeration threshold; a legit host adopts a device with a handful of packets, not a sweep
| order by Conns desc
```

### Rogue device adoption from the public internet to Omada controller (default-cred/race exploit)

`UC_19_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Traffic where (All_Traffic.dest_port=29812 OR All_Traffic.dest_port=29814) All_Traffic.action=allowed by All_Traffic.src All_Traffic.dest All_Traffic.dest_port _time span=1h
| `drop_dm_object_name(All_Traffic)`
| where NOT cidrmatch("10.0.0.0/8",src) AND NOT cidrmatch("172.16.0.0/12",src) AND NOT cidrmatch("192.168.0.0/16",src)
| stats sum(count) as conns min(_time) as firstSeen max(_time) as lastSeen by src dest dest_port
| sort - conns
```

### Stored XSS / JavaScript injection into Omada controller admin UI (CVE-2025-9289)

`UC_19_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web where (Web.dest_port=8043 OR Web.dest_port=8088 OR Web.dest_port=8843) by Web.src Web.dest Web.dest_port Web.http_method Web.url _time span=1h
| `drop_dm_object_name(Web)`
| where match(url, "(?i)(<script|javascript:|onerror=|onload=|%3Cscript|document\.cookie|String\.fromCharCode)")
| stats count min(_time) as firstSeen max(_time) as lastSeen values(url) as urls by src dest dest_port http_method
| sort - count
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-7850`, `CVE-2025-7851`, `CVE-2025-9289`, `CVE-2025-9290`, `CVE-2025-9291`, `CVE-2025-9292`, `CVE-2025-9293`, `CVE-2025-15544` _(+5 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, 7 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
