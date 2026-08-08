# [CRIT] Over 4,400 Rockwell PLCs Exposed Online, 22 Found in Water Attack Cities

**Source:** The Hacker News
**Published:** 2026-08-06
**Article:** https://thehackernews.com/2026/08/over-4400-rockwell-plcs-exposed-online.html

## Threat Profile

Over 4,400 Rockwell PLCs Exposed Online, 22 Found in Water Attack Cities 
 Swati Khandelwal  Aug 06, 2026 OT Security / Vulnerability 
Forescout found 22 internet-facing Rockwell Automation programmable logic controllers (PLCs) in cities hit by recent cyberattacks on US water utilities. Nineteen used the same mobile carrier network.
Its August 3 scan counted 4,407 exposed Rockwell controllers worldwide, including 2,844 in the United States, but Forescout could not confirm any were compromised.…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2017-16740`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1133** — External Remote Services
- **T1595** — Active Scanning
- **T1046** — Network Service Discovery
- **T0845** — Program Upload
- **T0843** — Program Download
- **T1119** — Automated Collection

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Internet-facing inbound access to Rockwell EtherNet/IP & Modbus OT ports (44818/2222/502)

`UC_42_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (44818, 2222, 502) by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| search NOT (src=10.0.0.0/8 OR src=172.16.0.0/12 OR src=192.168.0.0/16 OR src=127.0.0.0/8 OR src=169.254.0.0/16)
| search (dest=10.0.0.0/8 OR dest=172.16.0.0/12 OR dest=192.168.0.0/16)
| where action!="blocked" AND action!="denied" AND action!="dropped"
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort in (44818, 2222, 502)
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessAccountName !endswith "$"
| summarize Connections=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Ports=make_set(RemotePort) by DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Connections desc
```

### External or internal enumeration of Rockwell OT services (EtherNet/IP / Modbus port sweep)

`UC_42_6` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(All_Traffic.dest) as distinct_dests, dc(All_Traffic.dest_port) as distinct_ports, count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (44818, 2222, 502, 102, 22) by All_Traffic.src, _time span=10m
| `drop_dm_object_name(All_Traffic)`
| search NOT (src=10.0.0.0/8 OR src=172.16.0.0/12 OR src=192.168.0.0/16)
| where distinct_dests>=10 OR distinct_ports>=4
| sort - distinct_dests
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemotePort in (44818, 2222, 502, 102)
| where ActionType == "ConnectionSuccess"
| summarize DistinctTargets=dcount(RemoteIP), Targets=make_set(RemoteIP, 50), Ports=make_set(RemotePort), Total=count() by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, bin(Timestamp, 10m)
| where DistinctTargets >= 10
| order by DistinctTargets desc
```

### Rockwell/Schneider/Siemens engineering software reaching a PLC over the public internet

`UC_42_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest) as dest, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (44818, 2222, 502) All_Traffic.app IN ("LogixDesigner.exe","Studio 5000.exe","RSLogix 5000.exe","RS5000.exe","RSLogix 500.exe","RSLogix500.exe","RSLinx.exe","Siemens.Automation.Portal.exe") by All_Traffic.src, All_Traffic.app, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| search NOT (dest=10.0.0.0/8 OR dest=172.16.0.0/12 OR dest=192.168.0.0/16 OR dest=127.0.0.0/8)
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - count
```

**Defender KQL:**
```kql
let EngExe = dynamic(["LogixDesigner.exe","Studio 5000.exe","RSLogix 5000.exe","RS5000.exe","RSLogix 500.exe","RSLogix500.exe","RSLinx.exe","Siemens.Automation.Portal.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (44818, 2222, 502)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ (EngExe)
    or InitiatingProcessVersionInfoCompanyName has_any ("Rockwell","Schneider Electric","Siemens")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessVersionInfoCompanyName, InitiatingProcessCommandLine, RemoteIP, RemotePort
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2017-16740`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
