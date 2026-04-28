# [CRIT] Microsoft: New Remote Desktop warnings may display incorrectly

**Source:** BleepingComputer
**Published:** 2026-04-28
**Article:** https://www.bleepingcomputer.com/news/microsoft/microsoft-new-remote-desktop-warnings-may-display-incorrectly/

## Threat Profile

Microsoft: New Remote Desktop warnings may display incorrectly 
By Sergiu Gatlan 
April 28, 2026
05:51 AM
0 
Microsoft has confirmed a new issue causing newly introduced Windows security warnings to display incorrectly when opening Remote Desktop (.rdp) files.
This known issue impacts all supported Windows versions, including Windows 11 ( KB5083768 & KB5083769), Windows 10 ( KB5082200 ), and Windows Server ( KB5082063 ).
As Microsoft explains in updates to the original advisories, "the security …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.001** — PowerShell
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Suspicious URL click in email — phishing landing page

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.action="delivered" AND All_Email.url!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.url, All_Email.subject
| rex field=All_Email.url "https?://(?<email_domain>[^/]+)"
| join type=inner email_domain
    [| tstats `summariesonly` count
        from datamodel=Web
        where Web.action="allowed"
        by Web.src, Web.dest, Web.url, Web.user
     | rex field=Web.url "https?://(?<email_domain>[^/]+)"]
| stats values(All_Email.subject) as subject, values(Web.url) as clicked_url,
        earliest(_time) as first_seen, latest(_time) as last_seen
        by All_Email.recipient, email_domain
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let DeliveredEmails = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where DeliveryAction == "Delivered"
    | project NetworkMessageId, Subject, SenderFromAddress, RecipientEmailAddress,
              EmailTimestamp = Timestamp;
EmailUrlInfo
| where Timestamp > ago(LookbackDays)
| join kind=inner DeliveredEmails on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType == "ClickAllowed"
    | project Url, ClickTimestamp = Timestamp, AccountUpn, IPAddress
  ) on Url
| project ClickTimestamp, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, IPAddress
| order by ClickTimestamp desc
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
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
