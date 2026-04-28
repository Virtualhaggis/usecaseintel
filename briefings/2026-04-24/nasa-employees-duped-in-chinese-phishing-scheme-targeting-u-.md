<!-- curated:true -->
# [HIGH] NASA Employees Duped in Chinese Phishing Scheme Targeting U.S. Defense Software

**Source:** The Hacker News
**Published:** 2026-04-24
**Article:** https://thehackernews.com/2026/04/nasa-employees-duped-in-chinese.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

NASA's OIG disclosed a multi-year **Chinese spear-phishing campaign** in which a Chinese national impersonated a U.S. researcher to extract sensitive information from NASA employees, government entities, universities, and private companies — in violation of **export control law**. The campaign targeted **defense software** specifically (likely simulation tools, satellite-control systems, ITAR-classified design files).

The technique mix referenced in the article — phishing links, attachments, PowerShell, VBA, system-binary proxy execution, and **clipboard injection (ClickFix / FakeCaptcha)** — is the standard 2025-2026 commodity-phishing kill chain. What's distinctive is the **persistence (years) and target selection (export-controlled IP)** — APT-class collection objectives wrapped in commodity TTPs.

We've upgraded severity to **HIGH** for two reasons:
1. Defense / aerospace / academic / R&D sectors are squarely in scope — multiple verticals.
2. The technique set is **the most common 2026 SOC detection backlog** — every detection below should be live in any mature SOC; if any is missing, that's the action item.

## Indicators of Compromise

- _The OIG report and a forthcoming DOJ indictment will name the operator and likely list specific domains, attachment hashes, and infrastructure._
- Hunt focus: phishing links from external senders impersonating researchers / academics; Office macros; ClickFix-style clipboard-paste-PowerShell execution.

## MITRE ATT&CK (analyst-validated)

- **T1566.001** — Spearphishing Attachment
- **T1566.002** — Spearphishing Link
- **T1656** — Impersonation
- **T1204.001** — User Execution: Malicious Link
- **T1204.002** — User Execution: Malicious File
- **T1204.004** — User Execution: Malicious Copy and Paste (the ClickFix vector)
- **T1059.001** — PowerShell
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1041** — Exfiltration Over C2 Channel

## Recommended SOC actions (priority-ordered)

1. **Confirm Office macro restrictions are enforced.** "Block macros from internet" GPO + ASR rule `3b576869-a4ec-4529-8536-b80a7769e899` (block Office from creating executable content). Two of the OIG kill chains depend on macros.
2. **Hunt Office-app-spawning-script chains.** This is the highest-leverage Office-attack detection in the SOC catalogue.
3. **Hunt ClickFix / FakeCaptcha clipboard-paste-PowerShell.** `explorer.exe` or `RuntimeBroker.exe` spawning PowerShell with `iex` / `Invoke-Expression` / `FromBase64` / `DownloadString` is high-fidelity.
4. **Phishing-URL telemetry**: correlate delivered emails with subsequent URL clicks. EmailEvents → UrlClickEvents in Defender; `All_Email` → `Web` in Splunk.
5. **Run a phish simulation** with researcher-impersonation theme — train the population that's targeted (R&D, engineering, exec assistants).
6. **Audit external sender domain anti-spoofing** — DMARC enforcement, lookalike-domain monitoring, display-name banner.
7. **Tag academic / R&D / national-lab roles as high-risk** for additional sandboxing of inbound attachments.

## Splunk SPL — Office app spawning LOLBin child

```spl
| tstats `summariesonly` count min(_time) AS firstTime max(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe",
                                              "outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe",
                                       "cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe",
                                       "wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name,
       Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
```

## Splunk SPL — ClickFix / FakeCaptcha clipboard-paste-PowerShell

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl *"
        OR Processes.process="*wget *" OR Processes.process="*Invoke-WebRequest*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — phishing email delivered → URL click correlation

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
| stats values(All_Email.subject) AS subjects, values(Web.url) AS clicked_urls,
        earliest(_time) AS first_seen, latest(_time) AS last_seen
        by All_Email.recipient, email_domain
```

## Splunk SPL — Office attachment opened → child process

```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.file_name!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.file_name, All_Email.subject
| rename All_Email.recipient AS user
| join type=inner user
    [| tstats `summariesonly` count
         from datamodel=Endpoint.Processes
         where Processes.parent_process_name IN ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
           AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                                            "mshta.exe","rundll32.exe","regsvr32.exe")
         by Processes.dest, Processes.user, Processes.parent_process_name,
            Processes.process_name, Processes.process
     | rename Processes.user AS user]
```

## Defender KQL — Office app spawning LOLBin child

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe",
                                         "outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe",
                       "mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe",
                       "certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — ClickFix / FakeCaptcha pattern

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex
    @"(?i)(iex |invoke-expression|frombase64|downloadstring|hxxp|curl |wget |invoke-webrequest)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — phishing email → click correlation

```kql
let LookbackDays = 30d;
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

## Defender KQL — attachment open → exec correlation

```kql
let LookbackDays = 30d;
let MalAttachments = EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | project NetworkMessageId, RecipientEmailAddress,
              AttachmentFileName = FileName, AttachmentSHA256 = SHA256;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                       "mshta.exe","rundll32.exe","regsvr32.exe")
| extend AccountUpn = tostring(parse_json(AdditionalFields).AccountUpn)
| join kind=inner MalAttachments on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AttachmentFileName, AttachmentSHA256
| order by Timestamp desc
```

## Why this matters for your SOC

The OIG report is a reminder that **espionage-grade objectives are achieved with commodity TTPs**. The defender posture isn't to find a magic ATP-bypass detection; it's to make sure all the **bread-and-butter detections** are live and tuned: Office-spawning-script, ClickFix-clipboard-paste, attachment-then-exec, link-click-from-external-sender. Run the queries above as a self-audit. If any returns "rule not deployed," that's a one-week build for the most common espionage and ransomware delivery vectors of the year. The aerospace/defense angle is sector-specific; the detections are universal.
