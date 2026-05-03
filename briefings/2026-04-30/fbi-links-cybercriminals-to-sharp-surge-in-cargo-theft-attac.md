# [HIGH] FBI links cybercriminals to sharp surge in cargo theft attacks

**Source:** BleepingComputer
**Published:** 2026-04-30
**Article:** https://www.bleepingcomputer.com/news/security/fbi-links-cybercriminals-to-sharp-surge-in-cargo-theft-attacks/

## Threat Profile

FBI links cybercriminals to sharp surge in cargo theft attacks 
By Sergiu Gatlan 
April 30, 2026
12:32 PM
0 
The U.S. Federal Bureau of Investigation (FBI) warned the transportation and logistics industry of a sharp rise in cyber-enabled cargo theft, with estimated losses in the United States and Canada reaching nearly $725 million in 2025.
This represents a 60% surge in losses compared to the previous year, fueled by criminals increasingly using hacking and impersonation tactics to hijack high-…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1566.002** — Phishing: Spearphishing Link
- **T1219** — Remote Access Software
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1588.002** — Obtain Capabilities: Tool

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] RMM installer download from Diesel Vortex cargo-theft staging domains

`UC_36_3` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*nextgen1.net*" OR Web.url="*carrier-packets.net*" OR Web.url="*brokerpackets.com*" OR Web.url="*carriersetup.net*" OR Web.url="*dwssa.top*" OR Web.url="*officews101.com*") AND (Web.url="*.exe" OR Web.url="*.msi") by Web.dest Web.src Web.user Web.url Web.http_user_agent Web.http_method | `drop_dm_object_name(Web)` | rename firstTime as first_seen lastTime as last_seen | convert ctime(first_seen) ctime(last_seen)
```

**Defender KQL:**
```kql
let _staging = dynamic(["nextgen1.net","carrier-packets.net","brokerpackets.com","carriersetup.net","dwssa.top","officews101.com"]);
let _rmm = dynamic(["screenconnect.clientsetup.exe","screenconnect.windowsclient.exe","remote workforce client.exe","simplehelpcustomer.exe","simplehelpservice.exe","simple-service.exe","pdq-agent.exe","fleetdeck.installer.exe","fleetdeck.agent.exe","n-able-take-control.exe","logmeinrescuecalling.exe","client32.exe","strwinclt.exe"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed")
| where (FileName endswith ".exe" or FileName endswith ".msi")
| where FileOriginUrl has_any (_staging) or FileOriginReferrerUrl has_any (_staging)
| extend IsKnownRMM = iif(FileName has_any (_rmm), "yes", "no")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          FileName, FolderPath, SHA256, FileOriginUrl, FileOriginReferrerUrl, IsKnownRMM
| order by Timestamp desc
```

### [LLM] ScreenConnect / SimpleHelp C2 to cargo-theft cluster infrastructure

`UC_36_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("185.80.234.36","147.45.218.66") OR All_Traffic.dest IN ("dwssa.top","officews101.com","instance-hirb01-relay.screenconnect.com")) by All_Traffic.src All_Traffic.src_ip All_Traffic.user All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.transport All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | rename firstTime as first_seen lastTime as last_seen | convert ctime(first_seen) ctime(last_seen)
```

**Defender KQL:**
```kql
let _c2_domains = dynamic(["dwssa.top","officews101.com","instance-hirb01-relay.screenconnect.com"]);
let _c2_ips = dynamic(["185.80.234.36","147.45.218.66"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl has_any (_c2_domains)) or (RemoteIP in (_c2_ips))
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessSHA256, RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType
| order by Timestamp desc
```

### [LLM] NirSoft WebBrowserPassView spawned by RMM agent on logistics endpoint

`UC_36_5` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="WebBrowserPassView.exe" OR Processes.original_file_name="WebBrowserPassView.exe" OR Processes.process IN ("*WebBrowserPassView*","* /stext *","* /scomma *","* /shtml *")) AND Processes.parent_process_name IN ("ScreenConnect.WindowsClient.exe","ScreenConnect.ClientService.exe","Remote Workforce Client.exe","SimpleHelpCustomer.exe","SimpleHelpService.exe","pdq-agent.exe","FleetDeck.Agent.exe","LogMeInRescueCalling.exe","client32.exe","strwinclt.exe","WindowsAgent.exe","Take Control Agent.exe") by host Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | rename firstTime as first_seen lastTime as last_seen | convert ctime(first_seen) ctime(last_seen)
```

**Defender KQL:**
```kql
let _rmm_processes = dynamic(["screenconnect.windowsclient.exe","screenconnect.clientservice.exe","remote workforce client.exe","simplehelpcustomer.exe","simplehelpservice.exe","pdq-agent.exe","fleetdeck.agent.exe","logmeinrescuecalling.exe","client32.exe","strwinclt.exe","windowsagent.exe","take control agent.exe"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName =~ "WebBrowserPassView.exe"
    or ProcessVersionInfoOriginalFileName =~ "WebBrowserPassView.exe"
    or ProcessVersionInfoFileDescription has "WebBrowserPassView"
    or (ProcessVersionInfoCompanyName has "NirSoft" and ProcessCommandLine has_any ("/stext","/scomma","/shtml"))
    or ProcessCommandLine has_any ("WebBrowserPassView"," /stext "," /scomma "," /shtml ")
| where InitiatingProcessFileName in~ (_rmm_processes) or InitiatingProcessParentFileName in~ (_rmm_processes)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
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


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
