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
- **T1219** — Remote Access Software
- **T1566.002** — Phishing: Spearphishing Link
- **T1583.001** — Acquire Infrastructure: Domains
- **T1111** — Multi-Factor Authentication Interception

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Diesel Vortex post-phish RMM install on freight/logistics endpoints (ScreenConnect, SimpleHelp, PDQ Connect, N-able, GoTo Resolve)

`UC_32_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name IN ("ScreenConnect.ClientSetup.exe","ScreenConnect.WindowsClient.exe","SimpleHelpCustomer.exe","Remote Access.exe","PDQConnectAgent.exe","PDQConnectAgent-Setup.exe","GoToResolve.exe","GoToAssist.exe","N-able_Take_Control_Setup.exe","BASupSrvc.exe","BASupSrvcCnfg.exe") OR Processes.process IN ("*ScreenConnect.ClientSetup*","*SimpleHelp*Customer*","*PDQConnectAgent*","*GoToResolve*","*N-able*Take*Control*")) by host Processes.user Processes.process Processes.process_name Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | where parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe","outlook.exe","explorer.exe","OneDrive.exe") OR like(process,"%\\Downloads\\%") OR like(process,"%\\AppData\\Local\\Temp\\%") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let rmm_binaries = dynamic(["screenconnect.clientsetup.exe","screenconnect.windowsclient.exe","simplehelpcustomer.exe","remote access.exe","pdqconnectagent.exe","pdqconnectagent-setup.exe","gotoresolve.exe","gotoassist.exe","n-able_take_control_setup.exe","basupsrvc.exe","basupsrvccnfg.exe"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ (rmm_binaries) or ProcessCommandLine has_any ("ScreenConnect.ClientSetup","SimpleHelpCustomer","PDQConnectAgent","GoToResolve","N-able","Take Control")
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","outlook.exe","explorer.exe","onedrive.exe")
   or FolderPath has_any (@"\Downloads\", @"\AppData\Local\Temp\", @"\AppData\Roaming\")
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, OSPlatform, DeviceName) by DeviceId) on DeviceId
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| sort by Timestamp desc
```

### [LLM] Diesel Vortex load-board phishing — typosquat navigation to DAT / Truckstop / Penske / EFS / Timocom lookalikes

`UC_32_4` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user values(Web.src) as src from datamodel=Web.Web where Web.url IN ("*dat-one*","*datone-*","*dat-truckstop*","*truckstop-*","*-truckstop*","*penske-*","*-penske*","*efs-llc*","*efsllc-*","*-efsllc*","*timocom-*","*-timocom*","*loadboard-*","*-loadboard*","*ratecon-*","*-ratecon*") AND NOT Web.url IN ("*.dat.com*","*.truckstop.com*","*.penskelogistics.com*","*.efsllc.com*","*.timocom.com*") by Web.dest Web.url Web.user Web.http_referrer Web.http_user_agent | `drop_dm_object_name(Web)` | rex field=url "https?://(?<host>[^/]+)" | eval brand=case(match(host,"(?i)dat[-_.]?(one|truck)"),"DAT", match(host,"(?i)truckstop"),"Truckstop", match(host,"(?i)penske"),"Penske", match(host,"(?i)efs[-_.]?llc|electronicfunds"),"EFS", match(host,"(?i)timocom"),"Timocom", true(),"loadboard-generic") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let brand_terms = dynamic(["dat-one","datone-","dat-truckstop","truckstop-","-truckstop","penske-","-penske","efs-llc","efsllc-","-efsllc","timocom-","-timocom","loadboard-","-loadboard","ratecon-","-ratecon"]);
let legit = dynamic(["dat.com","truckstop.com","penskelogistics.com","efsllc.com","timocom.com","timocom.de"]);
let hits =
  union
  (DeviceNetworkEvents
     | where Timestamp > ago(30d)
     | where ActionType in ("ConnectionSuccess","HttpConnectionInspected","DnsConnectionInspected")
     | extend host = tolower(coalesce(RemoteUrl, RemoteIP))
     | where host has_any (brand_terms)
     | where not(host has_any (legit))
     | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, host, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (UrlClickEvents
     | where Timestamp > ago(30d)
     | extend host = tolower(tostring(parse_url(Url).Host))
     | where host has_any (brand_terms)
     | where not(host has_any (legit))
     | project Timestamp, DeviceName="", AccountName=AccountUpn, host, RemoteUrl=Url, InitiatingProcessFileName="email-click", InitiatingProcessCommandLine=Url);
hits
| extend brand = case(host has_any ("dat-one","datone","dat-truckstop"),"DAT",
                     host has "truckstop","Truckstop",
                     host has "penske","Penske",
                     host has_any ("efs","electronicfunds"),"EFS",
                     host has "timocom","Timocom",
                     "loadboard-generic")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count(), Users=make_set(AccountName,25), Processes=make_set(InitiatingProcessFileName,10) by DeviceName, host, brand
| sort by FirstSeen desc
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

Severity classified as **HIGH** based on: 5 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
