# [HIGH] Fake Call History Apps Stole Payments From Users After 7.3 Million Play Store Downloads

**Source:** The Hacker News
**Published:** 2026-05-08
**Article:** https://thehackernews.com/2026/05/fake-call-history-apps-stole-payments.html

## Threat Profile

Fake Call History Apps Stole Payments From Users After 7.3 Million Play Store Downloads 
 Ravie Lakshmanan  May 08, 2026 Android / Mobile Security 
Cybersecurity researchers have discovered fraudulent apps on the official Google Play Store for Android that falsely claimed to offer access to call histories for any phone number, only to trick users into joining a subscription that provided fake data and incurred financial loss.
The 28 apps have collectively racked up more than 7.3 million downlo…

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
- **T1195.002** — Compromise Software Supply Chain
- **T1660** — Phishing (Mobile)
- **T1655** — Masquerading (Mobile)
- **T1437** — Application Layer Protocol (Mobile)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Managed Android device has an ESET CallPhantom fake call-history Play Store app installed

`UC_141_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Endpoint.Inventory where Inventory.os="Android*" AND (Inventory.app_name IN ("calldetaila.ndcallhisto.rytogetan.ynumber","com.pixelxinnovation.manager","com.app.call.detail.history","sc.call.ofany.mobiledetail","com.cddhaduk.callerid.block.contact","com.basehistory.historydownloading","com.call.of.any.number","com.rajni.callhistory","com.callhistory.calldetails.callerids.callerhistory.callhostoryanynumber.getcall.history.callhistorymanager","com.callinformative.instantcallhistory.callhistorybluethem.callinfo","com.call.detail.caller.history","com.anycallinformation.datadetailswho.callinfo.numberfinder","com.callhistory.callhistoryyourgf","com.calldetails.smshistory.callhistoryofanynumber","com.callhistory.anynumber.chapfvor.history","com.callhistory.callhistoryany.call","com.name.factor","com.getanynumberofcallhistory.callhistoryofanynumber.findcalldetailsofanynumber","com.chdev.callhistory","com.phone.call.history.tracke","com.pdf.maker.pdfreader.pdfscanner","com.any.numbers.calls.history","com.callapp.historyero","all.callhistory.detail","com.easyranktools.callhistoryforanynumber","com.sbpinfotech.findlocationofanynumber","callhistoryeditor.callhistory.numberdetails.calleridlocator","com.all_historydownload.anynumber.callhistorybackup")) by Inventory.dest Inventory.user Inventory.app_name Inventory.app_version | `drop_dm_object_name(Inventory)` | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
let CallPhantomPackages = dynamic(["calldetaila.ndcallhisto.rytogetan.ynumber","com.pixelxinnovation.manager","com.app.call.detail.history","sc.call.ofany.mobiledetail","com.cddhaduk.callerid.block.contact","com.basehistory.historydownloading","com.call.of.any.number","com.rajni.callhistory","com.callhistory.calldetails.callerids.callerhistory.callhostoryanynumber.getcall.history.callhistorymanager","com.callinformative.instantcallhistory.callhistorybluethem.callinfo","com.call.detail.caller.history","com.anycallinformation.datadetailswho.callinfo.numberfinder","com.callhistory.callhistoryyourgf","com.calldetails.smshistory.callhistoryofanynumber","com.callhistory.anynumber.chapfvor.history","com.callhistory.callhistoryany.call","com.name.factor","com.getanynumberofcallhistory.callhistoryofanynumber.findcalldetailsofanynumber","com.chdev.callhistory","com.phone.call.history.tracke","com.pdf.maker.pdfreader.pdfscanner","com.any.numbers.calls.history","com.callapp.historyero","all.callhistory.detail","com.easyranktools.callhistoryforanynumber","com.sbpinfotech.findlocationofanynumber","callhistoryeditor.callhistory.numberdetails.calleridlocator","com.all_historydownload.anynumber.callhistorybackup"]);
DeviceTvmSoftwareInventory
| where Timestamp > ago(30d)
| where OSPlatform startswith "Android"
| where SoftwareName in~ (CallPhantomPackages) or SoftwareVendor in~ (CallPhantomPackages)
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, LoggedOnUsers, PublicIP) by DeviceId) on DeviceId
| project Timestamp, DeviceName, OSPlatform, OSVersion, SoftwareName, SoftwareVersion, SoftwareVendor, LoggedOnUsers, PublicIP
| order by Timestamp desc
```

### [LLM] CallPhantom APK SHA-1 hash observed in file telemetry (sideload / download)

`UC_141_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("799BB5127CA54239D3D4A14367DB3B712012CF14","56A4FD71D1E4BBA2C5C240BE0D794DCFF709D9EB") OR Filesystem.file_name="*.apk" AND Filesystem.file_hash IN ("799BB5127CA54239D3D4A14367DB3B712012CF14","56A4FD71D1E4BBA2C5C240BE0D794DCFF709D9EB")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
let CallPhantomApkSha1 = dynamic(["799BB5127CA54239D3D4A14367DB3B712012CF14","56A4FD71D1E4BBA2C5C240BE0D794DCFF709D9EB"]);
union isfuzzy=true
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA1 in~ (CallPhantomApkSha1)
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, FileOriginUrl, InitiatingProcessFileName, InitiatingProcessAccountName ),
  ( DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("FileDownloaded","BrowserLaunchedToOpenUrl")
    | where SHA1 in~ (CallPhantomApkSha1)
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, RemoteUrl, InitiatingProcessFileName, AccountName )
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


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
