# [CRIT] Azure AD Conditional Access Bypassed Via Phantom Device Registration and PRT Abuse

**Source:** Cyber Security News
**Published:** 2026-05-06
**Article:** https://cybersecuritynews.com/azure-ad-conditional-access-bypassed/

## Threat Profile

Home Cyber Security News 
Azure AD Conditional Access Bypassed Via Phantom Device Registration and PRT Abuse 
By Abinaya 
May 6, 2026 
Cloud identity security relies heavily on Microsoft Entra ID (formerly Azure AD) Conditional Access. It acts as the primary digital gatekeeper, checking user locations, calculating risk scores, and verifying device health before granting access.
However, an authorized red team engagement by Howler Cell recently revealed a critical attack path that entirely bypass…

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
- **T1098.005** — Account Manipulation: Device Registration
- **T1528** — Steal Application Access Token
- **T1556.007** — Modify Authentication Process: Hybrid Identity
- **T1087.004** — Account Discovery: Cloud Account
- **T1538** — Cloud Service Dashboard

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Device code flow auth to Device Registration Service after AADSTS53003 CA block (Storm-2372 / Howler Cell pattern)

`UC_7_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Authentication where Authentication.action=failure Authentication.signature_id="53003" by _time, Authentication.user, Authentication.src 
| `drop_dm_object_name(Authentication)` 
| rename _time as block_time, user as upn 
| join type=inner upn [
    | tstats summariesonly=t count from datamodel=Authentication where Authentication.action=success Authentication.app="Device Registration Service" by _time, Authentication.user, Authentication.src, Authentication.authentication_method 
    | `drop_dm_object_name(Authentication)` 
    | rename _time as success_time, user as upn 
    | search authentication_method="deviceCode" OR authentication_method="device_code" 
] 
| eval delta_min=round((success_time-block_time)/60,1) 
| where delta_min>=0 AND delta_min<=60 
| table block_time success_time delta_min upn src authentication_method
```

**Defender KQL:**
```kql
// Storm-2372 / Howler Cell entry: AADSTS53003 -> device-code auth to DRS, same user, within 1h
let CABlocks = AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode == 53003   // Access blocked by CA policy
    | project BlockTime = Timestamp, AccountUpn, AccountObjectId, BlockIP = IPAddress, BlockApp = Application;
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
// Device Registration Service AppId is the canonical DRS endpoint; ResourceDisplayName is also a fallback signal
| where ApplicationId =~ "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"
   or ResourceDisplayName has "Device Registration"
// device-code grant surfaces in AuthenticationProcessingDetails JSON as "Oauth Scope Info" / "Root Scope" plus protocol = deviceCode
| where tostring(AuthenticationProcessingDetails) has_any ("deviceCode", "device_code") 
   or tostring(AuthenticationDetails) has_any ("deviceCode", "device_code")
| join kind=inner CABlocks on AccountUpn
| where Timestamp between (BlockTime .. BlockTime + 1h)
| extend DelayMin = datetime_diff('minute', Timestamp, BlockTime)
| project BlockTime, SuccessTime = Timestamp, DelayMin,
          AccountUpn, BlockIP, SuccessIP = IPAddress,
          BlockApp, ResourceDisplayName, ClientAppUsed, ConditionalAccessStatus,
          IPDelta = iif(BlockIP != IPAddress, "YES", "no")
| order by SuccessTime desc
```

### [LLM] Phantom Entra ID device registration: non-Windows OS claiming hybrid Azure AD join

`UC_7_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Change where Change.action=created Change.object_category=device Change.change_type="AAD" by _time, Change.user, Change.object, Change.src, Change.result 
| `drop_dm_object_name(Change)` 
| search object="Add device" OR object="Add registered owner to device" 
| spath input=result path=targetResources{}.modifiedProperties{} output=props 
| mvexpand props 
| spath input=props 
| search displayName IN ("DeviceOSType","DeviceTrustType") 
| eval is_phantom=if((displayName="DeviceOSType" AND match(newValue,"(?i)Linux|Mac|Other|Unknown")) OR (displayName="DeviceTrustType" AND match(newValue,"(?i)ServerAd|Workplace|Hybrid")),"yes","no") 
| where is_phantom="yes" 
| table _time user object src displayName newValue
```

**Defender KQL:**
```kql
// Defender XDR has no first-party 'Add device' AuditLog table; CloudAppEvents surfaces the same activity from MCAS
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in~ ("Microsoft Azure", "Office 365", "Microsoft 365 admin center")
| where ActionType in~ ("Add device", "Add registered owner to device", "Add registered users to device")
| extend Raw = tostring(RawEventData)
| extend OSType  = extract(@'(?i)"DeviceOSType"\s*[:,].*?"newValue"\s*:\s*"\[?\\?"?([^"\]\\]+)', 1, Raw)
| extend TrustType = extract(@'(?i)"DeviceTrustType"\s*[:,].*?"newValue"\s*:\s*"\[?\\?"?([^"\]\\]+)', 1, Raw)
| extend IsCompliant = extract(@'(?i)"IsCompliant"\s*[:,].*?"newValue"\s*:\s*"\[?\\?"?([^"\]\\]+)', 1, Raw)
// Phantom device signature from the article: non-Windows OS asserting hybrid join, often without compliance attestation
| where (OSType matches regex "(?i)Linux|Mac|Other|Unknown")
     or (TrustType matches regex "(?i)ServerAd|Workplace" and OSType !has "Windows")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode,
          UserAgent, ActionType, OSType, TrustType, IsCompliant, ObjectName
```

### [LLM] Newly registered Entra ID device performs bulk Microsoft Graph directory enumeration within 1 hour

`UC_7_5` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t min(_time) as device_add_time values(Change.user) as actor from datamodel=Change where Change.change_type="AAD" Change.object="Add device" Change.action=created by Change.object_id 
| `drop_dm_object_name(Change)` 
| rename object_id as device_id 
| join type=inner actor [
    | tstats summariesonly=t count dc(Authentication.dest) as resources_hit values(Authentication.app) as apps from datamodel=Authentication where Authentication.action=success Authentication.app="Microsoft Graph" by _time span=5m Authentication.user 
    | `drop_dm_object_name(Authentication)` 
    | rename user as actor 
] 
| where _time>=device_add_time AND _time<=device_add_time+3600 
| where resources_hit>=20 OR count>=200 
| table device_add_time _time actor device_id resources_hit count apps
```

**Defender KQL:**
```kql
// New device registration -> same identity hits Microsoft Graph at high volume within 1h (PRT abuse / directory enum)
let NewDevices = CloudAppEvents
    | where Timestamp > ago(7d)
    | where ActionType in~ ("Add device", "Add registered owner to device")
    | project AddTime = Timestamp, ActorObjectId = AccountObjectId, ActorIP = IPAddress, NewDeviceName = ObjectName;
AADSignInEventsBeta
| where Timestamp > ago(7d)
// Microsoft Graph resource id
| where ResourceId =~ "00000003-0000-0000-c000-000000000000"
| where ErrorCode == 0
| join kind=inner NewDevices on $left.AccountObjectId == $right.ActorObjectId
| where Timestamp between (AddTime .. AddTime + 1h)
| summarize
    GraphCalls = count(),
    DistinctApps = dcount(Application),
    DistinctIPs = dcount(IPAddress),
    SampleIPs = make_set(IPAddress, 5),
    FirstCall = min(Timestamp),
    LastCall = max(Timestamp)
    by AccountUpn, AccountObjectId, AddTime, ActorIP, NewDeviceName
| extend BurstSeconds = datetime_diff('second', LastCall, FirstCall)
// Article says directory enum hit a 16k-user tenant — fan-out signal, not single call
| where GraphCalls >= 50 and BurstSeconds <= 3600
| order by GraphCalls desc
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

Severity classified as **CRIT** based on: 6 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
