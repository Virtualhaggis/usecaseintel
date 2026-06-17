# [HIGH] Blinding the Watchmen: Abusing Cloud Logging Services for Defense Evasion and Visibility

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-06-09
**Article:** https://unit42.paloaltonetworks.com/cloud-logging-defense-evasion/

## Threat Profile

Threat Research Center 
Threat Research 
Cloud Cybersecurity Research 
Cloud Cybersecurity Research 
Blinding the Watchmen: Abusing Cloud Logging Services for Defense Evasion and Visibility 
12 min read 
Related Products Cortex Cortex Cloud Unit 42 Cloud Security Assessment 
By: Yahav Festinger 
Published: June 9, 2026 
Categories: Cloud Cybersecurity Research 
Threat Research 
Tags: AWS CloudTrail 
Cloud logging 
Defense evasion 
Google Cloud 
Log poisoning 
Log router 
Log storage 
S3 
Executi…

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
- **T1562.008** — Impair Defenses: Disable or Modify Cloud Logs
- **T1070.001** — Indicator Removal: Clear Windows Event Logs
- **T1485** — Data Destruction
- **T1098.003** — Account Manipulation: Additional Cloud Roles
- **T1526** — Cloud Service Discovery
- **T1619** — Cloud Storage Object Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AWS CloudTrail trail disabled or deleted (StopLogging / DeleteTrail / PutEventSelectors)

`UC_116_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.user) as user values(All_Changes.src) as src from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" (All_Changes.command="StopLogging" OR All_Changes.command="DeleteTrail" OR All_Changes.command="PutEventSelectors" OR All_Changes.command="UpdateTrail") All_Changes.status=success by All_Changes.object All_Changes.user All_Changes.src All_Changes.command | `drop_dm_object_name(All_Changes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Amazon Web Services"
| where ActionType in~ ("StopLogging", "DeleteTrail", "PutEventSelectors", "UpdateTrail")
| extend TrailName = tostring(RawEventData.requestParameters.name)
| extend ErrorCode = tostring(RawEventData.errorCode)
| where isempty(ErrorCode)
| project Timestamp, ActionType, AccountDisplayName, AccountId, IPAddress, CountryCode, TrailName, UserAgent, ActivityObjects, RawEventData
| order by Timestamp desc
```

### S3 bucket housing CloudTrail logs deleted or emptied (DeleteBucket / bulk DeleteObject)

`UC_116_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.user) as user values(All_Changes.src) as src from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" (All_Changes.command="DeleteBucket" OR All_Changes.command="DeleteObject" OR All_Changes.command="DeleteObjects" OR All_Changes.command="DeleteBucketPolicy") All_Changes.status=success by All_Changes.object All_Changes.user All_Changes.src All_Changes.command | search All_Changes.object IN ("*cloudtrail*","*audit*","*log*","*trail*") | `drop_dm_object_name(All_Changes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LogBucketHints = dynamic(["cloudtrail","audit","trail-logs","-logs-","logarchive"]);
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Amazon Web Services"
| where ActionType in~ ("DeleteBucket","DeleteObject","DeleteObjects","DeleteBucketPolicy")
| extend BucketName = tostring(RawEventData.requestParameters.bucketName)
| where isnotempty(BucketName)
| where BucketName has_any (LogBucketHints)
| extend ErrorCode = tostring(RawEventData.errorCode)
| where isempty(ErrorCode)
| summarize Events = count(), Actions = make_set(ActionType), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by BucketName, AccountDisplayName, IPAddress, UserAgent
| where Events >= 1
| order by LastSeen desc
```

### GCP Cloud Logging sink disabled via UpdateSink (disabled=true)

`UC_116_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.user) as user values(All_Changes.src) as src from datamodel=Change where All_Changes.vendor_product="Google Cloud Platform" (All_Changes.command="google.logging.v2.ConfigServiceV2.UpdateSink" OR All_Changes.command="google.logging.v2.ConfigServiceV2.DeleteSink" OR All_Changes.command="google.logging.v2.ConfigServiceV2.DeleteBucket") All_Changes.status=success by All_Changes.object All_Changes.user All_Changes.src All_Changes.command | `drop_dm_object_name(All_Changes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Google Cloud"
| where ActionType has_any ("UpdateSink","DeleteSink","DeleteBucket")
| extend MethodName = tostring(RawEventData.protoPayload.methodName)
| extend SinkDisabled = tostring(RawEventData.protoPayload.request.sink.disabled)
| extend ResourceName = tostring(RawEventData.protoPayload.resourceName)
| extend PrincipalEmail = tostring(RawEventData.protoPayload.authenticationInfo.principalEmail)
| extend CallerIp = tostring(RawEventData.protoPayload.requestMetadata.callerIp)
| where MethodName has_any ("ConfigServiceV2.UpdateSink","ConfigServiceV2.DeleteSink","ConfigServiceV2.DeleteBucket")
| where (MethodName has "UpdateSink" and SinkDisabled =~ "true") or MethodName has "DeleteSink" or MethodName has "DeleteBucket"
| project Timestamp, MethodName, PrincipalEmail, CallerIp, ResourceName, SinkDisabled, RawEventData
| order by Timestamp desc
```

### IAM policy attached or written granting logging-impairment permissions

`UC_116_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.user) as user values(All_Changes.src) as src values(All_Changes.object_attrs) as policy from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" (All_Changes.command="PutUserPolicy" OR All_Changes.command="PutRolePolicy" OR All_Changes.command="PutGroupPolicy" OR All_Changes.command="AttachUserPolicy" OR All_Changes.command="AttachRolePolicy" OR All_Changes.command="CreatePolicyVersion") by All_Changes.object All_Changes.user All_Changes.src All_Changes.command | search policy IN ("*cloudtrail:StopLogging*","*cloudtrail:DeleteTrail*","*cloudtrail:PutEventSelectors*","*logs:DeleteLogGroup*","*logs:DeleteLogStream*","*s3:DeleteBucket*","*s3:DeleteObject*","*AdministratorAccess*") | `drop_dm_object_name(All_Changes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LoggingActions = dynamic(["cloudtrail:StopLogging","cloudtrail:DeleteTrail","cloudtrail:PutEventSelectors","cloudtrail:UpdateTrail","logs:DeleteLogGroup","logs:DeleteLogStream","s3:DeleteBucket","s3:DeleteObject","kms:DisableKey","kms:ScheduleKeyDeletion"]);
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Amazon Web Services"
| where ActionType in~ ("PutUserPolicy","PutRolePolicy","PutGroupPolicy","AttachUserPolicy","AttachRolePolicy","CreatePolicyVersion")
| extend PolicyDoc = tostring(RawEventData.requestParameters.policyDocument)
| extend PolicyArn = tostring(RawEventData.requestParameters.policyArn)
| extend TargetUser = tostring(RawEventData.requestParameters.userName)
| extend TargetRole = tostring(RawEventData.requestParameters.roleName)
| where PolicyDoc has_any (LoggingActions) or PolicyArn has_any ("AdministratorAccess","PowerUserAccess")
| project Timestamp, ActionType, AccountDisplayName, IPAddress, TargetUser, TargetRole, PolicyArn, PolicyDoc
| order by Timestamp desc
```

### Enumeration of cloud logging configuration (CloudTrail DescribeTrails / GCP ListSinks burst)

`UC_116_8` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.command) as commands dc(All_Changes.command) as unique_commands from datamodel=Change where All_Changes.vendor_product IN ("AWS CloudTrail","Google Cloud Platform") (All_Changes.command="DescribeTrails" OR All_Changes.command="GetTrailStatus" OR All_Changes.command="ListTrails" OR All_Changes.command="GetEventSelectors" OR All_Changes.command="ListBuckets" OR All_Changes.command="GetBucketPolicy" OR All_Changes.command="GetBucketLogging" OR All_Changes.command="google.logging.v2.ConfigServiceV2.ListSinks" OR All_Changes.command="google.logging.v2.ConfigServiceV2.GetSink" OR All_Changes.command="google.logging.v2.ConfigServiceV2.ListBuckets") by All_Changes.user All_Changes.src span=10m | where unique_commands >= 4 | `drop_dm_object_name(All_Changes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let DiscoveryActions = dynamic(["DescribeTrails","GetTrailStatus","ListTrails","GetEventSelectors","ListBuckets","GetBucketPolicy","GetBucketLogging","ListSinks","GetSink","ListLogBuckets"]);
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has_any ("Amazon Web Services","Google Cloud")
| where ActionType has_any (DiscoveryActions)
| summarize UniqueActions = dcount(ActionType), Actions = make_set(ActionType, 20), Calls = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountDisplayName, AccountId, IPAddress, bin(Timestamp, 10m)
| where UniqueActions >= 4
| order by LastSeen desc
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

Severity classified as **HIGH** based on: 9 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
