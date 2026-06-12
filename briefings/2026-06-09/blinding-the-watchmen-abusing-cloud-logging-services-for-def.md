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
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1562.008** — Impair Defenses: Disable or Modify Cloud Logs
- **T1485** — Data Destruction
- **T1070.007** — Indicator Removal: Clear Network Connection History and Configurations

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AWS CloudTrail trail tampering — StopLogging, DeleteTrail, or UpdateTrail disabling log validation/destination

`UC_59_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object) as trail values(All_Changes.src) as src_ip values(All_Changes.user) as user from datamodel=Change.All_Changes where All_Changes.vendor_product="AWS CloudTrail" AND (All_Changes.action IN ("StopLogging","DeleteTrail") OR (All_Changes.action="UpdateTrail" AND (All_Changes.change_type="audit" OR All_Changes.object_attrs.EnableLogFileValidation="false" OR All_Changes.object_attrs.S3BucketName=*))) by All_Changes.action All_Changes.object All_Changes.user All_Changes.src | `drop_dm_object_name(All_Changes)` | where user!="AWSServiceRoleForCloudTrail" | sort - lastTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType in ("StopLogging", "DeleteTrail", "UpdateTrail")
| extend Raw = parse_json(tostring(RawEventData))
| extend TrailName = tostring(Raw.requestParameters.name),
         NewS3Bucket = tostring(Raw.requestParameters.s3BucketName),
         LogValidation = tostring(Raw.requestParameters.enableLogFileValidation),
         ErrorCode = tostring(Raw.errorCode),
         CallerArn = tostring(Raw.userIdentity.arn),
         CallerType = tostring(Raw.userIdentity.type)
| where isempty(ErrorCode)
| where ActionType != "UpdateTrail" or (LogValidation =~ "false" or isnotempty(NewS3Bucket))
| where CallerType != "AWSService"
| project Timestamp, ActionType, TrailName, NewS3Bucket, LogValidation, CallerArn, CallerType, IPAddress, CountryCode, AccountDisplayName
| order by Timestamp desc
```

### AWS S3 bucket deletion targeting an active CloudTrail log destination

`UC_59_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.user) as user values(All_Changes.src) as src_ip from datamodel=Change.All_Changes where All_Changes.vendor_product="AWS CloudTrail" AND All_Changes.action="DeleteBucket" by All_Changes.object All_Changes.user All_Changes.src | `drop_dm_object_name(All_Changes)` | rename object as deleted_bucket | join type=inner deleted_bucket [ | tstats `summariesonly` values(All_Changes.object) as trail values(All_Changes.object_attrs.S3BucketName) as deleted_bucket from datamodel=Change.All_Changes where All_Changes.vendor_product="AWS CloudTrail" AND All_Changes.action IN ("CreateTrail","UpdateTrail","GetTrail") by All_Changes.object_attrs.S3BucketName | rename All_Changes.object_attrs.S3BucketName as deleted_bucket ] | sort - lastTime
```

**Defender KQL:**
```kql
let LogDestBuckets = CloudAppEvents
    | where Timestamp > ago(90d)
    | where Application == "Amazon Web Services"
    | where ActionType in ("CreateTrail", "UpdateTrail", "GetTrail")
    | extend Raw = parse_json(tostring(RawEventData))
    | extend Bucket = tostring(Raw.requestParameters.s3BucketName)
    | where isnotempty(Bucket)
    | summarize by Bucket;
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType == "DeleteBucket"
| extend Raw = parse_json(tostring(RawEventData))
| extend DeletedBucket = tostring(Raw.requestParameters.bucketName),
         ErrorCode = tostring(Raw.errorCode),
         CallerArn = tostring(Raw.userIdentity.arn),
         UserAgent = tostring(Raw.userAgent)
| where isempty(ErrorCode)
| where DeletedBucket in (LogDestBuckets)
| project Timestamp, DeletedBucket, CallerArn, UserAgent, IPAddress, CountryCode
| order by Timestamp desc
```

### AWS CloudWatch Logs group deletion or retention shortened on audit-tier log groups

`UC_59_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.user) as user values(All_Changes.src) as src_ip values(All_Changes.object_attrs.retentionInDays) as retention from datamodel=Change.All_Changes where All_Changes.vendor_product="AWS CloudTrail" AND All_Changes.action IN ("DeleteLogGroup","PutRetentionPolicy") AND (All_Changes.object IN ("/aws/cloudtrail/*","/aws/guardduty/*","/aws/vpc/flowlogs/*","/aws/lambda/*","CloudTrail/*") OR All_Changes.object="*cloudtrail*" OR All_Changes.object="*audit*" OR All_Changes.object="*guardduty*") by All_Changes.action All_Changes.object All_Changes.user All_Changes.src | `drop_dm_object_name(All_Changes)` | where action="DeleteLogGroup" OR (action="PutRetentionPolicy" AND retention<=7) | sort - lastTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType in ("DeleteLogGroup", "PutRetentionPolicy")
| extend Raw = parse_json(tostring(RawEventData))
| extend LogGroupName = tostring(Raw.requestParameters.logGroupName),
         RetentionDays = toint(Raw.requestParameters.retentionInDays),
         CallerArn = tostring(Raw.userIdentity.arn),
         CallerType = tostring(Raw.userIdentity.type),
         ErrorCode = tostring(Raw.errorCode)
| where isempty(ErrorCode)
| where CallerType != "AWSService"
| where LogGroupName has_any ("cloudtrail", "guardduty", "vpcflowlog", "audit", "securityhub", "/aws/lambda/")
| where ActionType == "DeleteLogGroup" or RetentionDays <= 7
| project Timestamp, ActionType, LogGroupName, RetentionDays, CallerArn, IPAddress, CountryCode
| order by Timestamp desc
```

### GCP Cloud Logging sink disabled or deleted

`UC_59_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.user) as user values(All_Changes.src) as src_ip values(All_Changes.object) as sink from datamodel=Change.All_Changes where All_Changes.vendor_product="GCP" AND (All_Changes.action="google.logging.v2.ConfigServiceV2.DeleteSink" OR (All_Changes.action="google.logging.v2.ConfigServiceV2.UpdateSink" AND All_Changes.object_attrs.disabled="true")) by All_Changes.action All_Changes.object All_Changes.user All_Changes.src | `drop_dm_object_name(All_Changes)` | where user!="system" | sort - lastTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Google Cloud Platform"
| where ActionType in ("google.logging.v2.ConfigServiceV2.DeleteSink",
                       "google.logging.v2.ConfigServiceV2.UpdateSink")
| extend Raw = parse_json(tostring(RawEventData))
| extend MethodName = tostring(Raw.protoPayload.methodName),
         SinkName = tostring(Raw.protoPayload.resourceName),
         CallerEmail = tostring(Raw.protoPayload.authenticationInfo.principalEmail),
         CallerIp = tostring(Raw.protoPayload.requestMetadata.callerIp),
         Disabled = tostring(Raw.protoPayload.request.sink.disabled),
         UpdateMask = tostring(Raw.protoPayload.request.updateMask)
| where ActionType == "google.logging.v2.ConfigServiceV2.DeleteSink"
     or (ActionType == "google.logging.v2.ConfigServiceV2.UpdateSink" and (Disabled =~ "true" or UpdateMask has "disabled"))
| where CallerEmail !endswith "gserviceaccount.com" or CallerEmail has "compute@developer"
| project Timestamp, MethodName, SinkName, CallerEmail, CallerIp, Disabled, UpdateMask
| order by Timestamp desc
```

### GCP Cloud Logging bucket deletion (DELETE_REQUESTED state)

`UC_59_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.user) as user values(All_Changes.src) as src_ip values(All_Changes.object) as bucket from datamodel=Change.All_Changes where All_Changes.vendor_product="GCP" AND All_Changes.action="google.logging.v2.ConfigServiceV2.DeleteBucket" by All_Changes.object All_Changes.user All_Changes.src | `drop_dm_object_name(All_Changes)` | where user!="system" | sort - lastTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Google Cloud Platform"
| where ActionType == "google.logging.v2.ConfigServiceV2.DeleteBucket"
| extend Raw = parse_json(tostring(RawEventData))
| extend BucketName = tostring(Raw.protoPayload.resourceName),
         CallerEmail = tostring(Raw.protoPayload.authenticationInfo.principalEmail),
         CallerIp = tostring(Raw.protoPayload.requestMetadata.callerIp),
         Severity = tostring(Raw.severity)
| where Severity != "ERROR"
| where CallerEmail !endswith "gserviceaccount.com" or CallerEmail has "compute@developer"
| project Timestamp, BucketName, CallerEmail, CallerIp, AccountDisplayName
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

Severity classified as **HIGH** based on: 9 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
