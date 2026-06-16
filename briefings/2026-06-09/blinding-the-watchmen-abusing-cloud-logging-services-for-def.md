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
- **T1070.004** — Indicator Removal: File Deletion
- **T1530** — Data from Cloud Storage
- **T1070.007** — Indicator Removal: Clear Network Connection History

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AWS CloudTrail trail disabled or deleted (StopLogging / DeleteTrail)

`UC_101_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=aws sourcetype="aws:cloudtrail" eventSource="cloudtrail.amazonaws.com" (eventName="StopLogging" OR eventName="DeleteTrail") NOT errorCode="*" | stats min(_time) as firstSeen, count by userIdentity.arn, userIdentity.type, sourceIPAddress, awsRegion, eventName, requestParameters.name | where count >= 1
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType in ("StopLogging", "DeleteTrail")
| extend TrailName = tostring(parse_json(tostring(RawEventData)).requestParameters.name)
| project Timestamp, AccountDisplayName, AccountObjectId, ActionType, TrailName, IPAddress, CountryCode, UserAgent, RawEventData
| order by Timestamp desc
```

### AWS CloudTrail S3 destination bucket emptied or deleted

`UC_101_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=aws sourcetype="aws:cloudtrail" eventSource="s3.amazonaws.com" eventName="DeleteBucket" NOT errorCode="*" | rename requestParameters.bucketName as bucketName | join type=left bucketName [ search index=aws sourcetype="aws:cloudtrail" eventSource="cloudtrail.amazonaws.com" eventName IN ("CreateTrail","UpdateTrail","GetTrail") | rename requestParameters.s3BucketName as bucketName | stats values(requestParameters.name) as trailName by bucketName ] | where isnotnull(trailName) | stats min(_time) as firstSeen, count by userIdentity.arn, sourceIPAddress, bucketName, trailName
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType == "DeleteBucket"
| extend BucketName = tostring(parse_json(tostring(RawEventData)).requestParameters.bucketName)
| where isnotempty(BucketName)
| project Timestamp, AccountDisplayName, AccountObjectId, BucketName, IPAddress, CountryCode, UserAgent, RawEventData
| order by Timestamp desc
```

### AWS CloudTrail UpdateTrail config tampering (S3 destination swap or validation disabled)

`UC_101_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=aws sourcetype="aws:cloudtrail" eventSource="cloudtrail.amazonaws.com" eventName="UpdateTrail" NOT errorCode="*" | rename requestParameters.name as trailName, requestParameters.s3BucketName as newBucket, requestParameters.enableLogFileValidation as logValidation | eval evasion=case(logValidation=="false","validation_disabled", isnotnull(newBucket),"destination_swapped", 1==1,"other") | where evasion!="other" | stats min(_time) as firstSeen, values(evasion) as evasionType, count by userIdentity.arn, sourceIPAddress, trailName, newBucket, logValidation
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType == "UpdateTrail"
| extend Raw = parse_json(tostring(RawEventData))
| extend TrailName = tostring(Raw.requestParameters.name)
| extend NewBucket = tostring(Raw.requestParameters.s3BucketName)
| extend LogValidation = tostring(Raw.requestParameters.enableLogFileValidation)
| where isnotempty(NewBucket) or LogValidation == "false"
| project Timestamp, AccountDisplayName, AccountObjectId, TrailName, NewBucket, LogValidation, IPAddress, UserAgent, RawEventData
| order by Timestamp desc
```

### GCP Cloud Logging sink disabled or deleted

`UC_101_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=gcp sourcetype="google:gcp:pubsub:message" (protoPayload.methodName="google.logging.v2.ConfigServiceV2.DeleteSink" OR (protoPayload.methodName="google.logging.v2.ConfigServiceV2.UpdateSink" AND protoPayload.request.sink.disabled=true)) | stats min(_time) as firstSeen, count by protoPayload.authenticationInfo.principalEmail, protoPayload.requestMetadata.callerIp, protoPayload.methodName, protoPayload.resourceName, resource.labels.project_id
```

### AWS CloudWatch Logs group deleted or retention shortened to 1 day

`UC_101_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=aws sourcetype="aws:cloudtrail" eventSource="logs.amazonaws.com" (eventName="DeleteLogGroup" OR (eventName="PutRetentionPolicy" AND requestParameters.retentionInDays<=1)) NOT errorCode="*" | rename requestParameters.logGroupName as logGroup, requestParameters.retentionInDays as retentionDays | stats min(_time) as firstSeen, values(eventName) as actions, values(retentionDays) as retentionDays, count by userIdentity.arn, sourceIPAddress, logGroup
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType in ("DeleteLogGroup", "PutRetentionPolicy")
| extend Req = parse_json(tostring(RawEventData)).requestParameters
| extend LogGroup = tostring(Req.logGroupName)
| extend RetentionDays = toint(Req.retentionInDays)
| where ActionType == "DeleteLogGroup" or (ActionType == "PutRetentionPolicy" and RetentionDays <= 1)
| project Timestamp, AccountDisplayName, AccountObjectId, ActionType, LogGroup, RetentionDays, IPAddress, UserAgent, RawEventData
| order by Timestamp desc
```

### AWS CloudTrail log file integrity validation disabled (EnableLogFileValidation=false)

`UC_101_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=aws sourcetype="aws:cloudtrail" eventSource="cloudtrail.amazonaws.com" (eventName="UpdateTrail" OR eventName="CreateTrail") requestParameters.enableLogFileValidation=false NOT errorCode="*" | rename requestParameters.name as trailName | stats min(_time) as firstSeen, count by userIdentity.arn, userIdentity.type, sourceIPAddress, awsRegion, trailName, eventName
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType in ("UpdateTrail", "CreateTrail")
| extend Req = parse_json(tostring(RawEventData)).requestParameters
| extend TrailName = tostring(Req.name)
| extend LogValidation = tostring(Req.enableLogFileValidation)
| where LogValidation == "false"
| project Timestamp, AccountDisplayName, AccountObjectId, ActionType, TrailName, LogValidation, IPAddress, UserAgent, RawEventData
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

Severity classified as **HIGH** based on: 10 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
