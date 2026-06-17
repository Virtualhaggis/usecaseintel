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
- **T1070.007** — Indicator Removal: Clear Network Connection History
- **T1485** — Data Destruction
- **T1098.003** — Account Manipulation: Additional Cloud Roles

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AWS CloudTrail StopLogging API invoked on a trail

`UC_125_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" All_Changes.action=success (All_Changes.command="StopLogging" OR All_Changes.object_category="trail" AND All_Changes.change_type="StopLogging") by All_Changes.user All_Changes.src All_Changes.object All_Changes.command All_Changes.user_agent | `drop_dm_object_name(All_Changes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(24h)
| where Application == "Amazon Web Services"
| where ActionType =~ "StopLogging"
| extend trailName = tostring(parse_json(tostring(RawEventData)).requestParameters.name)
| extend errorCode = tostring(parse_json(tostring(RawEventData)).errorCode)
| where isempty(errorCode)
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, UserAgent, trailName, ActionType, RawEventData
| order by Timestamp desc
```

### AWS CloudTrail trail deletion or event selector scope-narrowing

`UC_125_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" (All_Changes.command IN ("DeleteTrail","PutEventSelectors","UpdateTrail")) All_Changes.action=success by All_Changes.user All_Changes.user_agent All_Changes.src All_Changes.object All_Changes.command | `drop_dm_object_name(All_Changes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(24h)
| where Application == "Amazon Web Services"
| where ActionType in~ ("DeleteTrail", "PutEventSelectors", "UpdateTrail")
| extend raw = parse_json(tostring(RawEventData))
| extend errorCode = tostring(raw.errorCode)
| extend trailName = tostring(raw.requestParameters.name)
| extend selectors = tostring(raw.requestParameters.eventSelectors)
| where isempty(errorCode)
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, UserAgent, ActionType, trailName, selectors, RawEventData
| order by Timestamp desc
```

### S3 DeleteBucket targeting a CloudTrail log destination

`UC_125_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" All_Changes.command="DeleteBucket" All_Changes.action=success by All_Changes.user All_Changes.user_agent All_Changes.src All_Changes.object | `drop_dm_object_name(All_Changes)` | lookup cloudtrail_log_buckets bucket_name as object OUTPUT is_log_bucket | where is_log_bucket="true" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LogBuckets = dynamic(["cloudtrail-logs","aws-cloudtrail","audit-logs"]); // replace with org-specific list
CloudAppEvents
| where Timestamp > ago(24h)
| where Application == "Amazon Web Services"
| where ActionType in~ ("DeleteBucket","DeleteObject")
| extend raw = parse_json(tostring(RawEventData))
| extend bucketName = tostring(raw.requestParameters.bucketName)
| extend errorCode = tostring(raw.errorCode)
| where isempty(errorCode)
| where bucketName has_any (LogBuckets) or bucketName has_any ("cloudtrail","audit","logs")
| summarize Actions = make_set(ActionType), ObjectDeletes = countif(ActionType=~"DeleteObject"), BucketDelete = countif(ActionType=~"DeleteBucket") by bin(Timestamp,15m), AccountDisplayName, IPAddress, bucketName
| where BucketDelete > 0 or ObjectDeletes > 100
| order by Timestamp desc
```

### S3 PutBucketLogging disabled or target bucket removed

`UC_125_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" All_Changes.command="PutBucketLogging" All_Changes.action=success by All_Changes.user All_Changes.user_agent All_Changes.src All_Changes.object | `drop_dm_object_name(All_Changes)` | join type=left object [| inputlookup cloudtrail_log_buckets | rename bucket_name as object | fields object, is_log_bucket] | where is_log_bucket="true" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(24h)
| where Application == "Amazon Web Services"
| where ActionType =~ "PutBucketLogging"
| extend raw = parse_json(tostring(RawEventData))
| extend bucketName = tostring(raw.requestParameters.bucketName)
| extend loggingEnabled = tostring(raw.requestParameters.BucketLoggingStatus.LoggingEnabled)
| extend errorCode = tostring(raw.errorCode)
| where isempty(errorCode)
| where isempty(loggingEnabled) or loggingEnabled =~ "false"
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, UserAgent, bucketName, loggingEnabled, RawEventData
| order by Timestamp desc
```

### GCP Logging Sink disabled, deleted, or updated

`UC_125_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.vendor_product="Google Cloud Platform" (All_Changes.command IN ("google.logging.v2.ConfigServiceV2.UpdateSink","google.logging.v2.ConfigServiceV2.DeleteSink")) All_Changes.action=success by All_Changes.user All_Changes.src All_Changes.object All_Changes.command | `drop_dm_object_name(All_Changes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

### GCP log bucket deletion (DELETE_REQUESTED state)

`UC_125_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.vendor_product="Google Cloud Platform" All_Changes.command="google.logging.v2.ConfigServiceV2.DeleteBucket" All_Changes.action=success by All_Changes.user All_Changes.src All_Changes.object | `drop_dm_object_name(All_Changes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

### CloudWatch log group deleted or retention reduced

`UC_125_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" (All_Changes.command IN ("DeleteLogGroup","PutRetentionPolicy")) All_Changes.action=success by All_Changes.user All_Changes.src All_Changes.object All_Changes.command | `drop_dm_object_name(All_Changes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(24h)
| where Application == "Amazon Web Services"
| where ActionType in~ ("DeleteLogGroup","PutRetentionPolicy")
| extend raw = parse_json(tostring(RawEventData))
| extend errorCode = tostring(raw.errorCode)
| extend logGroupName = tostring(raw.requestParameters.logGroupName)
| extend retentionDays = toint(raw.requestParameters.retentionInDays)
| where isempty(errorCode)
| where ActionType =~ "DeleteLogGroup" or (ActionType =~ "PutRetentionPolicy" and retentionDays < 30)
| project Timestamp, AccountDisplayName, IPAddress, UserAgent, ActionType, logGroupName, retentionDays, RawEventData
| order by Timestamp desc
```

### IAM policy denies CloudTrail or logging read/write for other principals

`UC_125_11` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" (All_Changes.command IN ("PutUserPolicy","PutRolePolicy","PutGroupPolicy","CreatePolicyVersion","AttachUserPolicy","AttachRolePolicy")) All_Changes.action=success by All_Changes.user All_Changes.src All_Changes.object All_Changes.command _raw | `drop_dm_object_name(All_Changes)` | search _raw="*\"Effect\":\"Deny\"*" (_raw="*cloudtrail:*" OR _raw="*logs:*" OR _raw="*s3:GetObject*") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(24h)
| where Application == "Amazon Web Services"
| where ActionType in~ ("PutUserPolicy","PutRolePolicy","PutGroupPolicy","CreatePolicyVersion")
| extend raw = parse_json(tostring(RawEventData))
| extend doc = tostring(raw.requestParameters.policyDocument)
| where isempty(tostring(raw.errorCode))
| where doc has_cs "\"Effect\":\"Deny\""
  and (doc has_any ("cloudtrail:","logs:","s3:GetObject","guardduty:","config:","securityhub:"))
| project Timestamp, AccountDisplayName, IPAddress, UserAgent, ActionType, doc, RawEventData
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

Severity classified as **HIGH** based on: 12 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
