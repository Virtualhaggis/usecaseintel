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
- **T1485** — Data Destruction

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AWS CloudTrail StopLogging API invocation (logging disablement)

`UC_130_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object) as trail_name values(All_Changes.command) as command from datamodel=Change where All_Changes.action="stopped" All_Changes.object_category="AWS CloudTrail" OR (All_Changes.vendor_product="AWS CloudTrail" All_Changes.command="StopLogging") by All_Changes.user All_Changes.src All_Changes.vendor_account All_Changes.vendor_region
| `drop_dm_object_name("All_Changes")`
| where firstTime > relative_time(now(), "-24h")
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(24h)
| where Application in ("Amazon Web Services", "AWS")
| where ActionType =~ "StopLogging"
   or (ActionType has "StopLogging" and ObjectType has_any ("Trail","CloudTrail"))
| extend RawData = parse_json(RawEventData)
| extend TrailName = tostring(RawData.requestParameters.name),
         CallerType = tostring(RawData.userIdentity.type),
         CallerArn = tostring(RawData.userIdentity.arn),
         ErrorCode = tostring(RawData.errorCode)
| where isempty(ErrorCode)
| project Timestamp, AccountDisplayName, CallerType, CallerArn, IPAddress, CountryCode, TrailName, ObjectName, UserAgent, ActionType
| order by Timestamp desc
```

### AWS S3 DeleteBucket targeting a CloudTrail log destination bucket

`UC_130_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.command) as command values(All_Changes.object) as bucket from datamodel=Change where All_Changes.action="deleted" All_Changes.object_category="S3 Bucket" (All_Changes.object="*cloudtrail*" OR All_Changes.object="*-logs-*" OR All_Changes.object="*audit*" OR All_Changes.object="*log-archive*") by All_Changes.user All_Changes.src All_Changes.vendor_account All_Changes.vendor_region
| `drop_dm_object_name("All_Changes")`
| where firstTime > relative_time(now(), "-24h")
```

**Defender KQL:**
```kql
let LogBucketHints = dynamic(["cloudtrail","audit","log-archive","-logs-","securitylogs","loggingbucket"]);
CloudAppEvents
| where Timestamp > ago(24h)
| where Application in ("Amazon Web Services","AWS")
| where ActionType =~ "DeleteBucket"
| extend RawData = parse_json(RawEventData)
| extend BucketName = tolower(tostring(RawData.requestParameters.bucketName)),
         CallerType = tostring(RawData.userIdentity.type),
         CallerArn = tostring(RawData.userIdentity.arn),
         ErrorCode = tostring(RawData.errorCode)
| where isempty(ErrorCode)
| where BucketName has_any (LogBucketHints)
| project Timestamp, AccountDisplayName, CallerType, CallerArn, IPAddress, CountryCode, BucketName, UserAgent
| order by Timestamp desc
```

### AWS CloudTrail DeleteTrail removing the trail configuration

`UC_130_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object) as trail_name from datamodel=Change where All_Changes.action="deleted" All_Changes.object_category="AWS CloudTrail" OR (All_Changes.vendor_product="AWS CloudTrail" All_Changes.command="DeleteTrail") by All_Changes.user All_Changes.src All_Changes.vendor_account All_Changes.vendor_region
| `drop_dm_object_name("All_Changes")`
| where firstTime > relative_time(now(), "-24h")
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(24h)
| where Application in ("Amazon Web Services","AWS")
| where ActionType =~ "DeleteTrail"
| extend RawData = parse_json(RawEventData)
| extend TrailName = tostring(RawData.requestParameters.name),
         CallerType = tostring(RawData.userIdentity.type),
         CallerArn = tostring(RawData.userIdentity.arn),
         ErrorCode = tostring(RawData.errorCode)
| where isempty(ErrorCode)
| project Timestamp, AccountDisplayName, CallerType, CallerArn, IPAddress, CountryCode, TrailName, UserAgent
| order by Timestamp desc
```

### GCP Cloud Logging sink disabled via logging.sinks.update

`UC_130_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`gcp_pubsub` protoPayload.methodName="google.logging.v2.ConfigServiceV2.UpdateSink" "protoPayload.request.sink.disabled"=true
| rename protoPayload.authenticationInfo.principalEmail as principal, protoPayload.requestMetadata.callerIp as src_ip, protoPayload.request.sink.name as sink_name, protoPayload.request.sink.destination as sink_destination, resource.labels.project_id as project_id
| stats min(_time) as firstTime max(_time) as lastTime count by principal, src_ip, sink_name, sink_destination, project_id
| where firstTime > relative_time(now(), "-24h")
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(24h)
| where Application in ("Google Cloud Platform","Google Cloud")
| where ActionType has "UpdateSink" or ActionType =~ "google.logging.v2.ConfigServiceV2.UpdateSink"
| extend RawData = parse_json(RawEventData)
| extend SinkName = tostring(RawData.protoPayload.request.sink.name),
         SinkDestination = tostring(RawData.protoPayload.request.sink.destination),
         Disabled = tobool(RawData.protoPayload.request.sink.disabled),
         Principal = tostring(RawData.protoPayload.authenticationInfo.principalEmail),
         CallerIp = tostring(RawData.protoPayload.requestMetadata.callerIp),
         ProjectId = tostring(RawData.resource.labels.project_id)
| where Disabled == true
| project Timestamp, Principal, CallerIp, ProjectId, SinkName, SinkDestination, AccountDisplayName, IPAddress
| order by Timestamp desc
```

### GCP log bucket deletion via logging.buckets.delete (DELETE_REQUESTED)

`UC_130_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`gcp_pubsub` protoPayload.methodName="google.logging.v2.ConfigServiceV2.DeleteBucket"
| rename protoPayload.authenticationInfo.principalEmail as principal, protoPayload.requestMetadata.callerIp as src_ip, protoPayload.resourceName as bucket_resource, resource.labels.project_id as project_id
| where NOT match(principal, "(?i)gserviceaccount\.com$") OR match(principal, "(?i)(compute@developer|cloudservices@cloudservices)\.gserviceaccount\.com")=false
| stats min(_time) as firstTime max(_time) as lastTime count by principal, src_ip, bucket_resource, project_id
| where firstTime > relative_time(now(), "-24h")
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(24h)
| where Application in ("Google Cloud Platform","Google Cloud")
| where ActionType has "DeleteBucket" and ActionType has "logging"
   or ActionType =~ "google.logging.v2.ConfigServiceV2.DeleteBucket"
| extend RawData = parse_json(RawEventData)
| extend BucketResource = tostring(RawData.protoPayload.resourceName),
         Principal = tostring(RawData.protoPayload.authenticationInfo.principalEmail),
         CallerIp = tostring(RawData.protoPayload.requestMetadata.callerIp),
         ProjectId = tostring(RawData.resource.labels.project_id),
         ErrorCode = tostring(RawData.protoPayload.status.code)
| where ErrorCode in ("","0")
| project Timestamp, Principal, CallerIp, ProjectId, BucketResource, AccountDisplayName, IPAddress
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

Severity classified as **HIGH** based on: 9 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
