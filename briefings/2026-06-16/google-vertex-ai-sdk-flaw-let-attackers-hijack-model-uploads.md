# [CRIT] Google Vertex AI SDK Flaw Let Attackers Hijack Model Uploads via Bucket Squatting

**Source:** The Hacker News
**Published:** 2026-06-16
**Article:** https://thehackernews.com/2026/06/google-vertex-ai-sdk-flaw-let-attackers.html

## Threat Profile

Google Vertex AI SDK Flaw Let Attackers Hijack Model Uploads via Bucket Squatting 
 Swati Khandelwal  Jun 16, 2026 Machine Learning / Cloud Security 
A flaw in the Google Cloud Vertex AI SDK for Python let an attacker with no access to a victim's project hijack the victim's machine learning model upload and run code inside Google's serving infrastructure.
Palo Alto Networks Unit 42, which found and reported the bug through Google's bug bounty program, calls the technique " Pickle in the Middle…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-2473`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1583.001** — Acquire Infrastructure: Domains
- **T1583.004** — Acquire Infrastructure: Server
- **T1195.003** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1537** — Transfer Data to Cloud Account
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1041** — Exfiltration Over C2 Channel
- **T1546** — Event Triggered Execution
- **T1525** — Implant Internal Image
- **T1565.001** — Data Manipulation: Stored Data Manipulation
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1530** — Data from Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GCP Storage bucket creation matching Vertex AI predictable staging name pattern

`UC_110_6` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`gcp_pubsub_message` sourcetype=google:gcp:pubsub:message data.protoPayload.serviceName="storage.googleapis.com" data.protoPayload.methodName="storage.buckets.create" 
| rename data.protoPayload.resourceName as resourceName data.protoPayload.authenticationInfo.principalEmail as principal data.resource.labels.project_id as creatorProject data.protoPayload.requestMetadata.callerIp as callerIp
| rex field=resourceName "projects/_/buckets/(?<bucketName>[^/]+)"
| where match(bucketName, "(?i)-vertex-staging-(us|eu|asia|northamerica|southamerica|australia)-") OR match(bucketName, "(?i)^cloud-ai-platform-[a-f0-9-]{8,}$")
| eval embedded_project=mvindex(split(bucketName,"-vertex-staging-"),0)
| where embedded_project!=creatorProject
| table _time creatorProject embedded_project bucketName principal callerIp
```

### Vertex AI Model.upload sourcing artifact from cross-project / unverified staging bucket

`UC_110_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`gcp_pubsub_message` sourcetype=google:gcp:pubsub:message data.protoPayload.serviceName="aiplatform.googleapis.com" (data.protoPayload.methodName="google.cloud.aiplatform.v1.ModelService.UploadModel" OR data.protoPayload.methodName="google.cloud.aiplatform.v1.JobService.CreateCustomJob" OR data.protoPayload.methodName="google.cloud.aiplatform.v1.PipelineService.CreateTrainingPipeline")
| rename data.resource.labels.project_id as callerProject data.protoPayload.authenticationInfo.principalEmail as principal
| spath input=data.protoPayload.request output=artifactUri path=model.artifactUri
| spath input=data.protoPayload.request output=containerUri path=model.containerSpec.imageUri
| spath input=data.protoPayload.request output=pkgUris path=trainingPipeline.trainingTaskInputs.pythonPackageSpec.packageUris
| eval bucketUri=coalesce(artifactUri,pkgUris)
| rex field=bucketUri "gs://(?<bucketName>[^/]+)/"
| eval embedded_project=mvindex(split(bucketName,"-vertex-staging-"),0)
| where (isnotnull(embedded_project) AND embedded_project!=callerProject) OR match(bucketName, "(?i)^cloud-ai-platform-")=false AND bucketName!=callerProject."-vertex-staging-*"
| table _time callerProject principal bucketName artifactUri pkgUris
```

### google-cloud-aiplatform SDK version < 1.148.0 in use on workstation or CI

`UC_110_8` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name in ("pip.exe","pip","pip3","pip3.exe","poetry.exe","poetry","uv.exe","uv") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| where match(process, "(?i)(install|add|sync).*google-cloud-aiplatform")
| rex field=process "google-cloud-aiplatform(?:==|<=|<)(?<version>[0-9]+\.[0-9]+\.[0-9]+)"
| eval major=mvindex(split(version,"."),0), minor=mvindex(split(version,"."),1), patch=mvindex(split(version,"."),2)
| where isnotnull(version) AND (major<"1" OR (major="1" AND minor<"148"))
| convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where FileName in~ ("pip.exe","pip3.exe","poetry.exe","uv.exe","python.exe","python3.exe")
| where ProcessCommandLine has "google-cloud-aiplatform"
| extend Version = extract(@"(?i)google-cloud-aiplatform(?:==|<=|<)(\d+\.\d+\.\d+)", 1, ProcessCommandLine)
| extend Major = toint(split(Version,".")[0]), Minor = toint(split(Version,".")[1])
| where isnotempty(Version) and (Major < 1 or (Major == 1 and Minor < 148))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, Version, InitiatingProcessFileName
| order by Timestamp desc
```

### Vertex AI serving container metadata token request followed by outbound POST to non-Google host

`UC_110_9` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*metadata.google.internal*" OR Web.dest="169.254.169.254") AND Web.url="*/computeMetadata/v1/instance/service-accounts*token*" by Web.src Web.user Web.url _time
| `drop_dm_object_name(Web)`
| eval metaTime=_time
| join type=inner src [
    | tstats `summariesonly` count from datamodel=Web.Web where Web.http_method="POST" Web.url!="*googleapis.com*" Web.url!="*google.com*" Web.url!="*gstatic.com*" Web.dest!="169.254.169.254" by Web.src Web.dest Web.url _time
    | `drop_dm_object_name(Web)`
    | rename _time as postTime, url as postUrl, dest as postDest
  ]
| where postTime >= metaTime AND postTime <= metaTime + 60
| table metaTime postTime src user url postUrl postDest
```

**Defender KQL:**
```kql
let WindowSec = 60;
let MetadataHits = DeviceNetworkEvents
    | where Timestamp > ago(1d)
    | where RemoteUrl has "metadata.google.internal" or RemoteIP == "169.254.169.254"
    | where RemoteUrl has_any ("/computeMetadata/v1/instance/service-accounts","/token")
    | project MetaTime = Timestamp, DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and not(RemoteUrl has_any ("googleapis.com","google.com","gstatic.com","appspot.com"))
| join kind=inner MetadataHits on DeviceId
| where Timestamp between (MetaTime .. MetaTime + WindowSec * 1s)
| project MetaTime, ExfilTime = Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, MetadataUrl = RemoteUrl1, ExfilRemoteIP = RemoteIP, ExfilRemoteUrl = RemoteUrl
| order by MetaTime desc
```

### Cloud Function created with GCS finalize trigger on Vertex AI staging bucket pattern

`UC_110_10` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`gcp_pubsub_message` sourcetype=google:gcp:pubsub:message (data.protoPayload.serviceName="cloudfunctions.googleapis.com" OR data.protoPayload.serviceName="eventarc.googleapis.com") (data.protoPayload.methodName="google.cloud.functions.v2.FunctionService.CreateFunction" OR data.protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.CreateFunction" OR data.protoPayload.methodName="google.cloud.eventarc.v1.Eventarc.CreateTrigger")
| rename data.protoPayload.authenticationInfo.principalEmail as principal data.resource.labels.project_id as project
| spath input=data.protoPayload.request output=triggerBucket path=function.eventTrigger.eventFilters{}.value
| spath input=data.protoPayload.request output=eventType path=function.eventTrigger.eventType
| where match(eventType, "google\.cloud\.storage\.object\.v1\.finalized") OR match(eventType, "google\.storage\.object\.finalize")
| where match(triggerBucket, "(?i)-vertex-staging-") OR match(triggerBucket, "(?i)^cloud-ai-platform-")
| table _time project principal triggerBucket eventType
```

### GCS object overwrite within 5s of upload on Vertex AI staging bucket

`UC_110_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`gcp_pubsub_message` sourcetype=google:gcp:pubsub:message data.protoPayload.serviceName="storage.googleapis.com" data.protoPayload.methodName="storage.objects.create"
| rename data.protoPayload.resourceName as objectName data.protoPayload.authenticationInfo.principalEmail as principal data.protoPayload.requestMetadata.callerIp as callerIp
| where match(objectName, "(?i)/-vertex-staging-|/cloud-ai-platform-")
| sort 0 _time
| streamstats current=t window=2 values(principal) as principals, values(callerIp) as ips, count as overwriteCount by objectName
| where overwriteCount>=2 AND mvcount(principals)>=2
| eval delta=_time-mvindex(_time,1)
| where delta<=5
| table _time objectName principals ips delta
```

### Vertex AI service-agent OAuth token used to access artifacts in a different tenant

`UC_110_12` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`gcp_pubsub_message` sourcetype=google:gcp:pubsub:message data.protoPayload.authenticationInfo.principalEmail="service-*@gcp-sa-aiplatform.iam.gserviceaccount.com" OR data.protoPayload.authenticationInfo.principalEmail="*-compute@developer.gserviceaccount.com"
| rename data.protoPayload.authenticationInfo.principalEmail as principal data.resource.labels.project_id as accessedProject data.protoPayload.serviceName as svc data.protoPayload.methodName as method data.protoPayload.resourceName as resource data.protoPayload.requestMetadata.callerIp as callerIp
| rex field=principal "service-(?<tokenProject>[0-9]+)@gcp-sa-aiplatform"
| rex field=principal "(?<tokenProjectCompute>[0-9]+)-compute@developer"
| eval expectedProject=coalesce(tokenProject,tokenProjectCompute)
| stats values(svc) values(method) values(resource) values(callerIp) by principal accessedProject expectedProject _time
| where expectedProject!=accessedProject
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-2473`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 13 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
