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
- **T1583.006** — Acquire Infrastructure: Web Services
- **T1195.002** — Compromise Software Supply Chain
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1537** — Transfer Data to Cloud Account
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1565.001** — Stored Data Manipulation
- **T1036.005** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Bucket Squatting: GCS bucket created matching Vertex AI predictable staging-name pattern

`UC_100_6` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where All_Changes.object_category="bucket" All_Changes.action="created" (All_Changes.command="storage.buckets.create" OR All_Changes.command="google.storage.v1.Storage.CreateBucket") by All_Changes.user, All_Changes.object, All_Changes.dest, All_Changes.src, All_Changes.vendor_account, All_Changes.vendor_product | `drop_dm_object_name("All_Changes")` | rename object as bucket_name | where match(lower(bucket_name), "vertex-staging-(us|europe|asia|northamerica|southamerica|me-|africa-)") OR match(lower(bucket_name), "-vertex-staging-") | rex field=bucket_name "(?<embedded_project>[^-]+(?:-[^-]+)*)-vertex-staging-(?<region>.+)$" | rex field=user "service-(?<caller_project_num>\d+)@gcp-sa-aiplatform" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | table firstTime, lastTime, user, embedded_project, region, bucket_name, vendor_account, src
```

**Defender KQL:**
```kql
// Requires Defender for Cloud Apps GCP connector
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has_any ("Google Cloud Platform","Google Cloud Storage","GCP")
| where ActionType has_any ("storage.buckets.create","BucketCreated","Insert bucket","google.storage.v1.Storage.CreateBucket")
| extend BucketName = tolower(coalesce(ObjectName, tostring(parse_json(tostring(RawEventData)).resourceName)))
| where BucketName matches regex @"vertex-staging-(us|europe|asia|northamerica|southamerica|me-|africa-)"
   or BucketName has "-vertex-staging-"
| extend EmbeddedProject = extract(@"^(.*?)-vertex-staging-", 1, BucketName)
| extend Region = extract(@"-vertex-staging-(.+)$", 1, BucketName)
| project Timestamp, AccountDisplayName, AccountObjectId, AccountType, IPAddress, CountryCode, ISP, Application, ActionType, BucketName, EmbeddedProject, Region, RawEventData
| order by Timestamp desc
```

### Vulnerable google-cloud-aiplatform SDK install (<1.148.0 - Pickle in the Middle exposure)

`UC_100_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("pip.exe","pip3.exe","pip","pip3","python.exe","python","python3.exe","python3","uv.exe","uv","poetry.exe","poetry") Processes.process="*google-cloud-aiplatform*" by Processes.dest, Processes.user, Processes.process, Processes.process_name, Processes.parent_process_name | `drop_dm_object_name("Processes")` | rex field=process "google-cloud-aiplatform(?:[=<>~]=|@)?\s*(?<sdk_version>\d+\.\d+\.\d+)" | where isnotnull(sdk_version) | eval major=tonumber(mvindex(split(sdk_version,"."),0)), minor=tonumber(mvindex(split(sdk_version,"."),1)) | where major=1 AND minor<148 | eval patch_state=case(minor<144,"unpatched (vuln to bucket squat)",minor>=144 AND minor<148,"partial fix only (uuid4 - missing ownership check)",1=1,"unknown") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | table firstTime, lastTime, dest, user, sdk_version, patch_state, process
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("pip.exe","pip3.exe","python.exe","python3.exe","uv.exe","poetry.exe")
   or InitiatingProcessFileName in~ ("pip.exe","pip3.exe","python.exe","python3.exe","uv.exe","poetry.exe")
| extend FullCmd = strcat(tostring(ProcessCommandLine), " ", tostring(InitiatingProcessCommandLine))
| where FullCmd has "google-cloud-aiplatform" or FullCmd has "google-vertex-ai"
| extend SdkVersion = extract(@"google-cloud-aiplatform(?:[=<>~]=|@)?\s*(\d+\.\d+\.\d+)", 1, FullCmd)
| where isnotempty(SdkVersion)
| extend Parts = split(SdkVersion, ".")
| extend Major = toint(Parts[0]), Minor = toint(Parts[1])
| where Major == 1 and Minor < 148
| extend PatchState = case(Minor < 144, "unpatched", Minor >= 144 and Minor < 148, "partial-fix-only", "unknown")
| project Timestamp, DeviceName, AccountName, FileName, SdkVersion, PatchState, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Vertex AI model artifact written to *-vertex-staging-* bucket outside caller's project

`UC_100_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where All_Changes.command IN ("storage.objects.create","storage.objects.update") by All_Changes.user, All_Changes.object, All_Changes.dest, All_Changes.src, All_Changes.vendor_account, All_Changes.vendor_region | `drop_dm_object_name("All_Changes")` | rex field=object "projects/_/buckets/(?<bucket>[^/]+)/objects/(?<obj_path>.+)$" | where match(lower(bucket), "-vertex-staging-") | where match(lower(obj_path), "\.(pkl|pickle|joblib|pb|h5|onnx|safetensors)$") OR match(lower(obj_path), "saved_model") | rex field=user "service-(?<caller_project_num>\d+)@gcp-sa-aiplatform\.iam\.gserviceaccount\.com" | rex field=bucket "^(?<embedded_project>[^-]+(?:-[^-]+)*)-vertex-staging-" | eval is_vertex_agent=if(isnotnull(caller_project_num),"yes","no") | eval cross_project=if(is_vertex_agent="yes" AND vendor_account!=embedded_project,"yes","no") | where cross_project="yes" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | table firstTime, lastTime, user, vendor_account, bucket, embedded_project, obj_path
```

**Defender KQL:**
```kql
// Requires Defender for Cloud Apps GCP connector with object-level audit
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has_any ("Google Cloud Platform","Google Cloud Storage")
| where ActionType has_any ("storage.objects.create","storage.objects.update","Upload object")
| extend Raw = parse_json(tostring(RawEventData))
| extend ResourceName = tolower(tostring(Raw.protoPayload.resourceName))
| extend Bucket = extract(@"buckets/([^/]+)/objects/", 1, ResourceName)
| extend ObjPath = extract(@"objects/(.+)$", 1, ResourceName)
| extend Principal = tostring(Raw.protoPayload.authenticationInfo.principalEmail)
| extend CallerProject = tostring(Raw.resource.labels.project_id)
| where Bucket has "-vertex-staging-"
| where ObjPath matches regex @"(?i)\.(pkl|pickle|joblib|pb|h5|onnx|safetensors)$" or ObjPath has "saved_model"
| extend EmbeddedProject = extract(@"^(.*?)-vertex-staging-", 1, Bucket)
| where Principal matches regex @"service-\d+@gcp-sa-aiplatform\.iam\.gserviceaccount\.com"
| where EmbeddedProject != CallerProject
| project Timestamp, Principal, CallerProject, EmbeddedProject, Bucket, ObjPath, IPAddress, CountryCode, RawEventData
| order by Timestamp desc
```

### Race-condition pickle swap: rapid object overwrite in Vertex AI staging bucket within 5s

`UC_100_9` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Change.All_Changes where All_Changes.command IN ("storage.objects.create","storage.objects.update") by _time, All_Changes.user, All_Changes.object, All_Changes.src | `drop_dm_object_name("All_Changes")` | rex field=object "buckets/(?<bucket>[^/]+)/objects/(?<obj_path>.+)$" | where match(lower(bucket), "-vertex-staging-") | where match(lower(obj_path), "\.(pkl|pickle|joblib|pb|h5|onnx|safetensors)$") OR match(lower(obj_path), "saved_model") | sort 0 bucket obj_path _time | streamstats current=f window=1 last(_time) as prev_time last(user) as prev_user last(src) as prev_src by bucket, obj_path | eval delta_sec=_time-prev_time | where isnotnull(prev_time) AND delta_sec<=5 AND user!=prev_user | eval first_writer=prev_user, second_writer=user, first_src=prev_src, second_src=src | table _time, bucket, obj_path, delta_sec, first_writer, second_writer, first_src, second_src
```

**Defender KQL:**
```kql
// Requires Defender for Cloud Apps GCP connector with GCS data-access logs
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has_any ("Google Cloud Platform","Google Cloud Storage")
| where ActionType has_any ("storage.objects.create","storage.objects.update","Upload object")
| extend Raw = parse_json(tostring(RawEventData))
| extend ResourceName = tolower(tostring(Raw.protoPayload.resourceName))
| extend Bucket = extract(@"buckets/([^/]+)/objects/", 1, ResourceName)
| extend ObjPath = extract(@"objects/(.+)$", 1, ResourceName)
| extend Principal = tostring(Raw.protoPayload.authenticationInfo.principalEmail)
| where Bucket has "-vertex-staging-"
| where ObjPath matches regex @"(?i)\.(pkl|pickle|joblib|pb|h5|onnx|safetensors)$" or ObjPath has "saved_model"
| sort by Bucket asc, ObjPath asc, Timestamp asc
| serialize
| extend PrevTime = prev(Timestamp,1), PrevPrincipal = prev(Principal,1), PrevBucket = prev(Bucket,1), PrevObj = prev(ObjPath,1)
| where Bucket == PrevBucket and ObjPath == PrevObj
| extend DeltaSec = datetime_diff('second', Timestamp, PrevTime)
| where DeltaSec between (0 .. 5) and Principal != PrevPrincipal
| project Timestamp, Bucket, ObjPath, DeltaSec, FirstWriter=PrevPrincipal, SecondWriter=Principal, IPAddress, CountryCode
| order by Timestamp desc
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

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
