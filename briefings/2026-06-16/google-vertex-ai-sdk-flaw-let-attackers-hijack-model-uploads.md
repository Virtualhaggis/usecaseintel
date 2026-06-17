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
- **T1583.006** — Acquire Infrastructure: Web Services
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1554** — Compromise Host Software Binary
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1565.001** — Data Manipulation: Stored Data Manipulation
- **T1525** — Implant Internal Image
- **T1199** — Trusted Relationship

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GCS bucket creation matching Vertex AI predictable staging pattern (bucket squatting precursor)

`UC_22_6` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.action=created AND (All_Changes.object_category="google_storage_bucket" OR All_Changes.change_type="Cloud Storage" OR All_Changes.object_attrs.method_name="storage.buckets.create") by All_Changes.object All_Changes.user All_Changes.src All_Changes.dest All_Changes.command All_Changes.result
| `drop_dm_object_name(All_Changes)`
| rex field=object "(?<bucket_name>[^/]+)$"
| where match(bucket_name, "(?i).+-vertex-staging-.+") AND NOT match(bucket_name, "-vertex-staging-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
| convert ctime(firstTime) ctime(lastTime)
| table firstTime lastTime bucket_name user src result object
```

### Vulnerable google-cloud-aiplatform SDK install detected (<1.148.0)

`UC_22_7` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process) as parent_process values(Processes.process) as cmdline from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip.exe","pip3.exe","pip","pip3","python.exe","python3.exe","python","python3","poetry.exe","poetry","conda.exe","conda","uv.exe","uv")) AND Processes.process="*google-cloud-aiplatform*" by Processes.dest Processes.user Processes.process_name
| `drop_dm_object_name(Processes)`
| where match(cmdline, "(?i)google-cloud-aiplatform==1\.(13[0-9]|14[0-7])(\.[0-9]+)?\b") OR match(cmdline, "(?i)google-cloud-aiplatform(?!==).*install")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("pip.exe","pip3.exe","python.exe","python3.exe","poetry.exe","conda.exe","uv.exe")
| where ProcessCommandLine has "google-cloud-aiplatform"
| where ProcessCommandLine has_any ("install","add","sync","update")
| extend PinnedVersion = extract(@"(?i)google-cloud-aiplatform==(1\.(?:13[0-9]|14[0-7])(?:\.[0-9]+)?)", 1, ProcessCommandLine)
| where isnotempty(PinnedVersion) or ProcessCommandLine matches regex @"(?i)google-cloud-aiplatform(?!==)"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, PinnedVersion, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Vertex AI Model.upload artifactUri / staging_bucket references cross-project GCS bucket

`UC_22_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Changes.command) as cmd values(All_Changes.object_attrs.request.parent) as caller_project values(All_Changes.object_attrs.request.model.artifactUri) as artifact_uri from datamodel=Change where All_Changes.object_category="aiplatform_model" AND (All_Changes.object_attrs.method_name="google.cloud.aiplatform.v1.ModelService.UploadModel" OR All_Changes.object_attrs.method_name="google.cloud.aiplatform.v1beta1.ModelService.UploadModel" OR All_Changes.object_attrs.method_name="google.cloud.aiplatform.v1.JobService.CreateCustomJob") by All_Changes.user All_Changes.src
| `drop_dm_object_name(All_Changes)`
| rex field=caller_project "projects/(?<calling_project>[^/]+)/"
| rex field=artifact_uri "gs://(?<dest_bucket>[^/]+)/"
| eval bucket_project=case(match(dest_bucket,".+-vertex-staging-.+"), replace(dest_bucket,"(.+)-vertex-staging-.+","\1"), 1=1, dest_bucket)
| where isnotnull(calling_project) AND isnotnull(bucket_project) AND calling_project!=bucket_project
| convert ctime(firstTime) ctime(lastTime)
```

### Rapid object overwrite race in Vertex AI staging bucket (Pickle-in-the-Middle replacement)

`UC_22_9` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstWrite max(_time) as lastWrite values(All_Changes.user) as writers dc(All_Changes.user) as writer_count from datamodel=Change where All_Changes.object_category="google_storage_object" AND All_Changes.action=created AND (All_Changes.object="*-vertex-staging-*/model.pkl" OR All_Changes.object="*-vertex-staging-*/model.joblib" OR All_Changes.object="*-vertex-staging-*/saved_model.pb" OR All_Changes.object="*aiplatform-custom-training-*model*") by All_Changes.object _time span=5s
| `drop_dm_object_name(All_Changes)`
| where count >= 2 AND writer_count >= 2
| eval race_window_sec=lastWrite-firstWrite
| where race_window_sec <= 5
| convert ctime(firstWrite) ctime(lastWrite)
| table firstWrite lastWrite object writers race_window_sec count
```

### Vertex AI model deployed with artifactUri pointing to externally-owned GCS bucket

`UC_22_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object_attrs.request.deployedModel.model) as model_resource values(All_Changes.object_attrs.request.deployedModel.dedicatedResources.machineSpec.machineType) as machine_type values(All_Changes.object_attrs.response.model.artifactUri) as artifact_uri from datamodel=Change where All_Changes.object_category="aiplatform_endpoint" AND (All_Changes.object_attrs.method_name="google.cloud.aiplatform.v1.EndpointService.DeployModel" OR All_Changes.object_attrs.method_name="google.cloud.aiplatform.v1beta1.EndpointService.DeployModel") by All_Changes.user All_Changes.src All_Changes.dest
| `drop_dm_object_name(All_Changes)`
| rex field=user "projects/(?<calling_project>[^/]+)/"
| rex field=artifact_uri "gs://(?<dest_bucket>[^/]+)/"
| lookup gcp_owned_buckets bucket_name AS dest_bucket OUTPUT owning_project bucket_org
| where (isnull(owning_project)) OR (owning_project!=calling_project AND bucket_org!="<your-org-id>")
| convert ctime(firstTime) ctime(lastTime)
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

Severity classified as **CRIT** based on: CVE present, 11 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
