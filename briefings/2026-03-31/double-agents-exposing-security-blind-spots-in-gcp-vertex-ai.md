# [CRIT] Double Agents: Exposing Security Blind Spots in GCP Vertex AI

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-03-31
**Article:** https://unit42.paloaltonetworks.com/double-agents-vertex-ai/

## Threat Profile

Threat Research Center 
Threat Research 
Malware 
Malware 
Double Agents: Exposing Security Blind Spots in GCP Vertex AI 
11 min read 
Related Products Cortex Cortex Cloud Prisma AIRS Unit 42 AI Security Assessment Unit 42 Incident Response 
By: Ofir Shaty 
Published: March 31, 2026 
Categories: Malware 
Threat Research 
Tags: Agentic AI 
Data exfiltration 
GCP 
Google Cloud 
Google cloud storage 
JSON 
LLM 
Privilege escalation 
Vertex AI 
Executive Summary 
Artificial intelligence (AI) agents …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-55182`
- **Domain (defanged):** `gcp-sa-aiplatform-re.iam.gserviceaccount.com`
- **Domain (defanged):** `metadata.google.internal`
- **Domain (defanged):** `us-docker.pkg.dev`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1648** — Serverless Execution
- **T1608.001** — Stage Capabilities: Upload Malware
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1530** — Data from Cloud Storage
- **T1213.003** — Data from Information Repositories: Code Repositories
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vertex AI Agent Engine deployment with python stdlib names embedded in package extras

`UC_147_8` · phase: **weapon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where Change.object_category=cloud_resource (Change.object="*reasoningEngines*" OR Change.command="*ReasoningEngineService*" OR Change.command="*agent_engines*") (Change.command="*google-cloud-aiplatform[*subprocess*" OR Change.command="*google-cloud-aiplatform[*socket*" OR Change.command="*google-cloud-aiplatform[*\"os\"*" OR Change.command="*,os,*" OR Change.command="*,subprocess,*") by Change.user Change.src Change.object Change.command Change.action Change.result | `drop_dm_object_name(Change)` | search command IN ("*subprocess*","*socket*","*,os,*") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
CloudAppEvents
| where Application == "Google Cloud Platform"
| where ActionType has_any ("CreateReasoningEngine","UpdateReasoningEngine","google.cloud.aiplatform.v1beta1.ReasoningEngineService","agent_engines.create")
| extend raw = tostring(RawEventData)
| where raw has "google-cloud-aiplatform[" and raw has_any ("subprocess","socket",",os,",",os]")
| extend principal = tostring(RawEventData.protoPayload.authenticationInfo.principalEmail)
| extend resource = tostring(RawEventData.protoPayload.resourceName)
| project Timestamp, principal, ActionType, resource, raw, AccountObjectId, IPAddress
```

### [LLM] Vertex AI Reasoning Engine P4SA (gcp-sa-aiplatform-re) acting on consumer GCS or cross-project Artifact Registry

`UC_147_9` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(Change.object) as objects values(Change.command) as methods dc(Change.object) as bucket_count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where Change.user="service-*@gcp-sa-aiplatform-re.iam.gserviceaccount.com" (Change.command IN ("storage.buckets.list","storage.objects.list","storage.objects.get","storage.buckets.get","artifactregistry.repositories.list","artifactregistry.packages.list","artifactregistry.versions.list")) by Change.user Change.src Change.dest | `drop_dm_object_name(Change)` | where bucket_count > 3 OR like(methods,"%artifactregistry%") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let suspicious_methods = dynamic(["storage.buckets.list","storage.objects.list","storage.objects.get","storage.buckets.get","artifactregistry.repositories.list","artifactregistry.packages.list","artifactregistry.versions.list"]);
CloudAppEvents
| where Application == "Google Cloud Platform"
| extend principal = tostring(RawEventData.protoPayload.authenticationInfo.principalEmail)
| extend method   = tostring(RawEventData.protoPayload.methodName)
| extend resource = tostring(RawEventData.protoPayload.resourceName)
| where principal matches regex @"^service-[0-9]+@gcp-sa-aiplatform-re\.iam\.gserviceaccount\.com$"
| where method in (suspicious_methods) or resource has "cloud-aiplatform-private"
| summarize hits=count(), bucket_count=dcount(resource), methods=make_set(method,20), resources=make_set(resource,20) by principal, bin(Timestamp,1h)
| where bucket_count > 3 or methods has_any ("artifactregistry.repositories.list","artifactregistry.packages.list")
```

### [LLM] Outbound pulls to Google-internal Vertex AI private artifact registry path cloud-aiplatform-private

`UC_147_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("docker.exe","docker","crane","crane.exe","gcloud","gcloud.cmd","podman","skopeo") OR Processes.process IN ("*artifacts docker images*","*pull*")) (Processes.process="*cloud-aiplatform-private*" OR Processes.process="*reasoning-engine-py310*" OR Processes.process="*us-docker.pkg.dev/cloud-aiplatform-private*") by Processes.user Processes.dest Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [ | tstats summariesonly=t count from datamodel=Web.Web where (Web.url="*cloud-aiplatform-private*" OR Web.url="*reasoning-engine-py310*") by Web.user Web.src Web.dest Web.url | `drop_dm_object_name(Web)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
( DeviceProcessEvents
  | where ProcessCommandLine has_any ("cloud-aiplatform-private","reasoning-engine-py310","us-docker.pkg.dev/cloud-aiplatform-private")
  | where InitiatingProcessFileName in~ ("docker.exe","crane.exe","gcloud.cmd","podman.exe","skopeo.exe","powershell.exe","pwsh.exe","python.exe","bash","sh")
     or FileName in~ ("docker.exe","crane.exe","gcloud.cmd","podman.exe","skopeo.exe")
  | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName ),
( DeviceNetworkEvents
  | where RemoteUrl has_any ("cloud-aiplatform-private","reasoning-engine-py310")
     or (RemoteUrl has "us-docker.pkg.dev" and RemoteUrl has "cloud-aiplatform-private")
  | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP )
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
| where FolderPath has_any ("\Google\Chrome\User Data\","\Microsoft\Edge\User Data\","\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)

`UC_FAKECAPTCHA` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-55182`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `gcp-sa-aiplatform-re.iam.gserviceaccount.com`, `metadata.google.internal`, `us-docker.pkg.dev`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
