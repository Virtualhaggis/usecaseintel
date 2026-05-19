# [CRIT] Can AI Attack the Cloud? Lessons From Building an Autonomous Cloud Offensive Multi-Agent System

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-04-23
**Article:** https://unit42.paloaltonetworks.com/autonomous-ai-cloud-attacks/

## Threat Profile

Threat Research Center 
Threat Research 
Cloud Cybersecurity Research 
Cloud Cybersecurity Research 
Can AI Attack the Cloud? Lessons From Building an Autonomous Cloud Offensive Multi-Agent System 
12 min read 
Related Products Cortex Cortex Cloud Cortex XDR Cortex XSIAM Unit 42 AI Security Assessment Unit 42 Cloud Security Assessment Unit 42 Incident Response 
By: Yahav Festinger 
Chen Doytshman 
Published: April 23, 2026 
Categories: Cloud Cybersecurity Research 
Threat Research 
Tags: AI 
Clo…

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
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1046** — Network Service Discovery
- **T1580** — Cloud Infrastructure Discovery
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1087.004** — Account Discovery: Cloud Account
- **T1069.003** — Permission Groups Discovery: Cloud Groups
- **T1526** — Cloud Service Discovery
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1548.005** — Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access
- **T1537** — Transfer Data to Cloud Account
- **T1567.002** — Exfiltration to Cloud Storage
- **T1619** — Cloud Storage Object Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Internal VPC port scanning burst from GCP/cloud VM (Nmap-style sweep)

`UC_255_6` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count dc(All_Traffic.dest_ip) as DistinctIPs dc(All_Traffic.dest_port) as DistinctPorts values(All_Traffic.dest_port) as Ports from datamodel=Network_Traffic where All_Traffic.dest_ip=10.0.0.0/8 OR All_Traffic.dest_ip=172.16.0.0/12 OR All_Traffic.dest_ip=192.168.0.0/16 by All_Traffic.src host All_Traffic.app _time span=5m | `drop_dm_object_name(All_Traffic)` | where DistinctIPs>=5 AND DistinctPorts>=10
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType in ("ConnectionAttempt","ConnectionFailed","ConnectionSuccess")
| where RemoteIPType == "Private"
| where InitiatingProcessFileName !in~ ("sshd","kubelet","google_guest_agent","google_osconfig_agent","node_exporter","prometheus")
| summarize DistinctIPs = dcount(RemoteIP), DistinctPorts = dcount(RemotePort), Attempts = count(), SamplePorts = make_set(RemotePort, 20), SampleIPs = make_set(RemoteIP, 20) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, bin(Timestamp, 5m)
| where DistinctIPs >= 5 and DistinctPorts >= 10
| order by Attempts desc
```

### [LLM] GCP Instance Metadata Server (169.254.169.254) access from web-app process

`UC_255_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Traffic where All_Traffic.dest_ip=169.254.169.254 by All_Traffic.src All_Traffic.process_name All_Traffic.process_path _time | `drop_dm_object_name(All_Traffic)` | search process_name IN ("python*","node","java","php-fpm","ruby","perl","nginx","apache2","httpd","gunicorn","uwsgi","tomcat*")
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP == "169.254.169.254"
| where InitiatingProcessFileName !in~ ("google_metadata_script_runner","google_guest_agent","google_osconfig_agent","google_oslogin_control","gcloud","gsutil","bq","kubelet","cloud-init","metadata-helper","systemd-networkd")
| where InitiatingProcessFileName has_any ("python","node","java","php","ruby","perl","gunicorn","uwsgi","nginx","apache2","httpd","tomcat","curl","wget")
   or InitiatingProcessCommandLine has_any ("169.254.169.254","metadata.google.internal","computeMetadata/v1")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### [LLM] GCP IAM enumeration burst by single service-account principal

`UC_255_8` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`gcp_audit` (data.protoPayload.methodName="google.iam.admin.v1.ListServiceAccounts" OR data.protoPayload.methodName="google.iam.admin.v1.ListRoles" OR data.protoPayload.methodName="*.GetIamPolicy" OR data.protoPayload.methodName="google.cloud.resourcemanager.v3.Projects.GetIamPolicy" OR data.protoPayload.methodName="*.Instances.List" OR data.protoPayload.methodName="*.Buckets.List" OR data.protoPayload.methodName="*.Datasets.List") data.protoPayload.authenticationInfo.principalEmail="*.iam.gserviceaccount.com" | bin _time span=5m | stats dc(data.protoPayload.methodName) as DistinctMethods count as Calls values(data.protoPayload.methodName) as Methods by _time data.protoPayload.authenticationInfo.principalEmail data.protoPayload.requestMetadata.callerIp | where DistinctMethods>=5
```

### [LLM] GCP service account impersonation via iam.serviceAccounts.generateAccessToken

`UC_255_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`gcp_audit` (data.protoPayload.methodName="GenerateAccessToken" OR data.protoPayload.methodName="google.iam.credentials.v1.IAMCredentials.GenerateAccessToken" OR data.protoPayload.methodName="SignJwt" OR data.protoPayload.methodName="google.iam.credentials.v1.IAMCredentials.SignJwt") | rex field=data.protoPayload.resourceName "serviceAccounts/(?<TargetSA>[^/]+)" | eval Caller=data.protoPayload.authenticationInfo.principalEmail | where Caller!=TargetSA AND like(Caller,"%.iam.gserviceaccount.com") | stats count values(TargetSA) as TargetSAs values(data.protoPayload.requestMetadata.callerIp) as CallerIPs by _time Caller
```

### [LLM] BigQuery query/extract job writing results to a foreign GCP project

`UC_255_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`gcp_audit` data.protoPayload.serviceName="bigquery.googleapis.com" (data.protoPayload.methodName="jobservice.insert" OR data.protoPayload.methodName="google.cloud.bigquery.v2.JobService.InsertJob") | spath input=data.protoPayload.metadata.tableDataRead.jobName output=JobName | spath input=data.protoPayload.metadata.jobChange.job.jobConfig.queryConfig.destinationTable.projectId output=DestProject | spath input=data.resource.labels.project_id output=SrcProject | where isnotnull(DestProject) AND DestProject!=SrcProject | table _time data.protoPayload.authenticationInfo.principalEmail SrcProject DestProject JobName data.protoPayload.requestMetadata.callerIp
```

### [LLM] GCS object copy/rewrite to bucket in foreign GCP project

`UC_255_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`gcp_audit` data.protoPayload.serviceName="storage.googleapis.com" data.protoPayload.methodName IN ("storage.objects.copy","storage.objects.rewrite","storage.objects.compose") | spath input=data.protoPayload.resourceLocation.currentLocations{} output=DestLoc | rex field=data.protoPayload.resourceName "projects/_/buckets/(?<DestBucket>[^/]+)" | eval SrcProject=data.resource.labels.project_id | lookup gcs_bucket_project_map.csv bucket as DestBucket OUTPUT project as DestProject | where SrcProject!=DestProject | table _time data.protoPayload.authenticationInfo.principalEmail SrcProject DestBucket DestProject data.protoPayload.requestMetadata.callerIp
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

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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

Severity classified as **CRIT** based on: 12 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
