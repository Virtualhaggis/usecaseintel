# [HIGH] New Attacks Trick OpenClaw AI Agent Into Running Code and Leaking Secrets

**Source:** The Hacker News
**Published:** 2026-06-11
**Article:** https://thehackernews.com/2026/06/new-attacks-trick-openclaw-ai-agent.html

## Threat Profile

New Attacks Trick OpenClaw AI Agent Into Running Code and Leaking Secrets 
 Swati Khandelwal  Jun 11, 2026 AI Security / Data Security 
Two security teams have shown, in separate research published this week, that OpenClaw , the popular self-hosted AI agent, can be driven to run attacker-controlled code or hand over sensitive data through ordinary-looking inputs.
Imperva buried instructions inside shared contacts, vCards, and location pins that the agent executed without the victim ever seeing…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `imperva_artifactory.com`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1204** — User Execution
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1005** — Data from Local System
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1567** — Exfiltration Over Web Service
- **T1041** — Exfiltration Over C2 Channel
- **T1656** — Impersonation
- **T1078** — Valid Accounts
- **T1199** — Trusted Relationship

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### OpenClaw / AI agent egress to imperva_artifactory.com (Imperva PoC payload server)

`UC_143_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where Network_Traffic.All_Traffic.dest IN ("imperva_artifactory.com","imperva-artifactory.com") OR Network_Traffic.All_Traffic.dest_host IN ("imperva_artifactory.com","imperva-artifactory.com") by Network_Traffic.All_Traffic.src Network_Traffic.All_Traffic.src_ip Network_Traffic.All_Traffic.dest Network_Traffic.All_Traffic.dest_port Network_Traffic.All_Traffic.app | `drop_dm_object_name(Network_Traffic.All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("imperva_artifactory.com","imperva-artifactory.com") or AdditionalFields has "imperva_artifactory.com"
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### OpenClaw agent runtime spawning shell / download-and-run after prompt injection

`UC_143_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","python3","python","node.exe","node","openclaw.exe","openclaw-server","openclaw-agent","langchain","uvicorn","gunicorn") OR Processes.parent_process IN ("*openclaw*","*open_claw*","*claw-agent*")) AND Processes.process_name IN ("curl.exe","wget.exe","curl","wget","powershell.exe","pwsh.exe","bash","sh","cmd.exe","certutil.exe","bitsadmin.exe") AND (Processes.process IN ("*IEX*","*Invoke-Expression*","*DownloadString*","*curl *|* sh*","*wget *|* bash*","*-OutFile*","*--data-binary*","*chmod +x*")) by host Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let agent_parents = dynamic(["python.exe","python3.exe","python","node.exe","node","openclaw.exe","openclaw-server","openclaw-agent.exe","uvicorn.exe","gunicorn"]);
let exec_children = dynamic(["powershell.exe","pwsh.exe","cmd.exe","bash","sh","zsh","curl.exe","wget.exe","curl","wget","certutil.exe","bitsadmin.exe","mshta.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (agent_parents)
   or InitiatingProcessCommandLine has_any ("openclaw","open_claw","claw-agent","langchain","autogen","crewai")
| where FileName in~ (exec_children)
| where ProcessCommandLine has_any ("IEX ","Invoke-Expression","DownloadString","DownloadFile"," | sh"," | bash","-OutFile","--data-binary","chmod +x","-EncodedCommand","base64 -d","eval $(")
   or (FileName in~ ("curl.exe","curl","wget.exe","wget") and ProcessCommandLine matches regex @"https?://[^\s]+\.(sh|py|ps1|exe|bin)(\s|$)")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### OpenClaw / AI agent process reading credential stores (.env, .aws/credentials, id_rsa)

`UC_143_12` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("python.exe","python3","python","node.exe","node","openclaw.exe","openclaw-agent","openclaw-server","uvicorn.exe","gunicorn") AND (Filesystem.file_name IN (".env","credentials","id_rsa","id_ed25519",".pgpass",".npmrc",".pypirc") OR Filesystem.file_path IN ("*/.aws/credentials","*/.aws/config","*/.ssh/id_*","*/.kube/config","*/.docker/config.json","*/.gcloud/credentials*","*/.azure/accessTokens.json")) by host Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let agent_proc = dynamic(["python.exe","python3.exe","python","node.exe","node","openclaw.exe","openclaw-server","openclaw-agent.exe","uvicorn.exe","gunicorn"]);
let cred_files = dynamic([".env","credentials","id_rsa","id_ed25519",".pgpass",".npmrc",".pypirc","accessTokens.json","config.json"]);
let cred_paths = dynamic([@"\.aws\credentials",@"\.aws\config",@"\.ssh\id_",@"\.kube\config",@"\.docker\config.json",@"\.gcloud\",@"\.azure\accessTokens.json","/.aws/credentials","/.aws/config","/.ssh/id_","/.kube/config","/.docker/config.json","/.gcloud/","/.azure/accessTokens.json"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
   or ActionType startswith "File"
| where InitiatingProcessFileName in~ (agent_proc)
   or InitiatingProcessCommandLine has_any ("openclaw","open_claw","langchain","autogen","crewai","llama_index")
| where FileName in~ (cred_files) or FolderPath has_any (cred_paths)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ActionType, SHA256
| order by Timestamp desc
```

### AI agent mailbox auto-forwarding credentials to external address (Varonis Pinchy pattern)

`UC_143_13` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Email.subject) as subjects values(All_Email.recipient) as recipients from datamodel=Email where All_Email.direction="outbound" AND NOT All_Email.recipient_domain IN ("yourcorp.com","yourcorp.onmicrosoft.com") by All_Email.src_user All_Email.recipient | `drop_dm_object_name(All_Email)` | join type=inner src_user [search index=email sourcetype=*body* ("AKIA" OR "ASIA" OR "BEGIN RSA PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY" OR "postgres://*:*@" OR "mysql://*:*@" OR "mongodb://*:*@" OR "aws_secret_access_key") | rename sender as src_user | fields src_user, subject, body_snippet] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let agent_mailboxes = dynamic(["pinchy@","agent@","assistant@","openclaw@","ai-bot@","copilot@"]);  // tune per org
let internal_domain = "yourcorp.com";
let sus_subj = dynamic(["production incident","staging access","weekly customer export","QBR","customer export","credentials","access key","creds for"]);
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection in ("Outbound","Intra-org")
| where SenderFromAddress has_any (agent_mailboxes) or SenderMailFromAddress has_any (agent_mailboxes)
| where not(RecipientEmailAddress endswith internal_domain)
| where Subject has_any (sus_subj)
   or AdditionalFields has_any ("AKIA","ASIA","BEGIN RSA PRIVATE KEY","BEGIN OPENSSH PRIVATE KEY","aws_secret_access_key","postgres://","mysql://","mongodb://")
| join kind=leftouter (EmailAttachmentInfo | project NetworkMessageId, AttachFile=FileName, AttachType=FileType, AttachSize=FileSize) on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, AttachFile, AttachType, AttachSize, DeliveryAction
| order by Timestamp desc
```

### OpenClaw channel-extension allowlist bypass via attacker display-name rename

`UC_143_14` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=collaboration (sourcetype=slack:audit OR sourcetype=msteams:audit OR sourcetype=discord:audit) (action=user_profile_changed OR action=UserUpdated OR action=display_name_change OR action=user.update) | rex field=changes "(?i)display_?name.*?from\s*[\"']?(?<old_name>[^\"',]+)[\"']?.*?to\s*[\"']?(?<new_name>[^\"',]+)" | where isnotnull(new_name) AND old_name!=new_name | stats min(_time) as firstTime max(_time) as lastTime values(old_name) as old_names values(new_name) as new_names count by user, user_id, workspace, app | where count >= 1 | eval suspicious=if(match(new_names, "(?i)(admin|ceo|cto|cfo|security|finance|hr|ops|it[-_]?ops|openclaw|agent)"), 1, 0) | where suspicious=1
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft Teams","Slack","Discord","Matrix","Zalo")
| where ActionType in ("UpdateUser","UserProfileChanged","user_profile_changed","display_name_change","UserUpdated","users.profile_set")
| extend Old = tostring(parse_json(tostring(RawEventData)).previous_display_name), New = tostring(parse_json(tostring(RawEventData)).display_name)
| extend Old = iff(isempty(Old), tostring(AdditionalFields.PreviousDisplayName), Old), New = iff(isempty(New), tostring(AdditionalFields.NewDisplayName), New)
| where isnotempty(New) and Old != New
| where New matches regex @"(?i)(admin|ceo|cto|cfo|security|finance|hr|ops|it[-_]?ops|openclaw|agent|bot|sre|oncall)"
| project Timestamp, Application, AccountObjectId, AccountDisplayName, Old, New, IPAddress, CountryCode, UserAgent
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
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
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `imperva_artifactory.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 31 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
