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
- **T1656** — Impersonation
- **T1078** — Valid Accounts
- **T1059.004** — Unix Shell
- **T1552.001** — Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1005** — Data from Local System
- **T1048.003** — Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol
- **T1567** — Exfiltration Over Web Service
- **T1114.003** — Email Forwarding Rule

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Imperva OpenClaw PoC payload server callout (imperva_artifactory.com)

`UC_147_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(All_Traffic.src) as src, values(All_Traffic.dest_ip) as dest_ip, values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host="*imperva_artifactory.com*" OR All_Traffic.dest_host="*imperva-artifactory.com*" OR All_Traffic.url="*imperva_artifactory.com*") by All_Traffic.dest_host, All_Traffic.app, _time | `drop_dm_object_name(All_Traffic)` | sort - _time
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("imperva_artifactory.com", "imperva-artifactory.com")
   or RemoteUrl matches regex @"(?i)imperva[_-]?artifactory\.com"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName
| order by Timestamp desc
```

### OpenClaw channel-extension display-name allowlist bypass (Slack/Teams/Discord/Matrix/Zalo)

`UC_147_11` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(Authentication.user_display_name) as display_names, values(Authentication.src) as src, min(_time) as first_seen, max(_time) as last_seen from datamodel=Authentication where Authentication.action=success AND (Authentication.app="slack" OR Authentication.app="teams" OR Authentication.app="discord" OR Authentication.app="matrix" OR Authentication.app="zalo") by Authentication.user, Authentication.app | `drop_dm_object_name(Authentication)` | where mvcount(display_names) > 1 | eval reason="Channel-extension allowlist key (display name) changed for a single stable user — potential OpenClaw allowlist bypass" | sort - last_seen
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application in~ ("Microsoft Teams", "Slack", "Discord")
| where ActionType has_any ("UserUpdated", "UpdateDisplayName", "DisplayNameChanged", "user_profile_change", "Modify_User", "UpdateUser")
| extend NewDisplayName = tostring(parse_json(tostring(RawEventData)).NewDisplayName)
| extend OldDisplayName = tostring(parse_json(tostring(RawEventData)).OldDisplayName)
| where isnotempty(NewDisplayName) and NewDisplayName != OldDisplayName
| project Timestamp, Application, AccountDisplayName, AccountObjectId, AccountId, IPAddress, CountryCode, ActionType, OldDisplayName, NewDisplayName
| order by Timestamp desc
```

### OpenClaw agent runtime spawning shell or LOLBin child processes

`UC_147_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(Processes.process) as cmd, values(Processes.user) as user, values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","python3.exe","node.exe","pwsh.exe","openclaw.exe","openclaw-agent.exe") OR Processes.parent_process="*openclaw*" OR Processes.parent_process="*agent.py*" OR Processes.parent_process="*llm_agent*") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","wsl.exe","sh","curl.exe","wget.exe","certutil.exe","bitsadmin.exe") by host, Processes.parent_process_name, Processes.process_name | `drop_dm_object_name(Processes)` | sort - count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (InitiatingProcessFileName in~ ("python.exe","python3.exe","node.exe","pwsh.exe","openclaw.exe","openclaw-agent.exe")
      or InitiatingProcessCommandLine has_any ("openclaw", "agent.py", "agent_runtime", "llm_agent"))
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","wsl.exe","sh.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe","mshta.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### OpenClaw agent process reading credential stores or .env / .ssh / .aws paths

`UC_147_13` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(Filesystem.file_path) as paths, values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.process_name IN ("python.exe","python3.exe","node.exe","pwsh.exe","openclaw.exe","openclaw-agent.exe") OR Filesystem.process="*openclaw*" OR Filesystem.process="*agent.py*") AND (Filesystem.file_path="*\\.ssh\\*" OR Filesystem.file_path="*\\.aws\\*" OR Filesystem.file_path="*\\.azure\\*" OR Filesystem.file_path="*\\.gcloud\\*" OR Filesystem.file_name=".env" OR Filesystem.file_name="credentials" OR Filesystem.file_name="id_rsa" OR Filesystem.file_name="id_ed25519" OR Filesystem.file_name="secrets.json" OR Filesystem.file_path="/root/.ssh/*" OR Filesystem.file_path="/root/.aws/*" OR Filesystem.file_path="/etc/passwd" OR Filesystem.file_path="/etc/shadow") by host, Filesystem.user, Filesystem.process_name, Filesystem.file_path | `drop_dm_object_name(Filesystem)` | sort - count
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where (InitiatingProcessFileName in~ ("python.exe","python3.exe","node.exe","pwsh.exe","openclaw.exe","openclaw-agent.exe")
      or InitiatingProcessCommandLine has_any ("openclaw","agent.py","llm_agent","agent_runtime"))
| where FolderPath has_any (@"\.ssh\", @"\.aws\", @"\.azure\", @"\.gcloud\", @"\AppData\Roaming\Microsoft\Credentials", @"\AppData\Local\Microsoft\Credentials", "/root/.ssh", "/root/.aws", "/etc/passwd", "/etc/shadow")
   or FileName in~ (".env", "credentials", "id_rsa", "id_rsa.pub", "id_ed25519", "config.json", "secrets.json", "aws-credentials", "connection_strings.txt")
| where ActionType in~ ("FileCreated","FileRenamed","FileModified","FileAccessed","FileOpened")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### OpenClaw mail connector sending credentials to first-time external recipient

`UC_147_14` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(All_Email.recipient) as recipient, values(All_Email.subject) as subject, values(All_Email.src_user) as sender from datamodel=Email.All_Email where All_Email.direction="outbound" AND (All_Email.src_user="*openclaw*" OR All_Email.src_user="*pinchy*" OR All_Email.src_user="*agent*" OR All_Email.src_user="*automation*") AND (All_Email.subject="*credential*" OR All_Email.subject="*access key*" OR All_Email.subject="*AWS*" OR All_Email.subject="*SSH*" OR All_Email.subject="*connection string*" OR All_Email.subject="*customer export*" OR All_Email.subject="*QBR*" OR All_Email.subject="*staging access*") by All_Email.recipient, All_Email.src_user, _time | `drop_dm_object_name(All_Email)` | sort - _time
```

**Defender KQL:**
```kql
let Baseline = EmailEvents
    | where Timestamp between (ago(60d) .. ago(1d))
    | where EmailDirection == "Outbound"
    | summarize by RecipientEmailAddress;
EmailEvents
| where Timestamp > ago(1d)
| where EmailDirection == "Outbound"
| where SenderFromAddress has_any ("openclaw","agent","pinchy","automation","assistant")
   or SenderDisplayName has_any ("OpenClaw","Agent","Pinchy","AI Assistant")
| where Subject has_any ("credential","access key","AWS","IAM","SSH","connection string","customer export","QBR","staging access","production incident")
   or AttachmentCount > 0
| join kind=leftanti Baseline on RecipientEmailAddress
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderDisplayName, RecipientEmailAddress, Subject, AttachmentCount, UrlCount, DeliveryAction, EmailDirection
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

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 28 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
