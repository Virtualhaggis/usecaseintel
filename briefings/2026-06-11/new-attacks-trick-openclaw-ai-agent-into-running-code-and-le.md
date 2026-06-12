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
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1005** — Data from Local System
- **T1041** — Exfiltration Over C2 Channel
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1567** — Exfiltration Over Web Service
- **T1071.003** — Application Layer Protocol: Mail Protocols
- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### DNS or network egress to Imperva PoC infrastructure (imperva_artifactory.com)

`UC_7_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.dest) as dest from datamodel=Network_Resolution.DNS where DNS.query="imperva_artifactory.com" OR DNS.query="*.imperva_artifactory.com" by DNS.query DNS.src | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | append [| tstats summariesonly=true count from datamodel=Web.Web where Web.url="*imperva_artifactory.com*" by Web.src Web.url Web.dest | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
let SuspectDomain = "imperva_artifactory.com";
union isfuzzy=true
  (DeviceNetworkEvents
   | where Timestamp > ago(7d)
   | where RemoteUrl has SuspectDomain
   | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ReportId),
  (DeviceEvents
   | where Timestamp > ago(7d)
   | where ActionType == "DnsQueryResponse" or ActionType == "DnsConnectionInspected"
   | where RemoteUrl has SuspectDomain or AdditionalFields has SuspectDomain
   | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, AdditionalFields, ReportId)
| order by Timestamp desc
```

### OpenClaw agent process spawns LOLBin or interpreter (tool-use code execution)

`UC_7_11` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as childpath from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","python3","python","node.exe","node","openclaw","openclaw.exe","pinchy","pinchy.exe") OR Processes.parent_process IN ("*openclaw*","*pinchy*","*\\openclaw\\*","*/openclaw/*")) AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","bash","sh","zsh","curl.exe","curl","wget.exe","wget","certutil.exe","bitsadmin.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe") by host Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let AgentParents = dynamic(["python.exe","python3","python","node.exe","node","openclaw.exe","openclaw","pinchy.exe","pinchy"]);
let SuspChildren = dynamic(["powershell.exe","pwsh.exe","cmd.exe","bash.exe","wsl.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (AgentParents)
   or InitiatingProcessCommandLine has_any ("openclaw","OpenClaw","pinchy","Pinchy")
   or InitiatingProcessFolderPath has_any ("\\openclaw\\","/openclaw/","\\pinchy\\","/pinchy/")
| where FileName in~ (SuspChildren)
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256, ReportId
| order by Timestamp desc
```

### AI agent process reads credential stores then egresses to external destination

`UC_7_12` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.process_name IN ("python.exe","python3","node.exe","openclaw.exe","pinchy.exe") OR Filesystem.process_path IN ("*openclaw*","*pinchy*")) AND (Filesystem.file_path IN ("*\\.aws\\credentials*","*/.aws/credentials*","*\\.env*","*/.env*","*\\.ssh\\id_rsa*","*/.ssh/id_rsa*","*\\.ssh\\config*","*/.ssh/config*") OR Filesystem.file_name IN ("credentials",".env","id_rsa","id_ed25519")) by host Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let AgentImages = dynamic(["python.exe","python3","python","node.exe","openclaw.exe","pinchy.exe"]);
let CredPaths = dynamic(["\\.aws\\credentials","/.aws/credentials","\\.env","/.env","\\.ssh\\id_rsa","/.ssh/id_rsa","\\.ssh\\config","/.ssh/config","\\.docker\\config.json","/.docker/config.json","\\.kube\\config","/.kube/config"]);
let CredReads = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("FileOpened","FileCreated","FileModified")
    | where InitiatingProcessFileName in~ (AgentImages)
       or InitiatingProcessFolderPath has_any ("\\openclaw\\","/openclaw/","\\pinchy\\","/pinchy/")
    | where FolderPath has_any (CredPaths) or FileName in~ ("credentials",".env","id_rsa","id_ed25519")
    | project ReadTime=Timestamp, DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessId, FolderPath, FileName;
let AgentEgress = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ (AgentImages)
       or InitiatingProcessFolderPath has_any ("\\openclaw\\","/openclaw/","\\pinchy\\","/pinchy/")
    | where RemoteIPType == "Public"
    | project NetTime=Timestamp, DeviceId, InitiatingProcessFileName, InitiatingProcessId, RemoteIP, RemoteUrl, RemotePort;
CredReads
| join kind=inner (AgentEgress) on DeviceId
| where NetTime between (ReadTime .. ReadTime + 5m)
| project ReadTime, NetTime, DelaySec = datetime_diff('second', NetTime, ReadTime), DeviceName, InitiatingProcessFileName, FolderPath, FileName, RemoteIP, RemoteUrl, RemotePort
| order by ReadTime desc
```

### OpenClaw outbound mail to first-time / external recipient (agent-phishing exfil)

`UC_7_13` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Email.All_Email where All_Email.src_user IN ("*openclaw*","*pinchy*","agent-*") AND All_Email.direction=outbound by All_Email.src_user All_Email.recipient _time | `drop_dm_object_name(All_Email)` | eval recipient_domain=mvindex(split(recipient,"@"),1) | join type=left recipient_domain [| tstats summariesonly=true earliest(_time) as first_seen from datamodel=Email.All_Email where All_Email.direction=inbound by All_Email.src_user | `drop_dm_object_name(All_Email)` | rename src_user as recipient_domain] | where isnull(first_seen) OR first_seen > relative_time(_time,"-1d@d")
```

**Defender KQL:**
```kql
let AgentSenders = dynamic(["openclaw@","pinchy@","agent@","agent-"]);
let Baseline = EmailEvents
    | where Timestamp between (ago(60d) .. ago(1d))
    | where EmailDirection in ("Inbound","Outbound","Intra-org")
    | summarize by RecipientEmailAddress;
EmailEvents
| where Timestamp > ago(1d)
| where EmailDirection == "Outbound"
| where SenderFromAddress has_any (AgentSenders)
   or SenderDisplayName has_any ("openclaw","pinchy","OpenClaw","Pinchy")
| join kind=leftanti Baseline on RecipientEmailAddress
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderDisplayName, RecipientEmailAddress, Subject, AttachmentCount, UrlCount
| order by Timestamp desc
```

### Vulnerable OpenClaw install (pre-2026.4.23) inventoried in the estate

`UC_7_14` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name IN ("openclaw.exe","openclaw") by host Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)` | join host [| inputlookup software_inventory.csv | where like(SoftwareName,"%OpenClaw%") | rename Host as host] | where SoftwareVersion<"2026.4.23"
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareName has "OpenClaw" or SoftwareVendor has "OpenClaw"
| extend Major = toint(extract(@"^(\d+)", 1, SoftwareVersion))
| extend Minor = toint(extract(@"^\d+\.(\d+)", 1, SoftwareVersion))
| extend Patch = toint(extract(@"^\d+\.\d+\.(\d+)", 1, SoftwareVersion))
| where Major < 2026
   or (Major == 2026 and Minor < 4)
   or (Major == 2026 and Minor == 4 and Patch < 23)
| project Timestamp, DeviceId, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion
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

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 29 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
