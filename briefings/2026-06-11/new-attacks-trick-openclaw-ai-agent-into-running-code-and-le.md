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
- **T1059** — Command and Scripting Interpreter
- **T1204** — User Execution
- **T1114.002** — Email Collection: Remote Email Collection
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1530** — Data from Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound DNS/HTTP to imperva_artifactory.com from any host (OpenClaw PoC payload domain)

`UC_4_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Network_Resolution where DNS.query="*imperva_artifactory.com*" by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstSeen)`
| `security_content_ctime(lastSeen)`
```

**Defender KQL:**
```kql
let payloadHost = "imperva_artifactory.com";
union isfuzzy=true
  (DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has payloadHost
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort),
  (DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType == "DnsQueryResponse"
    | where RemoteUrl has payloadHost or AdditionalFields has payloadHost
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, AdditionalFields)
| order by Timestamp desc
```

### OpenClaw / AI agent runtime spawning shell or scripting interpreter with download command

`UC_4_11` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstSeen max(_time) as lastSeen values(Processes.process) as cmdline values(Processes.process_path) as image from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("openclaw.exe","openclaw-agent.exe","claw-agent.exe","pinchy.exe","openclaw","node.exe","python.exe") OR Processes.parent_process IN ("*openclaw*","*claw-agent*","*pinchy*")) AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","bash.exe","sh","bash","curl.exe","wget.exe","certutil.exe","bitsadmin.exe") AND (Processes.process IN ("*Invoke-WebRequest*","*Invoke-Expression*","*IEX*","*DownloadString*","*-c curl*","*-c wget*","*http://*","*https://*")) by host Processes.user Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("openclaw.exe","openclaw-agent.exe","claw-agent.exe","pinchy.exe","openclaw")
    or InitiatingProcessCommandLine has_any ("openclaw","claw-agent","pinchy")
    or InitiatingProcessFolderPath has_any ("\\OpenClaw\\","/openclaw/","\\openclaw\\")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","bash.exe","sh","curl.exe","wget.exe","certutil.exe","bitsadmin.exe","node.exe","python.exe")
| where ProcessCommandLine has_any ("http://","https://","Invoke-WebRequest","Invoke-Expression","IEX ","DownloadString","-OutFile","-decode","curl -s","wget -O","chmod +x")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Agent-driven outbound email containing AWS / SSH / DB credentials to external recipient

`UC_4_12` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(All_Email.subject) as subject values(All_Email.recipient) as recipient values(All_Email.src_user) as sender from datamodel=Email.All_Email where All_Email.action="sent" AND All_Email.recipient!="*@yourcorp.com" AND (All_Email.message="*AKIA*" OR All_Email.message="*ASIA*" OR All_Email.message="*aws_secret_access_key*" OR All_Email.message="*BEGIN OPENSSH PRIVATE KEY*" OR All_Email.message="*BEGIN RSA PRIVATE KEY*" OR All_Email.message="*postgres://*" OR All_Email.message="*mysql://*" OR All_Email.message="*mongodb://*" OR All_Email.message="*Server=*Password=*") by All_Email.src_user All_Email.recipient host
| `drop_dm_object_name(All_Email)`
```

**Defender KQL:**
```kql
let credentialMarkers = pack_array(
    "AKIA", "ASIA", "aws_access_key_id", "aws_secret_access_key",
    "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
    "postgres://", "postgresql://", "mysql://", "mongodb://", "mongodb+srv://",
    "Server=", "Password=", "jdbc:", "ssh-rsa");
let internalDomains = dynamic(["yourcorp.com","yourcorp.onmicrosoft.com"]);
let agentMailboxes = dynamic(["pinchy@","openclaw@","agent@","ai-assistant@"]);
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Outbound"
| where SenderFromAddress has_any (agentMailboxes)
    or SenderDisplayName has_any ("OpenClaw","Pinchy","AI Agent","Assistant")
| where not (RecipientEmailAddress has_any (internalDomains))
| extend hits = array_length(set_difference(credentialMarkers, set_difference(credentialMarkers, extract_all("(AKIA|ASIA|aws_secret_access_key|aws_access_key_id|-----BEGIN [A-Z ]+PRIVATE KEY-----|postgres://|mysql://|mongodb://|Server=|jdbc:|ssh-rsa)", tostring(Subject) + " " + tostring(AdditionalFields)))))
| where hits > 0 or AttachmentCount > 0
| project Timestamp, SenderFromAddress, SenderDisplayName, RecipientEmailAddress, Subject, AttachmentCount, EmailDirection, DeliveryAction, NetworkMessageId
| order by Timestamp desc
```

### Unpatched OpenClaw (<2026.4.23) in software inventory — message-object prompt-injection exposure

`UC_4_13` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.process_name="openclaw.exe" OR Processes.process_name="openclaw" by host Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
| join type=left host [| inputlookup asset_inventory.csv | rename hostname as host | fields host product version | search product="OpenClaw"]
| eval is_vulnerable=if(isnotnull(version) AND version<"2026.4.23",1,0)
| where is_vulnerable=1
| table host product version count
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareName has "openclaw" or SoftwareName has "OpenClaw"
| extend versionParts = split(SoftwareVersion, ".")
| extend major = toint(versionParts[0]), minor = toint(versionParts[1]), patch = toint(versionParts[2])
| where major < 2026
    or (major == 2026 and minor < 4)
    or (major == 2026 and minor == 4 and patch < 23)
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, OSPlatform
| order by DeviceName asc
```

### OpenClaw agent process reading cloud / SSH credential files prior to outbound network or mail

`UC_4_14` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstAccess from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*\\.aws\\credentials","*\\.aws\\config","*/.aws/credentials","*/.aws/config","*/.ssh/id_rsa","*/.ssh/id_ed25519","*\\.ssh\\id_rsa","*/etc/kubernetes/admin.conf","*\\kube\\config")) AND Filesystem.process_name IN ("openclaw.exe","openclaw-agent.exe","pinchy.exe","claw-agent.exe") by host Filesystem.process_name Filesystem.file_path Filesystem.user
| `drop_dm_object_name(Filesystem)`
| join type=inner host [| tstats summariesonly=t values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("openclaw.exe","pinchy.exe","claw-agent.exe") AND All_Traffic.dest_category!="internal" by host | rename _time as netTime]
| where netTime >= firstAccess AND netTime - firstAccess < 300
```

**Defender KQL:**
```kql
let credPaths = dynamic(["\\.aws\\credentials","\\.aws\\config","/.aws/credentials","/.aws/config","/.ssh/id_rsa","/.ssh/id_ed25519","\\.ssh\\id_rsa","\\.kube\\config","/etc/kubernetes/admin.conf","\\.docker\\config.json"]);
let agentProcs = dynamic(["openclaw.exe","openclaw-agent.exe","claw-agent.exe","pinchy.exe"]);
let credReads = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("FileCreated","FileModified","FileRenamed") or ActionType startswith "File"
    | where InitiatingProcessFileName in~ (agentProcs)
        or InitiatingProcessFolderPath has_any ("\\OpenClaw\\","/openclaw/","\\Pinchy\\")
    | where FolderPath has_any (credPaths) or FileName has_any ("credentials","id_rsa","id_ed25519","config.json")
    | project credTime=Timestamp, DeviceId, DeviceName, InitiatingProcessFileName, FolderPath, FileName;
let egress = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ (agentProcs)
        or InitiatingProcessFolderPath has_any ("\\OpenClaw\\","/openclaw/","\\Pinchy\\")
    | where RemoteIPType == "Public"
    | project egressTime=Timestamp, DeviceId, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine;
credReads
| join kind=inner egress on DeviceId
| where egressTime between (credTime .. credTime + 5min)
| project credTime, egressTime, DeviceName, InitiatingProcessFileName, FolderPath, FileName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine
| order by credTime desc
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

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 26 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
