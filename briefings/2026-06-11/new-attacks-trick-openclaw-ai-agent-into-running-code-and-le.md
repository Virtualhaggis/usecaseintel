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
- **T1059.004** — Unix Shell
- **T1059.006** — Python
- **T1552.001** — Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1039** — Data from Network Shared Drive
- **T1041** — Exfiltration Over C2 Channel
- **T1588.006** — Vulnerabilities
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1059** — Command and Scripting Interpreter
- **T1567** — Exfiltration Over Web Service
- **T1114.003** — Email Forwarding Rule

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### OpenClaw agent runtime spawning OS shell or scripting interpreter

`UC_146_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","python3","python3.exe","node.exe","node","openclaw.exe","openclaw") OR Processes.parent_process IN ("*openclaw*","*open_claw*","*agent_runtime*")) (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","zsh","mshta.exe","rundll32.exe","regsvr32.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where user!="SYSTEM" AND NOT match(user,"\\$$")
```

**Defender KQL:**
```kql
// OpenClaw agent runtime spawning a shell/LOLBin child — Imperva message-object injection path
let AgentParents = dynamic(["python.exe","python3.exe","python3","node.exe","node","openclaw.exe","openclaw"]);
let SuspiciousChildren = dynamic(["cmd.exe","powershell.exe","pwsh.exe","bash.exe","wsl.exe","mshta.exe","rundll32.exe","regsvr32.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe","wscript.exe","cscript.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (AgentParents)
   or InitiatingProcessCommandLine has_any ("openclaw","open_claw","agent_runtime","-m openclaw")
| where FileName in~ (SuspiciousChildren)
   or ProcessCommandLine has_any ("curl ","wget ","Invoke-WebRequest","DownloadString","IEX ","bash -c","sh -c")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, FolderPath, SHA256,
          InitiatingProcessTokenElevation, InitiatingProcessIntegrityLevel
| order by Timestamp desc
```

### OpenClaw agent process reading or shelling against credential file paths

`UC_146_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.process_name IN ("python.exe","python3","python3.exe","node.exe","node","openclaw.exe") OR Filesystem.process IN ("*openclaw*","*open_claw*","*agent_runtime*")) (Filesystem.file_path IN ("*\\.ssh\\*","*\\.aws\\credentials*","*\\.aws\\config*","*\\.env*","*\\.gcloud\\*","*\\.kube\\config*","*\\.docker\\config.json*","*/root/.ssh/*","*/home/*/.aws/*","*/etc/shadow*","*/etc/passwd*","*credential*","*secrets.yaml*","*secrets.yml*")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// OpenClaw runtime reading credential files — Varonis agent-phishing exfil path
let AgentImages = dynamic(["python.exe","python3.exe","python3","node.exe","node","openclaw.exe","openclaw"]);
let CredentialPaths = dynamic([
    "\\.ssh\\","\\.aws\\credentials","\\.aws\\config",
    "\\.gcloud\\","\\.kube\\config","\\.docker\\config.json",
    "\\AppData\\Roaming\\.env","\\secrets\\","credentials.json",
    "/root/.ssh","/home/","/.aws/credentials","/etc/shadow","/etc/kubernetes/"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed","FileAccessed")
   or isempty(ActionType)
| where InitiatingProcessFileName in~ (AgentImages)
    or InitiatingProcessCommandLine has_any ("openclaw","open_claw","agent_runtime")
| where FolderPath has_any (CredentialPaths)
    or FileName in~ (".env","credentials","id_rsa","id_ed25519","config.json","secrets.yaml")
| project Timestamp, DeviceName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessAccountUpn, SHA256
| order by Timestamp desc
```

### Vulnerable OpenClaw deployment (<2026.4.23) — pre-patch vCard injection exposure

`UC_146_12` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="openclaw.exe" OR Processes.process="*openclaw*" OR Processes.process="*open_claw*" OR Processes.process="*-m openclaw*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_version | `drop_dm_object_name(Processes)` | rex field=process "openclaw[ _-]?v?(?<oc_version>\d{4}\.\d+\.\d+)" | where isnotnull(oc_version) | eval major=tonumber(mvindex(split(oc_version,"."),0)), minor=tonumber(mvindex(split(oc_version,"."),1)), patch=tonumber(mvindex(split(oc_version,"."),2)) | where major<2026 OR (major=2026 AND minor<4) OR (major=2026 AND minor=4 AND patch<23) | table firstTime lastTime dest user oc_version process
```

**Defender KQL:**
```kql
// Pre-patch OpenClaw build exposed to Imperva vCard/contact/location injection (fix shipped in 2026.4.23)
let VulnVersionRegex = @"(?i)openclaw[ _\-]?v?(\d{4})\.(\d+)\.(\d+)";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("openclaw.exe","python.exe","python3.exe","node.exe")
| where InitiatingProcessCommandLine matches regex VulnVersionRegex
    or ProcessCommandLine matches regex VulnVersionRegex
| extend OcVersion = extract_all(VulnVersionRegex, dynamic([1,2,3]), strcat(InitiatingProcessCommandLine, " ", ProcessCommandLine))
| mv-expand OcVersion
| extend Major = toint(OcVersion[0]), Minor = toint(OcVersion[1]), Patch = toint(OcVersion[2])
| where Major < 2026
    or (Major == 2026 and Minor < 4)
    or (Major == 2026 and Minor == 4 and Patch < 23)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Sample = any(InitiatingProcessCommandLine)
          by DeviceName, AccountName, Major, Minor, Patch
| order by LastSeen desc
```

### OpenClaw agent connecting to Imperva PoC artifact host

`UC_146_13` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="imperva_artifactory.com" OR DNS.query="*.imperva_artifactory.com" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=t count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="imperva_artifactory.com" OR All_Traffic.dest_host="imperva_artifactory.com" by All_Traffic.src All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)`]
```

**Defender KQL:**
```kql
// IOC: imperva_artifactory.com — Imperva PoC payload host (article-cited)
let C2 = dynamic(["imperva_artifactory.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (C2)
   or tostring(parse_url(RemoteUrl).Host) has_any (C2)
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### OpenClaw agent prompt-injection markers in agent application logs

`UC_146_14` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* sourcetype IN ("openclaw:agent","openclaw:prompt","openclaw:tool","syslog") ("<contact:" OR "<vcard:" OR "<location:") ("ignore previous instructions" OR "system:" OR "download " OR "curl " OR "wget " OR "exec(" OR "os.system" OR "subprocess" OR "rm -rf" OR "bash -c") | rex field=_raw "<(?<obj_type>contact|vcard|location):\s*(?<obj_name>[^,>]{20,})" | where isnotnull(obj_name) | table _time host source obj_type obj_name _raw
```

**Defender KQL:**
```kql
// Imperva injection markers + Varonis social-pretext phrases reaching the OpenClaw agent
let InjectionMarkers = dynamic([
    "<contact:","<vcard:","<location:",
    "ignore previous instructions","system:","</system>",
    "download and run","curl http","wget http","bash -c","powershell -c",
    "forward to","reply with the","send to outside"]);
let SocialPretexts = dynamic([
    "production incident","staging access","QBR deck",
    "weekly customer export","team lead","urgent"]);
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has_cs "OpenClaw" or ApplicationId has "openclaw"
| where tostring(RawEventData) has_any (InjectionMarkers)
    or tostring(RawEventData) has_any (SocialPretexts)
| project Timestamp, Application, AccountDisplayName, ActionType,
          IPAddress, UserAgent, RawEventData
| order by Timestamp desc
```

### OpenClaw agent sending outbound mail to first-time external recipient

`UC_146_15` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Email.Email where All_Email.direction=outbound by All_Email.src_user All_Email.recipient | `drop_dm_object_name(All_Email)` | eval rcpt_domain=mvindex(split(recipient,"@"),1) | join type=left src_user [| tstats summariesonly=t earliest(_time) as baseline_first from datamodel=Email.Email where All_Email.direction=outbound earliest=-30d@d latest=-1h by All_Email.src_user All_Email.recipient | `drop_dm_object_name(All_Email)` | rename recipient as baseline_rcpt] | where isnull(baseline_first) AND match(src_user,"(?i)openclaw|agent|pinchy|bot") AND NOT match(rcpt_domain,"(?i)mycompany\.com$|mycorp\.local$")
```

**Defender KQL:**
```kql
// Agent identity sending to a recipient it has never sent to in the prior 30d (Varonis Pinchy exfil shape)
let Lookback = 30d;
let RecentWindow = 1h;
let AgentSenderPattern = @"(?i)openclaw|agent|pinchy|bot";
let Baseline = EmailEvents
    | where Timestamp between (ago(Lookback) .. ago(RecentWindow))
    | where EmailDirection == "Outbound"
    | where SenderFromAddress matches regex AgentSenderPattern
    | summarize by SenderFromAddress, RecipientEmailAddress;
EmailEvents
| where Timestamp > ago(RecentWindow)
| where EmailDirection == "Outbound"
| where SenderFromAddress matches regex AgentSenderPattern
| join kind=leftanti Baseline on SenderFromAddress, RecipientEmailAddress
| extend RcptDomain = tolower(tostring(split(RecipientEmailAddress, "@")[1]))
| where RcptDomain !endswith "yourcorp.com"   // tune per tenant
| project Timestamp, SenderFromAddress, RecipientEmailAddress, RcptDomain,
          Subject, AttachmentCount, UrlCount, NetworkMessageId
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

Severity classified as **HIGH** based on: IOCs present, 16 use case(s) fired, 30 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
