# [HIGH] Hades PyPI Attack: 19 Packages Poisoned to Auto-Run Bun Credential Stealer

**Source:** The Hacker News
**Published:** 2026-06-09
**Article:** https://thehackernews.com/2026/06/hades-pypi-attack-19-packages-poisoned.html

## Threat Profile

Hades PyPI Attack: 19 Packages Poisoned to Auto-Run Bun Credential Stealer 
 Ravie Lakshmanan  Jun 09, 2026 Supply Chain Attack / Malware 
The Miasma supply chain campaign has sparked a fresh attack wave called Hades , this time involving 37 malicious wheel artifacts across 19 packages in the Python Package Index (PyPI) registry, as the Mini Shai-Hulud-style attacks continue to be refined and splintered to target specific ecosystems.
"The compromised releases shipped a *-setup.pth file that at…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe`
- **SHA256:** `e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d`
- **SHA256:** `c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1105** — Ingress Tool Transfer
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546** — Event Triggered Execution
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1485** — Data Destruction
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Hades/Miasma PyPI poisoned package installation (26 named packages)

`UC_40_9` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("pip.exe","pip3.exe","pip","pip3","python.exe","python","python3","python3.exe") (Processes.process="*install*") (Processes.process IN ("*bramin*","*cmd2func*","*coolbox*","*dynamo-release*","*executor-engine*","*executor-http*","*funcdesc*","*magique*","*mrbios*","*napari-ufish*","*nucbox*","*okite*","*pantheon-agents*","*pantheon-toolsets*","*spateo-release*","*synago*","*ufish*","*uprobe*","*embiggen*","*ensmallen*","*gpsea*","*mflux-streamlit*","*nhmpy*","*ppkt2synergy*","*pyphetools*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let HadesPkgs = dynamic(["bramin","cmd2func","coolbox","dynamo-release","executor-engine","executor-http","funcdesc","magique","magique-ai","mrbios","napari-ufish","nucbox","okite","pantheon-agents","pantheon-toolsets","spateo-release","synago","ufish","uprobe","embiggen","ensmallen","gpsea","mflux-streamlit","nhmpy","ppkt2synergy","pyphetools"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName in~ ("pip.exe","pip3.exe","pip","pip3","python.exe","python","python3","python3.exe")
      or InitiatingProcessFileName in~ ("pip.exe","pip3.exe","pip","pip3","python.exe","python","python3","python3.exe"))
| where ProcessCommandLine has "install"
| where ProcessCommandLine has_any (HadesPkgs)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Python interpreter downloading Bun runtime ZIP from oven-sh GitHub release

`UC_40_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*github.com/oven-sh/bun*" OR Web.url="*objects.githubusercontent.com*bun-linux*" OR Web.url="*objects.githubusercontent.com*bun-windows*" OR Web.url="*objects.githubusercontent.com*bun-darwin*") (Web.src_user!="") by Web.src Web.src_user Web.url Web.user_agent Web.http_user_agent | `drop_dm_object_name(Web)` | join type=inner src [ | tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name IN ("python.exe","python3.exe","python","python3","pip.exe","pip3.exe") by Processes.dest | rename Processes.dest as src | `drop_dm_object_name(Processes)` ]
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","python","python3","pip.exe","pip3.exe","bash","sh","curl.exe","wget.exe","powershell.exe","pwsh.exe")
| where RemoteUrl has_any ("github.com/oven-sh/bun","objects.githubusercontent.com")
   and (RemoteUrl has_any ("bun-linux","bun-windows","bun-darwin","/releases/download/") or RemoteUrl endswith ".zip")
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where InitiatingProcessFileName in~ ("python.exe","python3.exe","python","python3","pip.exe","pip3.exe")
       or FileName in~ ("python.exe","python3.exe","python","python3","pip.exe","pip3.exe")
    | project DeviceId, PyTimestamp = Timestamp, PyCmd = ProcessCommandLine
) on DeviceId
| where Timestamp between (PyTimestamp .. PyTimestamp + 10m)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, PyCmd
| order by Timestamp desc
```

### Hades persistence: *-setup.pth file written into Python site-packages

`UC_40_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="*-setup.pth" Filesystem.file_path IN ("*\\site-packages\\*","*/site-packages/*","*\\dist-packages\\*","*/dist-packages/*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName endswith "-setup.pth"
| where FolderPath has_any (@"\site-packages\", "/site-packages/", @"\dist-packages\", "/dist-packages/")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Bun runtime reading developer credential files (.npmrc / .pypirc / .ssh / .env / cloud configs)

`UC_40_12` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Filesystem.file_path) as DistinctSecretPaths values(Filesystem.file_path) as Paths min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("bun","bun.exe") (Filesystem.file_path IN ("*.npmrc","*.pypirc","*/.env","*\\.env","*/.aws/credentials","*\\.aws\\credentials","*/.ssh/id_*","*\\.ssh\\id_*","*/.config/gcloud/*","*/.azure/*","*\\.azure\\*","*/.docker/config.json","*/.config/Claude/*","*\\Anthropic\\Claude\\*","*/mcp.json","*/.vault-token","*/.bash_history","*/.zsh_history","*/.jfrog/*","*/.gem/credentials","*/.circleci/cli.yml")) by Filesystem.dest Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where DistinctSecretPaths >= 3
```

**Defender KQL:**
```kql
let SecretPaths = pack_array(".npmrc",".pypirc",".env","credentials","id_rsa","id_ed25519","gcloud",".azure","config.json","mcp.json",".vault-token",".bash_history",".zsh_history","gh-token",".jfrog",".gem");
DeviceFileEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("bun","bun.exe")
| where ActionType in ("FileOpened","FileCreated","FileModified")
   and (FolderPath has_any (@"\.ssh\", "/.ssh/", @"\.aws\", "/.aws/", @"\.azure\", "/.azure/", @"\gcloud\", "/gcloud/", @"\.docker\", "/.docker/", @"\Claude\", "/Claude/", @"\.config\Claude\", @"\.jfrog\", "/.jfrog/")
        or FileName in~ (".npmrc",".pypirc",".env","credentials",".vault-token",".bash_history",".zsh_history","mcp.json")
        or FileName startswith "id_")
| summarize SecretReads = dcount(FolderPath), Paths = make_set(strcat(FolderPath, FileName), 50), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| where SecretReads >= 3
| order by LastSeen desc
```

### gh-token-monitor service install or rm -rf wiper command (Hades self-destruct)

`UC_40_13` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
(`endpoint_processes` OR `linux_processes`)
| eval is_service_install=if(match(process,"(?i)gh-token-monitor") AND (match(process,"(?i)(sc\\.exe|sc\\s+create|systemctl|launchctl|new-service)")),1,0),
       is_wiper=if(match(process,"(?i)rm\\s+-rf\\s+(~/?|/Users/[^/]+|/home/[^/]+)\\s*;\\s*rm\\s+-rf\\s+~?/Documents") OR match(process,"(?i)rm\\s+-rf\\s+~/?\\s*;?\\s*rm\\s+-rf\\s+~/Documents"),1,0)
| where is_service_install=1 OR is_wiper=1
| stats min(_time) as firstTime max(_time) as lastTime values(process) as commands by host user parent_process_name process_name is_service_install is_wiper
```

**Defender KQL:**
```kql
union
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where ProcessCommandLine has "gh-token-monitor"
     and ProcessCommandLine has_any ("sc create","sc.exe create","systemctl","launchctl","New-Service","systemd")
  | extend Pivot = "service_install"
),
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where ProcessCommandLine matches regex @"(?i)rm\s+-rf\s+(~/?|/home/[^/\s]+/?|/Users/[^/\s]+/?)\s*;\s*rm\s+-rf\s+~?/?Documents"
  | extend Pivot = "wiper"
),
( DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "ServiceInstalled"
  | where AdditionalFields has "gh-token-monitor" or FileName has "gh-token-monitor" or ProcessCommandLine has "gh-token-monitor"
  | extend Pivot = "service_event"
)
| project Timestamp, DeviceName, AccountName, Pivot, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Hades C2: GitHub commit search for campaign markers TheBeautifulSnadsOfTime / firedalazer

`UC_40_14` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
(`endpoint_processes` Processes.process IN ("*TheBeautifulSnadsOfTime*","*firedalazer*"))
| eval pivot="process"
| append [ search `web_logs` (url="*TheBeautifulSnadsOfTime*" OR url="*firedalazer*" OR uri_query="*TheBeautifulSnadsOfTime*" OR uri_query="*firedalazer*") | eval pivot="web" ]
| stats min(_time) as firstTime max(_time) as lastTime values(process) as commands values(url) as urls by host user pivot
```

**Defender KQL:**
```kql
let Markers = dynamic(["TheBeautifulSnadsOfTime","firedalazer"]);
union
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where ProcessCommandLine has_any (Markers)
  | extend Pivot = "process", Url = ""
  | project Timestamp, DeviceName, AccountName, Pivot, FileName, ProcessCommandLine, InitiatingProcessFileName, Url
),
( DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has_any (Markers)
  | extend Pivot = "network", FileName = InitiatingProcessFileName, ProcessCommandLine = InitiatingProcessCommandLine, AccountName = InitiatingProcessAccountName
  | project Timestamp, DeviceName, AccountName, Pivot, FileName, ProcessCommandLine, InitiatingProcessFileName, Url = RemoteUrl
)
| order by Timestamp desc
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
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Hades PyPI Attack: 19 Packages Poisoned to Auto-Run Bun Credential Stealer

`UC_40_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hades PyPI Attack: 19 Packages Poisoned to Auto-Run Bun Credential Stealer ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("_index.js","__init__.py","node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("_index.js","__init__.py","node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hades PyPI Attack: 19 Packages Poisoned to Auto-Run Bun Credential Stealer
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("_index.js", "__init__.py", "node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("_index.js", "__init__.py", "node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe`, `e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d`, `c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
