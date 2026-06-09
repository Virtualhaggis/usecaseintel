# [HIGH] Zero-day Extensive NPM Package Compromise - Shai Hulud Supply Chain Attack

**Source:** Snyk
**Published:** 2025-09-15
**Article:** https://snyk.io/blog/embedded-malicious-code-in-tinycolor-and-ngx-bootstrap-releases-on-npm/

## Threat Profile

Snyk Blog In this article
Written by Brian Clark 
September 15, 2025
0 mins read This is an ongoing incident and updates will be provided as more information is confirmed.
Identify how you may have been impacted by this attack with Snyk's featured Zero Day report.
TL;DR (Sep 17, 2025) The attack, which began around September 15, 2025, and came to be dubbed “Shai-Hulud,” is now known to be a worm-like malware that spreads over hundreds of compromised npm packages. The attack aims to steal and exf…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `webhook.site`
- **SHA256:** `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`

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
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1567** — Exfiltration Over Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1083** — File and Directory Discovery
- **T1546** — Event Triggered Execution
- **T1053.005** — Scheduled Task/Job: Scheduled Task (CI workflow analogue)
- **T1552.004** — Unsecured Credentials: Private Keys

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Shai-Hulud bundle.js postinstall payload by known SHA256 hash

`UC_772_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.user) as user values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_hash="46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09" by Filesystem.dest Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let ShaiHuludBundleHash = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09";
union isfuzzy=true
  (DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 == ShaiHuludBundleHash | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
  (DeviceImageLoadEvents | where Timestamp > ago(30d) | where SHA256 == ShaiHuludBundleHash | project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName=tostring(InitiatingProcessAccountName))
| order by Timestamp desc
```

### [LLM] Shai-Hulud worm C2 exfiltration to webhook.site UUID bb8ca5f6

`UC_772_11` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user values(Web.process) as process from datamodel=Web where Web.url="*webhook.site*bb8ca5f6-4175-45d2-b042-fc9ebb8170b7*" by Web.src Web.dest | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let ShaiHuludWebhookPath = "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7";
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "webhook.site" and RemoteUrl has ShaiHuludWebhookPath
   or RemoteUrl has ShaiHuludWebhookPath
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] TruffleHog secret-scanner executed by node/npm postinstall context

`UC_772_12` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where (Processes.process_name="trufflehog" OR Processes.process_name="trufflehog.exe" OR Processes.process="*trufflehog*") (Processes.parent_process_name IN ("node.exe","node","npm.exe","npm-cli.js","pnpm.exe","yarn.exe","npx.exe") OR Processes.parent_process="*node_modules*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "trufflehog" or FileName =~ "trufflehog.exe" or ProcessCommandLine has "trufflehog"
| where InitiatingProcessFileName in~ ("node.exe", "node", "npm.exe", "npm-cli.js", "pnpm.exe", "yarn.exe", "npx.exe", "bash", "sh", "cmd.exe", "powershell.exe")
   and (InitiatingProcessCommandLine has_any ("node_modules", "postinstall", "bundle.js", "npm install", "npm ci", "pnpm install", "yarn install")
        or InitiatingProcessParentFileName in~ ("node.exe", "npm.exe", "pnpm.exe", "yarn.exe"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Shai-Hulud persistence artifact: shai-hulud-workflow.yml file dropped on disk

`UC_772_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path from datamodel=Endpoint.Filesystem where Filesystem.file_name="shai-hulud-workflow.yml" OR (Filesystem.file_name="*.yml" AND Filesystem.file_path="*\\.github\\workflows\\shai-hulud*") by Filesystem.dest Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FileName =~ "shai-hulud-workflow.yml"
   or (FolderPath has @"\.github\workflows\" and FileName startswith "shai-hulud")
   or (FolderPath contains "/.github/workflows/" and FileName startswith "shai-hulud")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Postinstall node child enumerating multiple developer credential stores

`UC_772_14` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Filesystem.file_path) as distinct_secret_paths values(Filesystem.file_path) as secret_paths values(Filesystem.process_name) as process_name min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.process_name IN ("node.exe","node")) (Filesystem.file_path="*\\.npmrc*" OR Filesystem.file_path="*\\.aws\\credentials*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*\\.docker\\config.json*" OR Filesystem.file_path="*/.docker/config.json*" OR Filesystem.file_path="*\\.ssh\\*" OR Filesystem.file_path="*/.ssh/*" OR Filesystem.file_path="*\\.config\\gh\\*" OR Filesystem.file_path="*/.config/gh/*" OR Filesystem.file_path="*\\.gcloud\\*" OR Filesystem.file_path="*/.gcloud/*" OR Filesystem.file_path="*\\.kube\\config*" OR Filesystem.file_path="*/.kube/config*") by Filesystem.dest Filesystem.user Filesystem.process_guid span=5m | where distinct_secret_paths >= 3 | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CredPaths = dynamic([".npmrc", "\\.aws\\credentials", "/.aws/credentials", "\\.docker\\config.json", "/.docker/config.json", "\\.ssh\\", "/.ssh/", "\\.config\\gh\\", "/.config/gh/", "\\.gcloud\\", "/.gcloud/", "\\.kube\\config", "/.kube/config", "\\AppData\\Roaming\\npm\\", "\\AppData\\Local\\GitHub CLI\\"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileOpened", "FileModified", "FileAccessed")
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where InitiatingProcessParentFileName in~ ("npm.exe", "pnpm.exe", "yarn.exe", "npx.exe", "node.exe")
   or InitiatingProcessCommandLine has_any ("node_modules", "postinstall", "bundle.js", "install")
| extend MatchedPath = tostring(parse_json(tostring(CredPaths)))
| where FolderPath has_any (CredPaths) or FileName in~ (".npmrc", "credentials", "config.json", "config")
| summarize DistinctSecrets = dcount(strcat(FolderPath, FileName)),
            SecretPaths = make_set(strcat(FolderPath, FileName), 20),
            ParentCmd = any(InitiatingProcessCommandLine),
            ParentParent = any(InitiatingProcessParentFileName),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
  by DeviceName, InitiatingProcessAccountName, InitiatingProcessId, bin(Timestamp, 5m)
| where DistinctSecrets >= 3
| order by LastSeen desc
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

### Article-specific behavioural hunt — Zero-day Extensive NPM Package Compromise - Shai Hulud Supply Chain Attack

`UC_772_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Zero-day Extensive NPM Package Compromise - Shai Hulud Supply Chain Attack ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("bundle.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("bundle.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Zero-day Extensive NPM Package Compromise - Shai Hulud Supply Chain Attack
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("bundle.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("bundle.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `webhook.site`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
