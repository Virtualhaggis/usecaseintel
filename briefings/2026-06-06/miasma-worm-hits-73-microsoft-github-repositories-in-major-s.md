# [HIGH] Miasma Worm Hits 73 Microsoft GitHub Repositories in Major Supply Chain Attack

**Source:** The Hacker News
**Published:** 2026-06-06
**Article:** https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html

## Threat Profile

Miasma Worm Hits 73 Microsoft GitHub Repositories in Major Supply Chain Attack 
 Ravie Lakshmanan  Jun 06, 2026 Supply Chain Attack / Malware 
Microsoft's GitHub repositories have become the latest to fall victim to the ongoing Miasma self-replicating supply chain attack campaign.
The incident impacted 73 Microsoft repositories across four of its GitHub organizations, including Azure, Azure-Samples, Microsoft, and MicrosoftDocs, per OpenSourceMalware . The development has GitHub to disable acc…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `d630397de8b01af0f6f5cf4463da91b17f28195a2c50c8f3f38ad9f7873fdb8e`
- **SHA256:** `3a9db5ba0c8cd4c91e91717df6b1a141fc1e0fbc0558b5a78d7f5c23f5b2a150`
- **SHA256:** `633c8410ee0413ca4b090a19c30b20c03f31598c25247c484846fa34c1df5b64`
- **SHA256:** `ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90`

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
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1567.001** — Exfiltration to Code Repository
- **T1567** — Exfiltration Over Web Service
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1036.005** — Masquerading: Match Legitimate Name
- **T1105** — Ingress Tool Transfer
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1555** — Credentials from Password Stores

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GitHub repo created with Miasma/Hades worm signature description

`UC_88_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`github_audit` action="repo.create" OR action="public" OR action="repo.access" 
| eval desc=lower(coalesce(description, repo_description, _raw)) 
| where match(desc, "miasma\s*[:\-]?\s*the spreading blight") OR match(desc, "hades\s*-\s*the end for the damned") 
| stats min(_time) as firstSeen, values(repo) as repos, values(actor) as actors, count by org 
| sort - count
```

**Defender KQL:**
```kql
// Requires Defender for Cloud Apps GitHub Enterprise connector
let MiasmaDesc = dynamic(["Miasma: The Spreading Blight","Miasma : The Spreading Blight","Miasma - The Spreading Blight","Hades - The End for the Damned"]);
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "GitHub"
| where ActionType has_any ("Repository created","Create repository","repo.create","public")
| extend RepoDesc = tostring(RawEventData.description)
| extend RepoName = tostring(RawEventData.repository.name)
| extend ActorLogin = tostring(RawEventData.actor)
| where RepoDesc in~ (MiasmaDesc) or RepoDesc matches regex @"(?i)miasma\s*[: -]\s*the spreading blight" or RepoDesc matches regex @"(?i)hades\s*-\s*the end for the damned"
| project Timestamp, Application, ActorLogin, RepoName, RepoDesc, IPAddress, CountryCode, ReportId
| order by Timestamp desc
```

### AI coding agent spawning Bun runtime — Miasma loader detonation

`UC_88_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Processes.process) as cmd values(Processes.process_path) as path from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("claude","claude.exe","claude-code","gemini","gemini.exe","gemini-cli","cursor","Cursor.exe","code","Code.exe","code-insiders") OR (Processes.parent_process_name="node" AND match(Processes.parent_process, "(?i)(npm\s+(run\s+)?test|jest|vitest|mocha)"))) AND (Processes.process_name="bun" OR Processes.process_name="bun.exe" OR match(Processes.process_path, "(?i)(/tmp/b-|/var/folders/.+/b-|\\AppData\\Local\\Temp\\b-).+bun")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process 
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
let AiAgents = dynamic(["claude.exe","claude","claude-code","gemini.exe","gemini","gemini-cli","cursor.exe","Cursor","code.exe","Code","code-insiders.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "bun" or FileName =~ "bun.exe" or FolderPath matches regex @"(?i)(/tmp/b-|/var/folders/.+/b-|\\AppData\\Local\\Temp\\b-)[^/\\]+[\\/]bun"
| where InitiatingProcessFileName in~ (AiAgents)
   or (InitiatingProcessFileName in~ ("node","node.exe","npm.cmd","npm","pnpm","yarn") and InitiatingProcessCommandLine matches regex @"(?i)\b(npm\s+(run\s+)?test|jest|vitest|mocha)\b")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Bun runtime executed from random temp-dir path — Miasma staged loader artifact

`UC_88_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen values(Processes.process) as cmds values(Processes.parent_process) as parents from datamodel=Endpoint.Processes where Processes.process_name IN ("bun","bun.exe") AND (match(Processes.process_path, "(?i)/tmp/b-[a-z0-9]+/bun") OR match(Processes.process_path, "(?i)/var/folders/[^/]+/[^/]+/[^/]+/b-[a-z0-9]+/bun") OR match(Processes.process_path, "(?i)\\\\AppData\\\\Local\\\\Temp\\\\b-[a-z0-9]+\\\\bun\\.exe")) by Processes.dest Processes.user Processes.process_path Processes.process_hash 
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "bun" or FileName =~ "bun.exe"
| where FolderPath matches regex @"(?i)(/tmp/b-[a-z0-9]+/bun$|/var/folders/[^/]+/[^/]+/[^/]+/b-[a-z0-9]+/bun$|\\AppData\\Local\\Temp\\b-[a-z0-9]+\\bun\.exe$)"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Multi-megabyte staged Miasma loader JS dropped to OS temp

`UC_88_9` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Filesystem.file_size) as size values(Filesystem.process_name) as writer from datamodel=Endpoint.Filesystem where (match(Filesystem.file_path, "(?i)^/tmp/p[a-z0-9]{4,16}\\.js$") OR match(Filesystem.file_path, "(?i)^/var/folders/[^/]+/[^/]+/[^/]+/p[a-z0-9]{4,16}\\.js$")) AND Filesystem.file_size > 3000000 by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process 
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath matches regex @"(?i)(^/tmp/$|^/tmp$|^/var/folders/[^/]+/[^/]+/[^/]+/?$)" or FolderPath startswith "/tmp" or FolderPath contains "/var/folders/"
| where FileName matches regex @"(?i)^p[a-z0-9]{4,16}\.js$"
| where FileSize > 3000000
| project Timestamp, DeviceName, FolderPath, FileName, FileSize, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Bun runtime contacting cloud instance-metadata endpoint — Miasma credential collection

`UC_88_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(All_Traffic.dest_ip) as ips values(All_Traffic.dest_port) as ports values(All_Traffic.process_name) as proc from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process_name IN ("bun","bun.exe")) AND (All_Traffic.dest_ip="169.254.169.254" OR All_Traffic.dest="metadata.google.internal" OR All_Traffic.dest="169.254.170.2" OR All_Traffic.dest="metadata.azure.com" OR match(All_Traffic.dest, "(?i)(vault|secrets|1password|bitwarden|managedidentity)")) by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.process 
| `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
let MetaIPs = dynamic(["169.254.169.254","169.254.170.2","100.100.100.200"]);
let MetaHosts = dynamic(["metadata.google.internal","metadata.azure.com","login.microsoftonline.com","169.254.169.254","vault.","secrets.","1password.com","bitwarden.com","my.1password.com"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "bun" or InitiatingProcessFileName =~ "bun.exe" or InitiatingProcessFolderPath matches regex @"(?i)(/tmp/b-|/var/folders/.+/b-|\\AppData\\Local\\Temp\\b-)"
| where RemoteIP in (MetaIPs) or RemoteUrl has_any (MetaHosts)
| project Timestamp, DeviceName, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemoteUrl, RemotePort, Protocol
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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `d630397de8b01af0f6f5cf4463da91b17f28195a2c50c8f3f38ad9f7873fdb8e`, `3a9db5ba0c8cd4c91e91717df6b1a141fc1e0fbc0558b5a78d7f5c23f5b2a150`, `633c8410ee0413ca4b090a19c30b20c03f31598c25247c484846fa34c1df5b64`, `ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
