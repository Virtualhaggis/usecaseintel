# [CRIT] Miasma Supply Chain Attack Compromises Red Hat npm Packages with Credential-Stealing Worm

**Source:** The Hacker News
**Published:** 2026-06-01
**Article:** https://thehackernews.com/2026/06/miasma-supply-chain-attack-compromises.html

## Threat Profile

Miasma Supply Chain Attack Compromises Red Hat npm Packages with Credential-Stealing Worm 
 Ravie Lakshmanan  Jun 01, 2026 Supply Chain Attack / Software Security 
A new Mini Shai-Hulud supply chain attack campaign, codenamed Miasma , has compromised @redhat-cloud-services packages to steal credentials and secrets from developer machines and deliver a self-propagating worm.
"This is effectively a Mini Shai-Hulud campaign: it uses the same core tactics of install-time execution, credential harv…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45585`
- **CVE:** `CVE-2026-31635`
- **CVE:** `CVE-2026-42945`
- **Domain (defanged):** `api.anthropic.com`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1140** — Deobfuscate/Decode Files or Information
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] npm preinstall executing oversized index.js from @redhat-cloud-services scope

`UC_109_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="npm*" OR Processes.parent_process_name="npm-cli.js" OR Processes.parent_process_name="yarn*" OR Processes.parent_process_name="pnpm*" Processes.process_name IN ("node.exe","node") (Processes.process="*node_modules/@redhat-cloud-services/*index.js*" OR Processes.process="*node_modules\\@redhat-cloud-services\\*index.js*") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | rename firstTime as firstTime_proc | join type=outer dest [| tstats `summariesonly` max(Filesystem.file_size) as IndexSize from datamodel=Endpoint.Filesystem where Filesystem.file_path="*node_modules*@redhat-cloud-services*index.js" by Filesystem.dest Filesystem.file_path | `drop_dm_object_name(Filesystem)`] | where IndexSize > 524288 OR isnull(IndexSize)
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
let ScopePath = @"node_modules\@redhat-cloud-services\";
let ScopePathNix = "node_modules/@redhat-cloud-services/";
let HeavyDrop = DeviceFileEvents
    | where Timestamp > ago(LookbackDays)
    | where (FolderPath has ScopePath or FolderPath has ScopePathNix)
    | where FileName =~ "index.js"
    | where FileSize > 524288
    | project DropTime = Timestamp, DeviceId, DeviceName, FolderPath, FileSize, SHA256;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName has_any ("npm","npm-cli.js","yarn","pnpm","npm.cmd","node.exe","node")
| where FileName in~ ("node.exe","node")
| where ProcessCommandLine has "index.js"
| where ProcessCommandLine has "@redhat-cloud-services" or ProcessCommandLine has ScopePath or ProcessCommandLine has ScopePathNix
| join kind=inner HeavyDrop on DeviceId
| where DropTime between (Timestamp - 5m .. Timestamp + 5m)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, IndexPath = FolderPath1, IndexSize = FileSize, SHA256
| order by Timestamp desc
```

### [LLM] Node-driven Bun runtime download from oven-sh GitHub Releases during npm install

`UC_109_11` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.process_name IN ("node.exe","node") (Web.url="*github.com/oven-sh/bun/releases*" OR Web.url="*objects.githubusercontent.com*bun-v1.3.13*" OR Web.url="*release-assets.githubusercontent.com*bun-v1.3.13*") by Web.dest Web.src Web.user Web.url Web.http_user_agent Web.process_name | `drop_dm_object_name(Web)` | join type=outer dest [| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.file_path="/tmp/*bun*" Filesystem.file_name="bun" by Filesystem.dest Filesystem.file_path | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
let BunDrop = DeviceFileEvents
    | where Timestamp > ago(LookbackDays)
    | where FolderPath startswith "/tmp/" or FolderPath has @"\Temp\"
    | where FileName =~ "bun" or FileName =~ "bun.exe" or FileName endswith ".tar.gz" and FileName has "bun-v1.3.13"
    | project DropTime = Timestamp, DeviceId, DropPath = FolderPath, DropFile = FileName, DropSHA256 = SHA256, DropInitiator = InitiatingProcessFileName, DropInitiatorCmd = InitiatingProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where RemoteUrl has_any ("github.com/oven-sh/bun","objects.githubusercontent.com","release-assets.githubusercontent.com")
   and RemoteUrl has "bun-v1.3.13"
| join kind=inner BunDrop on DeviceId
| where DropTime between (Timestamp - 2m .. Timestamp + 5m)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, DropPath, DropFile, DropSHA256
| order by Timestamp desc
```

### [LLM] Stage-4 implant written to /tmp/p<random>.js and executed by freshly dropped Bun binary

`UC_109_12` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="bun" Processes.parent_process_name IN ("node","node.exe") (Processes.process="*/tmp/p*.js*" OR Processes.process_path="/tmp/*") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | regex process="/tmp/p[A-Za-z0-9]{4,}\.js"
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where FileName =~ "bun" or FileName =~ "bun.exe"
| where FolderPath startswith "/tmp/" or FolderPath has @"\Temp\"
| where InitiatingProcessFileName in~ ("node","node.exe")
| where ProcessCommandLine matches regex @"/tmp/p[A-Za-z0-9]{3,}\.js"
   or ProcessCommandLine matches regex @"\\Temp\\p[A-Za-z0-9]{3,}\.js"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] CI runner reading cloud-provider credential env files immediately after npm install

`UC_109_13` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.file_path) as paths min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("node","node.exe","bun","bun.exe") (Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.config/gcloud/*" OR Filesystem.file_path="*/.azure/*" OR Filesystem.file_path="*/.kube/config" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.circleci/config*" OR Filesystem.file_path="*/vault/token" OR Filesystem.file_path="*/.vault-token" OR Filesystem.file_path="*/RUNNER_TOKEN*" OR Filesystem.file_path="*/_temp/_runner_file_commands/*" OR Filesystem.file_path="*GITHUB_TOKEN*") by Filesystem.dest Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where mvcount(paths) >= 3
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let CredPaths = dynamic([".aws/credentials",".aws/config",".config/gcloud",".azure/",".kube/config",".npmrc",".circleci/config","vault/token",".vault-token","_runner_file_commands","actions/runner","RUNNER_TOKEN","GITHUB_TOKEN"]);
DeviceFileEvents
| where Timestamp > ago(LookbackDays)
| where ActionType in ("FileAccessed","FileOpened","FileModified","FileCreated")
| where InitiatingProcessFileName in~ ("node","node.exe","bun","bun.exe")
| where FolderPath has_any (CredPaths) or FileName has_any (CredPaths)
| summarize HitPaths = make_set(strcat(FolderPath, "/", FileName), 25),
            DistinctTargets = dcount(strcat(FolderPath, FileName)),
            FirstHit = min(Timestamp),
            LastHit = max(Timestamp)
            by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| where DistinctTargets >= 2
| order by LastHit desc
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

### Article-specific behavioural hunt — Miasma Supply Chain Attack Compromises Red Hat npm Packages with Credential-Stea

`UC_109_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Miasma Supply Chain Attack Compromises Red Hat npm Packages with Credential-Stea ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/sudoers.d*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Miasma Supply Chain Attack Compromises Red Hat npm Packages with Credential-Stea
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/sudoers.d"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-45585`, `CVE-2026-31635`, `CVE-2026-42945`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `api.anthropic.com`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
