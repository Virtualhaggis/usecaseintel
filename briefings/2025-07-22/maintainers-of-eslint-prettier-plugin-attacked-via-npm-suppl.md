# [CRIT] Maintainers of ESLint Prettier Plugin Attacked via npm Supply Chain Malware

**Source:** Snyk
**Published:** 2025-07-22
**Article:** https://snyk.io/blog/maintainers-of-eslint-prettier-plugin-attacked-via-npm-supply-chain-malware/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
July 22, 2025
0 mins read Starting on July 19th, 2025, an npm supply chain security incident has been attacking maintainers of popular open-source npm packages on the npm registry
The TL;DR on the npm malware Adversarial attackers have registered the domain npnjs.com (typosquatting a look-alike over the official npmjs.com registry)
Maintainers were victim for email phishing campaign that hijacked their npm registry credentials
Impacted packages: es…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-54313`
- **Domain (defanged):** `npnjs.com`
- **SHA256:** `c68e42f416f482d43653f36cd14384270b54b68d6496a8e34ce887687de5b441`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1218.011** — System Binary Proxy Execution: Rundll32
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1568** — Dynamic Resolution
- **T1566.002** — Phishing: Spearphishing Link
- **T1583.001** — Acquire Infrastructure: Domains
- **T1195.002** — Supply Chain Compromise
- **T1105** — Ingress Tool Transfer
- **T1497** — Virtualization/Sandbox Evasion
- **T1036** — Masquerading

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] rundll32.exe loading node-gyp.dll dropped by Scavenger-infected npm postinstall (CVE-2025-54313)

`UC_804_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="rundll32.exe" Processes.process="*node-gyp.dll*" (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="npm.exe" OR Processes.parent_process_name="yarn.exe" OR Processes.parent_process_name="pnpm.exe" OR Processes.parent_process="*install.js*" OR Processes.parent_process="*npm-cli.js*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has "node-gyp.dll"
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe","cmd.exe")
    or InitiatingProcessCommandLine has_any ("install.js","npm-cli.js","npm.cmd"," yarn "," pnpm ","node_modules")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ChildCmd = ProcessCommandLine,
          ParentImage = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          GrandparentImage = InitiatingProcessParentFileName,
          SHA256, FolderPath
| order by Timestamp desc
```

### [LLM] Scavenger Stealer C2 beacon to corroborated infrastructure (datahog.su / datalytica.su / smartscreen-api.com)

`UC_804_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("datahog.su","*.datahog.su","datalytica.su","*.datalytica.su","datacrab-analytics.com","*.datacrab-analytics.com","dieorsuffer.com","*.dieorsuffer.com","firebase.su","*.firebase.su","smartscreen-api.com","*.smartscreen-api.com") by DNS.src DNS.dest DNS.query DNS.answer | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let ScavengerC2 = dynamic(["datahog.su","datalytica.su","datacrab-analytics.com","dieorsuffer.com","firebase.su","smartscreen-api.com"]);
DeviceNetworkEvents
| where Timestamp > ago(60d)
| extend Host = tolower(tostring(parse_url(RemoteUrl).Host))
| where Host has_any (ScavengerC2)
    or RemoteUrl has_any (ScavengerC2)
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### [LLM] npm registry typosquat npnjs.com — DNS / URL click (eslint-config-prettier maintainer phishing kit)

`UC_804_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("npnjs.com","*.npnjs.com") by DNS.src DNS.dest DNS.query DNS.answer | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats summariesonly=true count from datamodel=Web.Web where Web.url="*npnjs.com*" by Web.src Web.user Web.url | `drop_dm_object_name(Web)` ]
```

**Defender KQL:**
```kql
union isfuzzy=true
    (UrlClickEvents
        | where Timestamp > ago(90d)
        | where Url has "npnjs.com"
        | project Timestamp, AccountUpn, Url, Workload, ActionType, Source = "UrlClickEvents"),
    (DeviceNetworkEvents
        | where Timestamp > ago(90d)
        | where RemoteUrl has "npnjs.com"
        | project Timestamp, DeviceName, AccountUpn = InitiatingProcessAccountUpn, Url = RemoteUrl, Process = InitiatingProcessFileName, Source = "DeviceNetworkEvents"),
    (EmailUrlInfo
        | where Timestamp > ago(90d)
        | where Url has "npnjs.com"
        | project Timestamp, NetworkMessageId, Url, UrlDomain, Source = "EmailUrlInfo")
| order by Timestamp desc
```

### [LLM] Scavenger Loader DLL (node-gyp.dll) written inside node_modules of CVE-2025-54313 packages

`UC_804_11` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="node-gyp.dll" Filesystem.file_path="*\\node_modules\\*" (Filesystem.file_path="*\\eslint-config-prettier\\*" OR Filesystem.file_path="*\\eslint-plugin-prettier\\*" OR Filesystem.file_path="*\\synckit\\*" OR Filesystem.file_path="*\\@pkgr\\core\\*" OR Filesystem.file_path="*\\napi-postinstall\\*" OR Filesystem.file_path="*\\got-fetch\\*" OR Filesystem.file_path="*\\node_modules\\is\\*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CompromisedPkgPaths = dynamic([
    @"\node_modules\eslint-config-prettier\",
    @"\node_modules\eslint-plugin-prettier\",
    @"\node_modules\synckit\",
    @"\node_modules\@pkgr\core\",
    @"\node_modules\napi-postinstall\",
    @"\node_modules\got-fetch\",
    @"\node_modules\is\"
]);
DeviceFileEvents
| where Timestamp > ago(60d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName =~ "node-gyp.dll"
| where FolderPath has_any (CompromisedPkgPaths)
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
          FolderPath, FileName, SHA256, FileSize,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Scavenger Stealer sandbox-evasion marker file %TEMP%\SCVNGR_VM created

`UC_804_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\Temp\\*SCVNGR_VM*" by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has "SCVNGR_VM" or FileName has "SCVNGR_VM"
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
          FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-54313`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `npnjs.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c68e42f416f482d43653f36cd14384270b54b68d6496a8e34ce887687de5b441`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 13 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
