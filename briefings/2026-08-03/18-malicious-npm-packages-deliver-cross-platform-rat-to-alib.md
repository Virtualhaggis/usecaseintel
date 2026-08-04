# [HIGH] 18 Malicious npm Packages Deliver Cross-Platform RAT to Alibaba Tool Users

**Source:** The Hacker News
**Published:** 2026-08-03
**Article:** https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html

## Threat Profile

18 Malicious npm Packages Deliver Cross-Platform RAT to Alibaba Tool Users 
 Ravie Lakshmanan  Aug 03, 2026 Malware / Software Supply Chain 
Cybersecurity researchers have discovered a new set of malicious npm packages that target users of Alibaba developer tools with a cross-platform remote access trojan (RAT) as part of a sophisticated, targeted software supply chain attack targeting Chinese-speaking environments.
One of the packages in question is " lib-mtop ," an unscoped package with the …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `aone-cli-next.oss-cn-beijing.aliyuncs.com`
- **Domain (defanged):** `aone-ai-cli.oss-cn-beijing.aliyuncs.com`
- **Domain (defanged):** `aone-kit.oss-cn-beijing.aliyuncs.com`
- **Domain (defanged):** `xemzqli2vu.ai-app.pub`
- **Domain (defanged):** `diamond-cli-znsxphqell.cn-shanghai.fcapp.run`
- **Domain (defanged):** `metrics.femboy.energy`
- **Domain (defanged):** `https://metrics.femboy.energy/v1/collect`
- **Domain (defanged):** `https://webhook.site/710babde-6ace-47fe-83f4-9688e6548df9`
- **SHA256:** `84a6ccaaab1596139d28e822f40cc99c68d337d4c81d1c6d9692c1d6bb22e4af`
- **SHA256:** `6044974c633b3a319c31bb32110411520c425e89722a64806528553227e7a50a`
- **SHA256:** `0910ecfa049738ef3f2540855341a380df89224ff71da94b4c21689fd66f62e3`
- **SHA256:** `b8b81af76163bdcc5b4f7d8fe6795f164991f8a62678c971db031b9e90a27813`
- **SHA256:** `ef9a1896eeaae929800eade768276e2240ef252d26d0d96c1950a1a5e1aadb34`
- **SHA256:** `e5d8350f1540fe91145dc262c455bca7748ad97dafb2d9facd5adebed9f66d2d`
- **SHA256:** `41957bd0ba2d9c07af2e069f10780fdf6b2102c065bebe0db2136dfe07d67a28`
- **SHA256:** `33b58598eb317553942e27545982d4c25ce6120eae10e42393746eb0e02ecae9`

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1204.003** — User Execution: Malicious Image
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1070.004** — Indicator Removal: File Deletion
- **T1620** — Reflective Code Loading
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Malicious @ali-impersonating npm packages installed into node_modules (Alibaba RAT cluster)

`UC_6_9` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*node_modules*lib-mtop*","*node_modules*aone-kit*","*node_modules*aone-kit-cli*","*node_modules*aone-sandbox*","*node_modules*local-config-parser*","*node_modules*smart-config-manager*","*node_modules*cloud-config-fetcher*","*node_modules*fast-transform-pipeline*","*node_modules*aone-cloud-cli*","*node_modules*colder-cli*","*node_modules*def-open-client*","*node_modules*feedback-ai-sdk*","*node_modules*flight-compare-analyzer*","*node_modules*lwp-web-client*","*node_modules*lzd-unified-station-sdk*","*node_modules*open-worker-cli*","*node_modules*test-skill-zip*","*node_modules*uniapi-bridge*")) by Filesystem.dest Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "node_modules"
| where FolderPath has_any ("lib-mtop","aone-kit","aone-kit-cli","aone-sandbox","local-config-parser","smart-config-manager","cloud-config-fetcher","fast-transform-pipeline","aone-cloud-cli","colder-cli","def-open-client","feedback-ai-sdk","flight-compare-analyzer","lwp-web-client","lzd-unified-station-sdk","open-worker-cli","test-skill-zip","uniapi-bridge")
| summarize FirstSeen=min(Timestamp), Files=count(), SampleFile=any(FolderPath) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by FirstSeen desc
```

### npm/node loader spawning curl to fetch remote JavaScript from decoy Alibaba domains

`UC_6_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("curl.exe","curl")) (Processes.parent_process_name IN ("node.exe","node","npm.exe","pnpm.exe","yarn.exe")) (Processes.process="*aliyuncs.com*" OR Processes.process="*fcapp.run*" OR Processes.process="*ai-app.pub*") by Processes.dest Processes.user Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("curl.exe","curl")
| where InitiatingProcessFileName in~ ("node.exe","node","npm.exe","npm","pnpm.exe","yarn.exe")
| where ProcessCommandLine has_any ("aliyuncs.com","fcapp.run","ai-app.pub")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Network callback to decoy Alibaba OSS / Aliyun Function Compute RAT C2 hosts

`UC_6_11` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("aone-cli-next.oss-cn-beijing.aliyuncs.com","aone-ai-cli.oss-cn-beijing.aliyuncs.com","aone-kit.oss-cn-beijing.aliyuncs.com","xemzqli2vu.ai-app.pub","diamond-cli-znsxphqell.cn-shanghai.fcapp.run") by DNS.src DNS.query | `drop_dm_object_name(DNS)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("aone-cli-next.oss-cn-beijing.aliyuncs.com","aone-ai-cli.oss-cn-beijing.aliyuncs.com","aone-kit.oss-cn-beijing.aliyuncs.com","xemzqli2vu.ai-app.pub","diamond-cli-znsxphqell.cn-shanghai.fcapp.run")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Linux RAT payload dropped to /tmp then self-deleted after in-memory load

`UC_6_12` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` values(Filesystem.action) as actions min(_time) as create_time max(_time) as delete_time count from datamodel=Endpoint.Filesystem where Filesystem.file_path="/tmp/*" (Filesystem.action=created OR Filesystem.action=deleted) by Filesystem.dest Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where mvcount(actions)=2 AND (delete_time - create_time) <= 300 | sort - create_time
```

**Defender KQL:**
```kql
let Created = DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where FolderPath startswith "/tmp/"
| where InitiatingProcessFileName in~ ("curl","wget","node","bash","sh")
| project CreateTime=Timestamp, DeviceName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine;
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileDeleted"
| where FolderPath startswith "/tmp/"
| project DeleteTime=Timestamp, DeviceName, FolderPath
| join kind=inner Created on DeviceName, FolderPath
| where DeleteTime between (CreateTime .. CreateTime + 5m)
| project DeviceName, FolderPath, CreateTime, DeleteTime, SecondsAlive=datetime_diff('second', DeleteTime, CreateTime), InitiatingProcessFileName, InitiatingProcessCommandLine
| order by CreateTime desc
```

### macOS RAT persistence via ~/.zshrc injection and 10-minute LaunchAgent

`UC_6_13` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name=".zshrc" OR Filesystem.file_path="*/Library/LaunchAgents/*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | search process_name IN ("node","npm","curl","osascript","sh","bash") | sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FileName == ".zshrc" or FolderPath has "/Library/LaunchAgents/")
| where InitiatingProcessFileName in~ ("node","npm","curl","osascript")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### mrmustard PyPI stealer exfil to metrics.femboy.energy / webhook.site

`UC_6_14` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="metrics.femboy.energy" OR DNS.query="*.femboy.energy" OR DNS.query="webhook.site") by DNS.src DNS.query | `drop_dm_object_name(DNS)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("metrics.femboy.energy","webhook.site/710babde-6ace-47fe-83f4-9688e6548df9")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `aone-cli-next.oss-cn-beijing.aliyuncs.com`, `aone-ai-cli.oss-cn-beijing.aliyuncs.com`, `aone-kit.oss-cn-beijing.aliyuncs.com`, `xemzqli2vu.ai-app.pub`, `diamond-cli-znsxphqell.cn-shanghai.fcapp.run`, `metrics.femboy.energy`, `https://metrics.femboy.energy/v1/collect`, `https://webhook.site/710babde-6ace-47fe-83f4-9688e6548df9`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `84a6ccaaab1596139d28e822f40cc99c68d337d4c81d1c6d9692c1d6bb22e4af`, `6044974c633b3a319c31bb32110411520c425e89722a64806528553227e7a50a`, `0910ecfa049738ef3f2540855341a380df89224ff71da94b4c21689fd66f62e3`, `b8b81af76163bdcc5b4f7d8fe6795f164991f8a62678c971db031b9e90a27813`, `ef9a1896eeaae929800eade768276e2240ef252d26d0d96c1950a1a5e1aadb34`, `e5d8350f1540fe91145dc262c455bca7748ad97dafb2d9facd5adebed9f66d2d`, `41957bd0ba2d9c07af2e069f10780fdf6b2102c065bebe0db2136dfe07d67a28`, `33b58598eb317553942e27545982d4c25ce6120eae10e42393746eb0e02ecae9`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
