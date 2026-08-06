# [CRIT] Chinese Hacker Commands DeepSeek via Telegram to Launch Autonomous Attacks

**Source:** The Hacker News
**Published:** 2026-07-31
**Article:** https://thehackernews.com/2026/07/chinese-hacker-commands-deepseek-via.html

## Threat Profile

Chinese Hacker Commands DeepSeek via Telegram to Launch Autonomous Attacks 
 Swati Khandelwal  Jul 31, 2026 Artificial Intelligence / Cyber Attack 
Palo Alto Networks' Unit 42 says a Chinese-speaking threat actor used DeepSeek through the open-source Hermes Agent framework to launch attacks autonomously.
After an initial Telegram instruction, the agent found internet-facing systems and selected public exploits. The researchers recovered no further operator input in the session.
The operator, t…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33017`
- **CVE:** `CVE-2026-21858`
- **CVE:** `CVE-2025-68613`
- **CVE:** `CVE-2026-3055`
- **CVE:** `CVE-2026-39987`
- **CVE:** `CVE-2026-34486`
- **CVE:** `CVE-2026-0300`
- **CVE:** `CVE-2026-33824`
- **Domain (defanged):** `code.newcli.com`

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
- **T1071** — Application Layer Protocol
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1595.002** — Active Scanning: Vulnerability Scanning
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1608.001** — Stage Capabilities: Upload Malware
- **T1105** — Ingress Tool Transfer
- **T1102.002** — Web Service: Bidirectional Communication
- **T1539** — Steal Web Session Cookie
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Marimo pre-auth RCE (CVE-2026-39987): marimo/python parent spawning a shell (PTY)

`UC_104_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process="*marimo*" OR Processes.parent_process="*/terminal/ws*") AND Processes.process_name IN ("sh","bash","dash","zsh","ash") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| where user!="root" OR like(parent_process,"%marimo%")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (InitiatingProcessCommandLine has "marimo" or InitiatingProcessFolderPath has "marimo")
| where FileName in~ ("sh","bash","dash","zsh","ash")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ChildProcess = FileName, ChildCmd = ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Langflow CVE-2026-33017 exploitation: scanner tooling and langflow exec-to-shell

`UC_104_8` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*langflow_poc.py*" OR Processes.process="*langflow_targets.txt*") OR (Processes.parent_process="*langflow*" AND Processes.process_name IN ("sh","bash","dash","zsh")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("langflow_poc.py","langflow_targets.txt")
    or (InitiatingProcessCommandLine has "langflow" and FileName in~ ("sh","bash","dash","zsh","ash"))
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ChildProcess = FileName, ChildCmd = ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### n8n exploit chain (CVE-2026-21858 + CVE-2025-68613): node process spawning a shell

`UC_104_9` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process="*n8n*" AND Processes.parent_process_name IN ("node","node.js")) AND Processes.process_name IN ("sh","bash","dash","zsh","ash") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node","node.js")
| where (InitiatingProcessCommandLine has "n8n" or InitiatingProcessFolderPath has "n8n")
| where FileName in~ ("sh","bash","dash","zsh","ash")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, ChildProcess = FileName, ChildCmd = ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Hermes AI agent OPSEC leak: python3 -m http.server 8888 from home directory

`UC_104_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*http.server*8888*" AND Processes.process_name IN ("python3","python") by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("python3","python")
| where ProcessCommandLine has "http.server" and ProcessCommandLine has "8888"
| extend HighFidelity = iff(AccountName =~ "worker", "worker-account", "other")
| project Timestamp, DeviceName, AccountName, HighFidelity, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Autonomous attack-agent egress to LLM inference APIs from non-browser process

`UC_104_11` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("api.deepseek.com","dashscope.aliyuncs.com","code.newcli.com") by DNS.src DNS.query
| `drop_dm_object_name(DNS)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any ("api.deepseek.com","dashscope.aliyuncs.com","code.newcli.com")
| where InitiatingProcessFileName in~ ("python3","python","node","curl","wget","go","sh","bash")
| where InitiatingProcessAccountName !endswith "$"
| summarize Count = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Procs = make_set(InitiatingProcessFileName, 8), Domains = make_set(RemoteUrl, 8) by DeviceName, InitiatingProcessAccountName
| order by FirstSeen desc
```

### Hermes agent C2 fingerprint: Telegram Bot API + LLM inference API from same host

`UC_104_12` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS where DNS.query IN ("api.telegram.org","api.deepseek.com","dashscope.aliyuncs.com","code.newcli.com") by DNS.src DNS.query
| `drop_dm_object_name(DNS)`
| eval group=if(query=="api.telegram.org","telegram","llm")
| stats dc(group) as groups values(query) as domains by src
| where groups>=2
```

**Defender KQL:**
```kql
let win = 1h;
let llm = DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemoteUrl has_any ("api.deepseek.com","dashscope.aliyuncs.com","code.newcli.com")
    | project DeviceId, DeviceName, LlmTime = Timestamp, LlmUrl = RemoteUrl, LlmProc = InitiatingProcessFileName;
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has "api.telegram.org"
| project DeviceId, DeviceName, TgTime = Timestamp, TgProc = InitiatingProcessFileName
| join kind=inner llm on DeviceId
| where abs(datetime_diff('minute', TgTime, LlmTime)) <= 60
| project DeviceName, DeviceId, TgTime, LlmTime, TgProc, LlmProc, LlmUrl
| order by TgTime desc
```

### NetScaler CVE-2026-3055 SAML IdP exposure and session-cookie (NSC_AAAC) abuse

`UC_104_13` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities where Vulnerabilities.cve="CVE-2026-3055" by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.category
| `drop_dm_object_name(Vulnerabilities)`
| sort - count
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2026-3055"
| project DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| join kind=leftouter (DeviceInfo | where IsInternetFacing == true | summarize by DeviceId, IsInternetFacing) on DeviceId
| order by IsInternetFacing desc
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

### Article-specific behavioural hunt — Chinese Hacker Commands DeepSeek via Telegram to Launch Autonomous Attacks

`UC_104_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Chinese Hacker Commands DeepSeek via Telegram to Launch Autonomous Attacks ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/home/worker.*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Chinese Hacker Commands DeepSeek via Telegram to Launch Autonomous Attacks
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/home/worker."))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33017`, `CVE-2026-21858`, `CVE-2025-68613`, `CVE-2026-3055`, `CVE-2026-39987`, `CVE-2026-34486`, `CVE-2026-0300`, `CVE-2026-33824`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `code.newcli.com`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
