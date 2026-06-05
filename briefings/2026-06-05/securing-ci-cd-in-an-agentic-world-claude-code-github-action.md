# [HIGH] Securing CI/CD in an agentic world: Claude Code Github action case

**Source:** Microsoft Security Blog
**Published:** 2026-06-05
**Article:** https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/

## Threat Profile

Tags 
CI/CD 
Frontier AI models 
Vulnerability 
Content types 
Research 
Products and services 
Microsoft Defender 
Topics 
Actionable threat insights 
AI and agents 
Defending against advanced tactics 
Microsoft Threat Intelligence discovered that Anthropic’s Claude Code GitHub Action could expose CI/CD workflow secrets when AI agents process untrusted GitHub content, including issue bodies, pull request descriptions, and comments. We found that while Claude Code Action supported environment sc…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1212** — Exploitation for Credential Access
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Claude Code Action Read tool exfil: node opens /proc/<pid>/environ on Linux CI runner

`UC_5_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name="node" AND (Filesystem.file_path="/proc/self/environ" OR Filesystem.file_path="/proc/*/environ") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.process_id Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | where action IN ("read","open","access")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node"
| where FolderPath matches regex @"^/proc/(self|\d+)/environ$"
| where InitiatingProcessFolderPath has_any ("_work/", "actions-runner", "_actions/anthropics/claude-code-action", "runners/") or InitiatingProcessCommandLine has_any ("@anthropic-ai/claude-code", "claude-code-action")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessId,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Claude Code Read tool steered to cloud-credential files on GitHub Actions runner

`UC_5_5` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name="node" AND (Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.gitconfig" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.kube/config" OR Filesystem.file_path="*/.netrc" OR Filesystem.file_path="*/.env" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.config/gh/hosts.yml") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.process_id Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where process_path LIKE "%/_work/%" OR process_path LIKE "%actions-runner%" OR process_path LIKE "%_actions/anthropics/claude-code-action%" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CredPaths = dynamic([".aws/credentials", ".npmrc", ".gitconfig", ".docker/config.json", ".kube/config", ".netrc", "/.env", ".config/gh/hosts.yml", ".terraformrc", ".pypirc"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node"
| where InitiatingProcessFolderPath has_any ("_work/", "actions-runner", "_actions/anthropics/claude-code-action") 
   or InitiatingProcessCommandLine has_any ("@anthropic-ai/claude-code", "claude-code-action")
| where FolderPath has_any (CredPaths)
   or FolderPath matches regex @"\.ssh/id_(rsa|ed25519|dsa|ecdsa)$"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessId,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] GitHub Actions runner: node from Claude Code Action egresses to non-Anthropic/non-GitHub endpoint

`UC_5_6` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.dest_ip) as dest_ip from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="node" AND All_Traffic.src_category="github_actions_runner" AND All_Traffic.dest_category!="private" by All_Traffic.src All_Traffic.dest All_Traffic.app All_Traffic.process_id | `drop_dm_object_name(All_Traffic)` | where NOT match(dest, "(?i)(\.anthropic\.com|api\.github\.com|githubusercontent\.com|githubapp\.com|githubassets\.com|ghcr\.io|actions\.githubusercontent\.com)$") | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let RunnerNode = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "node"
    | where FolderPath has_any ("_actions/anthropics/claude-code-action", "_work/", "actions-runner")
         or ProcessCommandLine has_any ("@anthropic-ai/claude-code", "claude-code-action")
    | project NodeTime = Timestamp, DeviceId, NodePid = ProcessId, NodeCmd = ProcessCommandLine, NodeFolder = FolderPath;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node"
| where RemoteIPType == "Public"
| where not(RemoteUrl has_any ("anthropic.com", "api.github.com", "githubusercontent.com", "githubapp.com", "githubassets.com", "ghcr.io", "actions.githubusercontent.com"))
| where isnotempty(RemoteIP)
| join kind=inner RunnerNode on $left.DeviceId == $right.DeviceId, $left.InitiatingProcessId == $right.NodePid
| project Timestamp, DeviceName, NodeCmd, NodeFolder, RemoteIP, RemoteUrl, RemotePort, Protocol, InitiatingProcessCommandLine
| summarize HitCount = count(), FirstSeen = min(Timestamp), Destinations = make_set(RemoteUrl, 20), DestIPs = make_set(RemoteIP, 20)
           by DeviceName, NodeFolder, RemotePort
| order by FirstSeen desc
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


## Why this matters

Severity classified as **HIGH** based on: 7 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
