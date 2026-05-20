# [HIGH] Stealer Backdoor Found in 3 Node-IPC Versions Targeting Developer Secrets

**Source:** The Hacker News
**Published:** 2026-05-14
**Article:** https://thehackernews.com/2026/05/stealer-backdoor-found-in-3-node-ipc.html

## Threat Profile

Stealer Backdoor Found in 3 Node-IPC Versions Targeting Developer Secrets 
 Ravie Lakshmanan  May 14, 2026 Developer Security / Supply Chain Attack 
Cybersecurity researchers are sounding the alarm about what has been described as "malicious activity" in newly published versions of node-ipc.
According to Socket and StepSecurity , three different versions of the npm package have been confirmed as malicious -
node-ipc@9.1.6
node-ipc@9.2.3
node-ipc@12.0.1
"Early analysis indicates that node-ipc@9…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `sh.azurestaticprovider.net`

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1048.003** — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
- **T1567** — Exfiltration Over Web Service
- **T1132.001** — Data Encoding: Standard Encoding
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1048.003** — Exfiltration Over Alternative Protocol
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1554** — Compromise Host Software Binary
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1083** — File and Directory Discovery
- **T1555.005** — Credentials from Password Stores: Password Managers
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Network resolution or connection to node-ipc backdoor C2 sh.azurestaticprovider.net

`UC_100_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.dest) as resolved_ip from datamodel=Network_Resolution.DNS where DNS.query="sh.azurestaticprovider.net" OR DNS.query="*.azurestaticprovider.net" by DNS.query | `drop_dm_object_name(DNS)` | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_ip) as dest_ip from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="sh.azurestaticprovider.net" OR All_Traffic.dest="*.azurestaticprovider.net" OR All_Traffic.url="*azurestaticprovider.net*" by All_Traffic.dest | `drop_dm_object_name(All_Traffic)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union isfuzzy=true
(DeviceNetworkEvents
 | where Timestamp > ago(30d)
 | where RemoteUrl has "azurestaticprovider.net"
 | project Timestamp, DeviceName, InitiatingProcessAccountName,
           InitiatingProcessFileName, InitiatingProcessCommandLine,
           InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort, ActionType),
(DeviceEvents
 | where Timestamp > ago(30d)
 | where ActionType in ("DnsQueryResponse","DnsConnectionInspected","InboundConnectionAccepted")
 | where RemoteUrl has "azurestaticprovider.net" or AdditionalFields has "azurestaticprovider.net"
 | project Timestamp, DeviceName, InitiatingProcessAccountName,
           InitiatingProcessFileName, InitiatingProcessCommandLine,
           RemoteUrl, RemoteIP, RemotePort, ActionType)
| order by Timestamp desc
```

### [LLM] node.exe initiating outbound to node-ipc backdoor C2 sh.azurestaticprovider.net

`UC_100_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count sum(All_Traffic.bytes_out) as bytes_out min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process_name="node.exe" OR All_Traffic.process_name="node" OR All_Traffic.app="node*") (All_Traffic.dest="sh.azurestaticprovider.net" OR All_Traffic.dest="*azurestaticprovider.net" OR All_Traffic.url="*azurestaticprovider.net*") by host All_Traffic.user All_Traffic.process_name All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where RemoteUrl has "azurestaticprovider.net"
| extend ChildIsHttps = (RemotePort == 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessParentFileName,
          RemoteUrl, RemoteIP, RemotePort, ChildIsHttps, ActionType
| order by Timestamp desc
```

### [LLM] node.exe sending UDP/53 directly to public DNS resolvers (resolver-override bypass)

`UC_100_11` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process_name="node.exe" OR All_Traffic.process_name="node") All_Traffic.dest_port=53 (All_Traffic.dest_ip="1.1.1.1" OR All_Traffic.dest_ip="1.0.0.1" OR All_Traffic.dest_ip="8.8.8.8" OR All_Traffic.dest_ip="8.8.4.4") by host All_Traffic.user All_Traffic.process_name All_Traffic.dest_ip All_Traffic.transport | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let PublicResolvers = dynamic(["1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where RemotePort == 53
| where RemoteIP in (PublicResolvers)
| summarize QueryCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp),
            CmdLine = any(InitiatingProcessCommandLine),
            ParentName = any(InitiatingProcessParentFileName),
            FolderPath = any(InitiatingProcessFolderPath)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessId, RemoteIP
| order by QueryCount desc
```

### [LLM] Installation or package-lock entry for compromised node-ipc 9.1.6 / 9.2.3 / 12.0.1

`UC_100_12` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="npm.exe" OR Processes.process_name="npm-cli.js" OR Processes.process_name="yarn.exe" OR Processes.process_name="pnpm.exe" OR Processes.process_name="node.exe") Processes.process="*node-ipc*" (Processes.process="*9.1.6*" OR Processes.process="*9.2.3*" OR Processes.process="*12.0.1*") by host Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [ | tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.file_name="node-ipc.cjs" Filesystem.file_path="*\\node_modules\\node-ipc\\*" by host Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let BadVersions = dynamic(["9.1.6","9.2.3","12.0.1"]);
union isfuzzy=true
(DeviceProcessEvents
  | where Timestamp > ago(60d)
  | where (FileName in~ ("npm.exe","npm.cmd","yarn.exe","pnpm.exe","node.exe")
        or InitiatingProcessFileName in~ ("npm.exe","npm.cmd","yarn.exe","pnpm.exe","node.exe"))
  | where ProcessCommandLine has "node-ipc"
  | where ProcessCommandLine has_any (BadVersions)
  | extend Signal = "install_cmdline"
  | project Timestamp, DeviceName, Signal, AccountName, FileName, ProcessCommandLine,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            InitiatingProcessParentFileName, FolderPath),
(DeviceFileEvents
  | where Timestamp > ago(60d)
  | where FileName =~ "node-ipc.cjs"
  | where FolderPath has @"\node_modules\node-ipc\"
  | where ActionType in ("FileCreated","FileModified","FileRenamed")
  | extend Signal = "file_write"
  | project Timestamp, DeviceName, Signal, InitiatingProcessAccountName,
            FileName, FolderPath, FileSize, SHA256,
            InitiatingProcessFileName, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### [LLM] node.exe fan-out across developer credential file paths

`UC_100_13` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where (Filesystem.process_name="node.exe" OR Filesystem.process_name="node") (Filesystem.file_path="*\\.aws\\credentials" OR Filesystem.file_path="*\\.aws\\config" OR Filesystem.file_path="*\\.ssh\\id_*" OR Filesystem.file_path="*\\.ssh\\config" OR Filesystem.file_path="*\\.kube\\config" OR Filesystem.file_path="*\\.config\\gh\\hosts.yml" OR Filesystem.file_path="*\\.config\\gh\\config.yml" OR Filesystem.file_path="*\\.config\\gcloud\\application_default_credentials.json" OR Filesystem.file_path="*\\.azure\\msal_token_cache*" OR Filesystem.file_path="*terraform.tfstate*" OR Filesystem.file_path="*\\.docker\\config.json" OR Filesystem.file_path="*\\.npmrc" OR Filesystem.file_path="*\\.pypirc" OR Filesystem.file_path="*\\.claude*" OR Filesystem.file_path="*\\.kiro*" OR Filesystem.file_path="*\\.bash_history" OR Filesystem.file_path="*\\.zsh_history" OR Filesystem.file_path="*\\.psql_history") by host Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | stats dc(file_path) as path_count values(file_path) as paths min(_time) as first_seen max(_time) as last_seen by host user process_name | where path_count >= 4 | convert ctime(first_seen) ctime(last_seen)
```

**Defender KQL:**
```kql
let credPathPatterns = dynamic([
    @"\.aws\credentials", @"\.aws\config",
    @"\.ssh\id_rsa", @"\.ssh\id_ed25519", @"\.ssh\id_ecdsa", @"\.ssh\config",
    @"\.kube\config",
    @"\.config\gh\hosts.yml", @"\.config\gh\config.yml",
    @"\.config\gcloud\application_default_credentials.json", @"\.config\gcloud\credentials.db",
    @"\.azure\msal_token_cache", @"\.azure\accessTokens.json",
    @"terraform.tfstate",
    @"\.docker\config.json",
    @"\.npmrc", @"\.pypirc",
    @"\.claude", @"\.kiro",
    @"\.bash_history", @"\.zsh_history", @"\.psql_history"
]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| extend FullPath = strcat(FolderPath, "\\", FileName)
| where FullPath has_any (credPathPatterns) or FolderPath has_any (credPathPatterns)
| summarize PathCount = dcount(FullPath),
            SamplePaths = make_set(FullPath, 25),
            FirstTouch = min(Timestamp), LastTouch = max(Timestamp),
            CmdLine = any(InitiatingProcessCommandLine),
            ParentName = any(InitiatingProcessParentFileName)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessId
| where PathCount >= 4
| order by FirstTouch desc
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

### Article-specific behavioural hunt — Stealer Backdoor Found in 3 Node-IPC Versions Targeting Developer Secrets

`UC_100_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Stealer Backdoor Found in 3 Node-IPC Versions Targeting Developer Secrets ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("bt.node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("bt.node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Stealer Backdoor Found in 3 Node-IPC Versions Targeting Developer Secrets
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("bt.node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("bt.node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `sh.azurestaticprovider.net`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 14 use case(s) fired, 27 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
