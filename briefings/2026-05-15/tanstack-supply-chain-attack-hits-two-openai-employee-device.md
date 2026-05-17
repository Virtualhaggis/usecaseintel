# [CRIT] TanStack Supply Chain Attack Hits Two OpenAI Employee Devices, Forces macOS Updates

**Source:** The Hacker News
**Published:** 2026-05-15
**Article:** https://thehackernews.com/2026/05/tanstack-supply-chain-attack-hits-two.html

## Threat Profile

TanStack Supply Chain Attack Hits Two OpenAI Employee Devices, Forces macOS Updates 
 Ravie Lakshmanan  May 15, 2026 Supply Chain Attack / Malware 
OpenAI has disclosed that two of its employee devices in its corporate environment were impacted via the Mini Shai-Hulud supply chain attack on TanStack, but noted that no user data, production systems, or intellectual property were compromised or modified in an unauthorized manner.
"Upon identification of the malicious activity, we worked quickly …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `83.142.209.194`

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
- **T1195.002** — Compromise Software Supply Chain
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1008** — Fallback Channels
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1552.007** — Unsecured Credentials: Container API
- **T1105** — Ingress Tool Transfer
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Mini Shai-Hulud Worm C2 Beacon to 83.142.209.194 (TanStack/Mistral AI Supply Chain)

`UC_25_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.user) as user values(All_Traffic.bytes_out) as bytes_out values(All_Traffic.dest_url) as dest_url from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="83.142.209.194" OR All_Traffic.dest_ip="83.142.209.194") by All_Traffic.src All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "83.142.209.194"
   or RemoteUrl has_any ("83.142.209.194/v1/weights", "83.142.209.194/v1/models", "83.142.209.194/audio.mp3", "//83.142.209.194")
| project Timestamp, DeviceName, DeviceId, RemoteIP, RemotePort, RemoteUrl, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessSHA256, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] FIRESCALE Fallback C2 Discovery via GitHub Commit-Search API

`UC_25_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user values(Web.http_user_agent) as user_agent values(Web.process) as process from datamodel=Web.Web where Web.url="*api.github.com/search/commits*" AND (Web.url="*FIRESCALE*" OR Web.url="*q=FIRESCALE*" OR Web.url="*q%3DFIRESCALE*") by Web.src Web.dest Web.url | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _developer_clients = dynamic(["code.exe","devenv.exe","webstorm64.exe","webstorm.exe","idea64.exe","idea.exe","pycharm64.exe","pycharm.exe","sublime_text.exe","atom.exe","gh.exe","git.exe","github desktop.exe","code-insiders.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "api.github.com"
| where RemoteUrl has "search/commits"
| where RemoteUrl has "FIRESCALE"
    or InitiatingProcessFileName in~ ("python.exe","python3.exe","python","python3","node.exe","node","curl.exe","curl","wget.exe","wget","powershell.exe","pwsh.exe","npm","yarn","pip","pip3")
| where InitiatingProcessFileName !in~ (_developer_clients)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, RemoteIP, RemoteUrl
| order by Timestamp desc
```

### [LLM] Mini Shai-Hulud Worm Credential-Harvest Drop (/tmp/transformers.pyz + Post-Install AWS/SSH/Docker Read)

`UC_25_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path from datamodel=Endpoint.Filesystem where Filesystem.action=created AND (Filesystem.file_path="/tmp/transformers.pyz" OR Filesystem.file_name="transformers.pyz" OR Filesystem.file_name="pgmonitor.py" OR Filesystem.file_name="pgsql-monitor.service" OR Filesystem.file_path="*/etc/systemd/system/pgsql-monitor.service") by Filesystem.dest Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let FileIOCs = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("FileCreated","FileModified")
    | where FolderPath =~ "/tmp/transformers.pyz"
        or FileName in~ ("transformers.pyz", "pgmonitor.py", "pgsql-monitor.service")
    | project Timestamp, DeviceName, DeviceId, EvidenceType="FileArtifact",
              FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessFolderPath, InitiatingProcessAccountName,
              InitiatingProcessParentFileName;
let PostInstallCredRead = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("npm","pip","pip3","yarn","pnpm","node","python","python3")
        or InitiatingProcessParentFileName in~ ("npm","pip","pip3","yarn","pnpm","node")
    | where FileName in~ ("python","python3","node","sh","bash","cat","curl","wget")
        or ProcessCommandLine has_any ("/.aws/credentials","/.aws/config","/.ssh/id_","/.ssh/config","/var/run/docker.sock","transformers.pyz")
    | where ProcessCommandLine has_any ("/.aws/credentials","/.aws/config","/.ssh/id_","/.ssh/config","/var/run/docker.sock","transformers.pyz",".env","environ")
    | project Timestamp, DeviceName, DeviceId, EvidenceType="PostInstallCredRead",
              FileName=FileName, FolderPath, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessFolderPath=InitiatingProcessFolderPath,
              InitiatingProcessAccountName=AccountName,
              InitiatingProcessParentFileName=InitiatingProcessParentFileName,
              SHA256=SHA256;
union FileIOCs, PostInstallCredRead
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
  - IP / domain IOC(s): `83.142.209.194`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
