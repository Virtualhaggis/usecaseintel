# [CRIT] IronWorm and New Miasma Worm Variant Hit npm in Supply Chain Attacks

**Source:** The Hacker News
**Published:** 2026-06-05
**Article:** https://thehackernews.com/2026/06/ironworm-and-new-miasma-worm-variant.html

## Threat Profile

IronWorm and New Miasma Worm Variant Hit npm in Supply Chain Attacks 
 Ravie Lakshmanan  Jun 05, 2026 Software Supply Chain / Malware 
Multiple software supply chain attacks have hit the npm ecosystem, with threat actors using both malicious and poisoned versions of over 50 legitimate packages to distribute a Rust-based information stealer and a self-spreading worm, respectively.
According to JFrog , the information stealer "scrapes every secret it can find on a developer's machine, hides behi…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `288f26c2eadcb1a7923fe376d16f5404216cce15d9fc162a4a78574dc7df399a`
- **SHA256:** `ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90`
- **SHA256:** `5926b86b642e00672252953eb30d8f75cfb7797fe3118bd6fa2cfbee92905d61`
- **SHA256:** `e3dbe63aded45278f49c4746ab938ed9472b36def79b43e2dd2d7eff014481d1`
- **SHA256:** `82d83274680df928fdda296a348e01802f595e412308c399565c320df444052a`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
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
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1105** — Ingress Tool Transfer
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1564.003** — Hidden Window / Detached Session
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1546** — Event Triggered Execution
- **T1555** — Credentials from Password Stores
- **T1552.001** — Credentials In Files
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1021.007** — Remote Services: Cloud Services
- **T1609** — Container Administration Command
- **T1018** — Remote System Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Installation of compromised Microsoft durabletask PyPI versions 1.4.1-1.4.3

`UC_21_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("pip","pip3","python","python3","python3.14") (Processes.process="*durabletask==1.4.1*" OR Processes.process="*durabletask==1.4.2*" OR Processes.process="*durabletask==1.4.3*" OR Processes.process="*durabletask-1.4.1*" OR Processes.process="*durabletask-1.4.2*" OR Processes.process="*durabletask-1.4.3*") by host Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("pip","pip3","python3","python3.14","python")
   or FileName in~ ("pip","pip3")
| where ProcessCommandLine has "durabletask"
| where ProcessCommandLine has_any ("1.4.1","1.4.2","1.4.3")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### [LLM] Python urlretrieve download of rope.pyz from check.git-service.com to /tmp/managed.pyz

`UC_21_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="python*" (All_Traffic.dest="check.git-service.com" OR All_Traffic.dest="git-service.com" OR All_Traffic.dest_ip="160.119.64.3") by host All_Traffic.user All_Traffic.app All_Traffic.dest All_Traffic.dest_ip | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let TimeRange = ago(30d);
let C2 = dynamic(["check.git-service.com","git-service.com"]);
let C2IP = dynamic(["160.119.64.3","83.142.209.194"]);
let Net = DeviceNetworkEvents
    | where Timestamp > TimeRange
    | where InitiatingProcessFileName has_any ("python","python3","python3.14")
    | where RemoteUrl has_any (C2) or RemoteIP in (C2IP);
let Drop = DeviceFileEvents
    | where Timestamp > TimeRange
    | where FolderPath == "/tmp" and FileName =~ "managed.pyz"
    | where InitiatingProcessFileName has_any ("python","python3","python3.14");
union Net, Drop
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### [LLM] python3 import durabletask spawning detached /tmp/managed.pyz collector swarm

`UC_21_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmds dc(Processes.process_id) as child_pids from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3","python3.14") Processes.process="*managed.pyz*" by host Processes.user Processes.parent_process Processes.process_name | `drop_dm_object_name(Processes)` | where child_pids >= 2 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("python","python3","python3.14")
| where ProcessCommandLine has "/tmp/managed.pyz"
| summarize ChildPids = dcount(ProcessId), AnyCmd = any(ProcessCommandLine), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), ParentCmd = any(InitiatingProcessCommandLine)
          by DeviceId, DeviceName, AccountName, InitiatingProcessId
| where ChildPids >= 2
| order by FirstSeen desc
```

### [LLM] Fake pgsql-monitor.service persistence via systemctl --user daemon-reload from python parent

`UC_21_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3","python3.14") (Processes.process="*systemctl --user daemon-reload*" OR Processes.process_name="systemctl" AND Processes.process="*pgsql-monitor*") by host Processes.user Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.file_name="pgsql-monitor.service" by host Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)` ]
```

**Defender KQL:**
```kql
let TimeRange = ago(30d);
let Procs = DeviceProcessEvents
    | where Timestamp > TimeRange
    | where InitiatingProcessFileName has_any ("python","python3","python3.14")
    | where (FileName =~ "systemctl" and ProcessCommandLine has "--user" and ProcessCommandLine has "daemon-reload")
        or ProcessCommandLine has "pgsql-monitor"
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Source = "process";
let Files = DeviceFileEvents
    | where Timestamp > TimeRange
    | where FileName =~ "pgsql-monitor.service"
       or (FolderPath has "systemd/user" and FileName endswith ".service" and InitiatingProcessFileName has_any ("python","python3","python3.14"))
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, FileName, ProcessCommandLine = InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Source = "file";
union Procs, Files
| order by Timestamp desc
```

### [LLM] GPG batch passphrase 'anon' + gh auth token credential harvesting from python parent

`UC_21_13` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmds from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3","python3.14") ((Processes.process_name="gpg" AND Processes.process="*--batch*--passphrase*anon*--decrypt*") OR (Processes.process_name="gh" AND (Processes.process="*auth token*" OR Processes.process="*auth status --show-token*"))) by host Processes.user Processes.parent_process Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("python","python3","python3.14")
| where (FileName =~ "gpg" and ProcessCommandLine has "--batch" and ProcessCommandLine has "--passphrase" and ProcessCommandLine has " anon" and ProcessCommandLine has "--decrypt")
   or (FileName =~ "gh" and (ProcessCommandLine has "auth token" or ProcessCommandLine has "auth status --show-token"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] DNS / connection to TeamPCP secondary C2 m-kosche.com

`UC_21_14` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="m-kosche.com" OR DNS.query="*.m-kosche.com" OR DNS.query="git-service.com" OR DNS.query="*.git-service.com") by host DNS.src DNS.query | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="160.119.64.3" OR All_Traffic.dest_ip="83.142.209.194") by host All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` ]
```

**Defender KQL:**
```kql
let BadDomains = dynamic(["m-kosche.com","t.m-kosche.com","git-service.com","check.git-service.com"]);
let BadIPs = dynamic(["160.119.64.3","83.142.209.194"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (BadDomains) or RemoteIP in (BadIPs)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### [LLM] AWS SSM SendCommand / kubectl exec lateral movement from compromised CI runtime

`UC_21_15` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmds from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3","python3.14") (Processes.process_name="kubectl" OR Processes.process_name="aws") (Processes.process="*kubectl*exec*" OR Processes.process="*kubectl version --client*" OR Processes.process="*ssm send-command*" OR Processes.process="*ssm start-session*") by host Processes.user Processes.parent_process Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("python","python3","python3.14")
| where (FileName =~ "kubectl" and (ProcessCommandLine has "version --client" or ProcessCommandLine has " exec "))
   or (FileName =~ "aws" and (ProcessCommandLine has "ssm send-command" or ProcessCommandLine has "ssm start-session"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — IronWorm and New Miasma Worm Variant Hit npm in Supply Chain Attacks

`UC_21_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — IronWorm and New Miasma Worm Variant Hit npm in Supply Chain Attacks ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — IronWorm and New Miasma Worm Variant Hit npm in Supply Chain Attacks
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `288f26c2eadcb1a7923fe376d16f5404216cce15d9fc162a4a78574dc7df399a`, `ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90`, `5926b86b642e00672252953eb30d8f75cfb7797fe3118bd6fa2cfbee92905d61`, `e3dbe63aded45278f49c4746ab938ed9472b36def79b43e2dd2d7eff014481d1`, `82d83274680df928fdda296a348e01802f595e412308c399565c320df444052a`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 16 use case(s) fired, 26 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
