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
- **T1071.004** — Application Layer Protocol: DNS
- **T1090** — Proxy
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1083** — File and Directory Discovery
- **T1552.007** — Container API
- **T1613** — Container and Resource Discovery
- **T1552.001** — Credentials In Files
- **T1485** — Data Destruction
- **T1561.001** — Disk Wipe: Disk Content Wipe

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Mini Shai-Hulud / TeamPCP C2 communication to 83.142.209.194 or campaign domains

`UC_41_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="83.142.209.194" OR All_Traffic.dest="83.142.209.194" by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.app host | `drop_dm_object_name(All_Traffic)` | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*git-tanstack.com" OR DNS.query="*.getsession.org" OR DNS.answer="83.142.209.194") by DNS.src DNS.query DNS.answer host | `drop_dm_object_name(DNS)` ] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let bad_ips = dynamic(["83.142.209.194"]);
let bad_domains = dynamic(["git-tanstack.com","getsession.org"]);
union isfuzzy=true
( DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteIP in (bad_ips) or RemoteUrl has_any (bad_domains)
  | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl, ActionType ),
( DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | extend Query = tostring(parse_json(AdditionalFields).QueryName), Answer = tostring(parse_json(AdditionalFields).IPAddresses)
  | where Query has_any (bad_domains) or Answer has "83.142.209.194"
  | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, Query, Answer )
| order by Timestamp desc
```

### [LLM] npm/pnpm/yarn/pip install of Mini Shai-Hulud trojanized package ecosystems

`UC_41_7` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("npm.exe","npm","pnpm.exe","pnpm","yarn.exe","yarn","pip.exe","pip","pip3","pip3.exe","python.exe","python","python3") (Processes.process="*install*" OR Processes.process="* add *" OR Processes.process="* ci *") (Processes.process="*@tanstack/*" OR Processes.process="*mistralai*" OR Processes.process="*guardrails-ai*" OR Processes.process="*@opensearch-project/*" OR Processes.process="*@uipath/*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("npm.exe","npm","pnpm.exe","pnpm","yarn.exe","yarn") and ProcessCommandLine matches regex @"(?i)\b(install|add|ci|i)\b")
   or (FileName in~ ("pip.exe","pip","pip3","pip3.exe","python.exe","python","python3") and ProcessCommandLine has "install")
| where ProcessCommandLine has_any ("@tanstack/","mistralai","guardrails-ai","@opensearch-project/","@uipath/")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] Bulk fan-out of credential file reads (~/.aws/, ~/.ssh/, .npmrc, dotenv, docker config)

`UC_41_8` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(Filesystem.file_path) as secret_files values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.ssh/id_rsa" OR Filesystem.file_path="*/.ssh/id_ed25519" OR Filesystem.file_path="*/.ssh/id_ecdsa" OR Filesystem.file_path="*/.ssh/id_dsa" OR Filesystem.file_path="*/.ssh/config" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.pypirc" OR Filesystem.file_path="*/.git-credentials" OR Filesystem.file_path="*/.netrc" OR Filesystem.file_name="*.env") by Filesystem.dest Filesystem.user Filesystem.process_guid span=5m | `drop_dm_object_name(Filesystem)` | where secret_files >= 4 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CredPaths = dynamic(["/.aws/credentials","/.aws/config","/.ssh/id_rsa","/.ssh/id_ed25519","/.ssh/id_ecdsa","/.ssh/id_dsa","/.ssh/config","/.docker/config.json","/.npmrc","/.pypirc","/.git-credentials","/.netrc"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (CredPaths) or (FileName endswith ".env" and (FolderPath startswith "/home/" or FolderPath startswith "/Users/" or FolderPath startswith "/root/"))
| where InitiatingProcessFileName !in~ ("sshd","ssh","scp","rsync","git","gh","aws","kubectl","helm","terraform","ansible-playbook","dockerd","containerd","backup","restic","borg")
| summarize SecretFileCount = dcount(strcat(FolderPath, "/", FileName)),
            Files = make_set(strcat(FolderPath, "/", FileName), 50),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine, bin(Timestamp, 2m)
| where SecretFileCount >= 4
| order by SecretFileCount desc, LastSeen desc
```

### [LLM] Docker socket abuse / running container env extraction (credential pull from containers)

`UC_41_9` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process_name) as parent values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.process_name IN ("docker","docker.exe") AND (Processes.process="*inspect*" OR Processes.process="*exec*env*" OR Processes.process="*\".Config.Env*")) OR (Processes.process="*/var/run/docker.sock*" AND Processes.process_name IN ("curl","socat","nc","python","python3","node")) by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | search NOT (parent IN ("dockerd","containerd","containerd-shim","kubelet","runc","systemd","docker-compose","compose")) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ( FileName in~ ("docker","docker.exe")
          and ( ProcessCommandLine has "inspect"
             or (ProcessCommandLine has "exec" and ProcessCommandLine has "env")
             or ProcessCommandLine has ".Config.Env"
             or (ProcessCommandLine has "ps" and ProcessCommandLine has "-q") ) )
   or ( ProcessCommandLine has "/var/run/docker.sock"
        and FileName in~ ("curl","socat","nc","ncat","python","python3","node","bash","sh") )
| where InitiatingProcessFileName !in~ ("dockerd","containerd","containerd-shim","kubelet","runc","systemd","docker-compose")
| where InitiatingProcessCommandLine !has "compose" and InitiatingProcessCommandLine !has "kubectl" and InitiatingProcessCommandLine !has "helm"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Mass file deletion in user home directories (Mini Shai-Hulud destructive wiper)

`UC_41_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(Filesystem.file_path) as DeletedFileCount values(Filesystem.file_path) as paths min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action="deleted" (Filesystem.file_path="/home/*" OR Filesystem.file_path="/Users/*" OR Filesystem.file_path="/root/*" OR Filesystem.file_path="C:\\Users\\*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_guid span=2m | `drop_dm_object_name(Filesystem)` | where DeletedFileCount >= 200 | search NOT (process_name IN ("explorer.exe","finder","trash","rsync","restic","borg","npm.exe","pnpm.exe","yarn.exe","git","gc.exe")) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileDeleted"
| where FolderPath startswith "/home/" or FolderPath startswith "/Users/" or FolderPath startswith "/root/" or FolderPath matches regex @"(?i)^[a-z]:\\users\\"
| where InitiatingProcessFileName !in~ ("explorer.exe","finder","trash","rsync","restic","borg","npm.exe","pnpm.exe","yarn.exe","git","git.exe","go.exe","cargo","cargo.exe","OneDrive.exe","Dropbox.exe")
| summarize DeletedFileCount = dcount(strcat(FolderPath, "/", FileName)),
            SampleFiles = make_set(FileName, 20),
            FirstDelete = min(Timestamp), LastDelete = max(Timestamp),
            DurationSec = datetime_diff('second', max(Timestamp), min(Timestamp))
            by DeviceName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine, bin(Timestamp, 2m)
| where DeletedFileCount >= 200
| extend DeletionsPerSecond = round(todouble(DeletedFileCount) / todouble(case(DurationSec == 0, 1, DurationSec)), 2)
| order by DeletedFileCount desc
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

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
