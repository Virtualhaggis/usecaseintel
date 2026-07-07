# [HIGH] Axios npm Package Compromised: Supply Chain Attack Delivers Cross-Platform RAT

**Source:** Snyk
**Published:** 2026-03-30
**Article:** https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
March 30, 2026
0 mins read On March 31, 2026, two malicious versions of axios , the enormously popular JavaScript HTTP client with over 100 million weekly downloads, were briefly published to npm via a compromised maintainer account. The packages contained a hidden dependency that deployed a cross-platform remote access trojan (RAT) to any machine that ran npm install (or equivalent in other package managers like Bun) during a two-hour window.
The …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `142.11.206.73`
- **Domain (defanged):** `sfrclak.com`
- **SHA256:** `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101`
- **SHA256:** `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a`
- **SHA256:** `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf`
- **SHA1:** `2553649f2322049666871cea80a5d0d6adc700ca`
- **SHA1:** `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71`
- **SHA1:** `07d889e2dadce6f3910dcbc253317d28ca61c766`

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
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1105** — Ingress Tool Transfer
- **T1059.006** — Python
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1036.004** — Masquerading: Masquerade Task or Service
- **T1553.002** — Subvert Trust Controls: Code Signing
- **T1564.001** — Hidden Files and Directories
- **T1059.002** — AppleScript
- **T1059** — Command and Scripting Interpreter
- **T1546.016** — Event Triggered Execution: Installer Packages

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound C2 to sfrclak.com / 142.11.206.73:8000 (Axios npm RAT beacon)

`UC_479_11` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.src_ip) as src_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="sfrclak.com" OR All_Traffic.dest_ip="142.11.206.73") by All_Traffic.dest All_Traffic.dest_ip host | `drop_dm_object_name(All_Traffic)` | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src from datamodel=Network_Resolution.DNS where DNS.query="sfrclak.com" OR DNS.query="*.sfrclak.com" by DNS.query host | `drop_dm_object_name(DNS)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let C2Domains = dynamic(["sfrclak.com"]);
let C2IPs = dynamic(["142.11.206.73"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (C2IPs) or RemoteUrl has_any (C2Domains)
| project Timestamp, DeviceName, DeviceId, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName, RemoteIP, RemotePort, RemoteUrl, Protocol, InitiatingProcessAccountName
| order by Timestamp asc
```

### PowerShell masquerading as Windows Terminal at %PROGRAMDATA%\wt.exe (Axios RAT Windows stage)

`UC_479_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process_name) as parent values(Processes.parent_process) as parent_cmd values(Processes.process) as cmdline values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where (Processes.process_path="C:\\ProgramData\\wt.exe" OR Processes.process_name="wt.exe" AND Processes.process_path="*\\ProgramData\\*") OR (Processes.process_name="wt.exe" AND (Processes.process="*-ExecutionPolicy*Bypass*" OR Processes.process="*-ep*bypass*" OR Processes.process="*-WindowStyle*Hidden*" OR Processes.process="*-w*h*")) by host Processes.user Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let SuspectPaths = dynamic([@"c:\programdata\wt.exe", @"%programdata%\wt.exe"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FolderPath has @"\ProgramData\" and FileName =~ "wt.exe")
     or (FileName =~ "wt.exe" and ProcessCommandLine has_any ("-ExecutionPolicy Bypass", "-ep bypass", "-WindowStyle Hidden", "-w hidden", "-nop", "-noprofile"))
| where FolderPath !startswith @"C:\Program Files\WindowsApps\" and FolderPath !contains @"\Microsoft\WindowsApps\"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has @"\ProgramData\" and FileName =~ "wt.exe"
    | project DeviceName, DropTime=Timestamp, DroppedBy=InitiatingProcessFileName, DroppedByCmd=InitiatingProcessCommandLine, DroppedSHA256=SHA256
  ) on DeviceName
| order by Timestamp desc
```

### Linux Python RAT orphaned via nohup python3 /tmp/ld.py (Axios npm payload)

`UC_479_13` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where Processes.os="linux" AND ((Processes.process_name="python3" OR Processes.process_name="python" OR Processes.process_name="nohup") AND (Processes.process="*nohup*python*\/tmp\/ld.py*" OR Processes.process="*python3*\/tmp\/ld.py*" OR Processes.process="*\/tmp\/ld.py*")) by host Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceName !endswith ".local" or 1==1  // applies to all OS; Linux sensor populates this table when MDE for Linux is deployed
| where (FileName in~ ("python3", "python", "python3.10", "python3.11", "python3.12") and ProcessCommandLine has "/tmp/ld.py")
     or (FileName =~ "nohup" and ProcessCommandLine has "/tmp/ld.py")
     or (InitiatingProcessFileName =~ "nohup" and FileName matches regex @"^python[0-9.]*$" and ProcessCommandLine has "/tmp/ld.py")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath == "/tmp/" and FileName =~ "ld.py"
    | project DeviceName, DropTime=Timestamp, DroppedBy=InitiatingProcessFileName, DroppedByCmd=InitiatingProcessCommandLine, DroppedSHA256=SHA256
  ) on DeviceName
| order by Timestamp desc
```

### macOS Axios RAT daemon spoof + ad-hoc codesign of hidden /private/tmp binary

`UC_479_14` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as written_by from datamodel=Endpoint.Filesystem where Filesystem.file_path="/Library/Caches/com.apple.act.mond" by host Filesystem.file_path | `drop_dm_object_name(Filesystem)` | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process_name) as parent values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.os="macos" AND Processes.process_name="codesign" AND (Processes.process="*--force*--deep*--sign*-*" AND Processes.process="*\/private\/tmp\/.*") by host Processes.user | `drop_dm_object_name(Processes)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let RatPath = "/Library/Caches/com.apple.act.mond";
union isfuzzy=true
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has "/Library/Caches/" and FileName =~ "com.apple.act.mond"
    | project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName),
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "codesign"
    | where ProcessCommandLine has "--force" and ProcessCommandLine has "--deep" and ProcessCommandLine has "--sign -"
    | where ProcessCommandLine matches regex @"/private/tmp/\.[A-Za-z0-9]{4,}"
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName),
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "osascript" and InitiatingProcessFileName in~ ("node", "npm", "yarn", "pnpm", "bun", "sh", "bash", "zsh")
    | where ProcessCommandLine has "curl" or ProcessCommandLine has "/Library/Caches/" or ProcessCommandLine has "sfrclak"
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName)
| order by Timestamp desc
```

### npm/node postinstall hook spawning interpreter and reaching new C2 host (Axios-style dropper)

`UC_479_15` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_name) as child from datamodel=Endpoint.Processes where Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node" AND Processes.process_name IN ("wscript.exe","cscript.exe","powershell.exe","pwsh.exe","cmd.exe","python.exe","python3","python","sh","bash","osascript","nohup","curl","wget") by host Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | rename host as src_host | join type=inner src_host [ | tstats `summariesonly` count as netconns values(All_Traffic.dest) as dest values(All_Traffic.dest_ip) as dest_ip min(_time) as first_conn from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (80,443,8000,8080,8443) AND All_Traffic.action="allowed" by All_Traffic.src as src_host All_Traffic.dest_ip | `drop_dm_object_name(All_Traffic)` ] | where (first_conn - firstTime) BETWEEN 0 AND 60 | convert ctime(firstTime) ctime(lastTime) ctime(first_conn)
```

**Defender KQL:**
```kql
let Lookback = 30d;
let WindowSec = 60;
let PostInstallChildren = dynamic(["wscript.exe","cscript.exe","powershell.exe","pwsh.exe","cmd.exe","python.exe","python3","python","sh","bash","osascript","nohup","curl.exe","curl","wget.exe","wget"]);
let KnownRegistries = dynamic(["registry.npmjs.org","registry.yarnpkg.com","registry.npm.taobao.org","npmjs.com","npmjs.org","yarnpkg.com","pnpm.io","bun.sh","jsdelivr.net","unpkg.com","github.com","githubusercontent.com"]);
let NodeChildren = DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where InitiatingProcessFileName in~ ("node.exe", "node", "npm.exe", "npm", "yarn.exe", "yarn", "pnpm.exe", "pnpm", "bun.exe", "bun")
         or InitiatingProcessParentFileName in~ ("node.exe", "node", "npm.exe", "npm", "yarn.exe", "yarn", "pnpm.exe", "pnpm", "bun.exe", "bun")
    | where FileName in~ (PostInstallChildren)
    | project ProcTime=Timestamp, DeviceId, DeviceName, AccountName, ChildName=FileName, ChildCmd=ProcessCommandLine, ParentName=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine, ProcessId;
let Beacons = DeviceNetworkEvents
    | where Timestamp > ago(Lookback)
    | where RemoteIPType == "Public"
    | where isnotempty(RemoteIP)
    | where not(RemoteUrl has_any (KnownRegistries))
    | project NetTime=Timestamp, DeviceId, DeviceName, NetProc=InitiatingProcessFileName, NetCmd=InitiatingProcessCommandLine, NetPID=InitiatingProcessId, RemoteIP, RemotePort, RemoteUrl;
NodeChildren
| join kind=inner Beacons on DeviceId
| where NetTime between (ProcTime .. ProcTime + WindowSec * 1s)
| where ChildName =~ NetProc or ProcessId == NetPID
| project ProcTime, NetTime, DelaySec=datetime_diff('second', NetTime, ProcTime), DeviceName, AccountName, ParentName, ParentCmd, ChildName, ChildCmd, RemoteIP, RemotePort, RemoteUrl
| order by ProcTime desc
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

### Article-specific behavioural hunt — Axios npm Package Compromised: Supply Chain Attack Delivers Cross-Platform RAT

`UC_479_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Axios npm Package Compromised: Supply Chain Attack Delivers Cross-Platform RAT ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("setup.js","wt.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/Library/Caches/com.apple.act.mond*" OR Filesystem.file_path="*/private/tmp/.XXXXXX*" OR Filesystem.file_path="*/tmp/ld.py*" OR Filesystem.file_name IN ("setup.js","wt.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Axios npm Package Compromised: Supply Chain Attack Delivers Cross-Platform RAT
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("setup.js", "wt.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/Library/Caches/com.apple.act.mond", "/private/tmp/.XXXXXX", "/tmp/ld.py") or FileName in~ ("setup.js", "wt.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `142.11.206.73`, `sfrclak.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101`, `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a`, `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf`, `2553649f2322049666871cea80a5d0d6adc700ca`, `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71`, `07d889e2dadce6f3910dcbc253317d28ca61c766`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 16 use case(s) fired, 27 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
