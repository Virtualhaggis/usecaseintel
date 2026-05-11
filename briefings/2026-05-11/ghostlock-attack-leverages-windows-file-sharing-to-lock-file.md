# [CRIT] GhostLock Attack Leverages Windows file-sharing to Lock Files Access Like Ransomware

**Source:** Cyber Security News
**Published:** 2026-05-11
**Article:** https://cybersecuritynews.com/ghostlock-attack/

## Threat Profile

Home Cyber Security News 
GhostLock Attack Leverages Windows file-sharing to Lock Files Access Like Ransomware 
By Guru Baran 
May 11, 2026 
Traditional ransomware disrupts organizations by encrypting data and demanding payment for decryption keys.
However, a newly disclosed technique called GhostLock demonstrates a fundamentally different availability attack that achieves the same business disruption without writing a single encrypted byte to disk.
Discovered by Kim Dvash, an Offensive Security…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1588.002** — Obtain Capabilities: Tool
- **T1105** — Ingress Tool Transfer
- **T1499.004** — Endpoint Denial of Service: Application or System Exploitation
- **T1485** — Data Destruction
- **T1083** — File and Directory Discovery
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1021.002** — Remote Services: SMB/Windows Admin Shares

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] GhostLock availability-attack tooling — public site / GitHub / cmdline reference

`UC_14_8` · phase: **weapon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Network_Resolution.DNS where (DNS.query="ghostlock.io" OR DNS.query="*.ghostlock.io") by _time, DNS.src, DNS.query, DNS.dest | `drop_dm_object_name(DNS)` | append [ | tstats summariesonly=t count from datamodel=Web.Web where (Web.url="*ghostlock.io*" OR Web.url="*github.com/kimd155/ghostlock*" OR Web.url="*raw.githubusercontent.com/kimd155/ghostlock*") by _time, Web.src, Web.user, Web.url, Web.dest | `drop_dm_object_name(Web)` ] | append [ | tstats summariesonly=t count from datamodel=Endpoint.Processes where Endpoint.Processes.process="*ghostlock*" by _time, Endpoint.Processes.dest, Endpoint.Processes.user, Endpoint.Processes.process, Endpoint.Processes.process_name | `drop_dm_object_name(Processes)` ] | sort 0 - _time
```

**Defender KQL:**
```kql
let _start = ago(7d);
let _dns = DeviceEvents
    | where Timestamp > _start
    | where ActionType == "DnsQueryResponse"
    | extend QueryName = tolower(tostring(parse_json(AdditionalFields).QueryName))
    | where QueryName endswith "ghostlock.io"
    | project Timestamp, DeviceName, Account=InitiatingProcessAccountName,
              Signal="DNS", IOC=QueryName,
              Image=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine;
let _net = DeviceNetworkEvents
    | where Timestamp > _start
    | where (RemoteUrl has "ghostlock.io")
        or (RemoteUrl has "kimd155/ghostlock")
    | project Timestamp, DeviceName, Account=InitiatingProcessAccountName,
              Signal="HTTP", IOC=RemoteUrl,
              Image=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine;
let _proc = DeviceProcessEvents
    | where Timestamp > _start
    | where AccountName !endswith "$"
    | where ProcessCommandLine has "ghostlock"
        or InitiatingProcessCommandLine has "ghostlock"
        or FolderPath has "ghostlock"
    | project Timestamp, DeviceName, Account=AccountName,
              Signal="ProcessCmd", IOC=ProcessCommandLine,
              Image=FileName, Cmd=ProcessCommandLine;
union _dns, _net, _proc
| order by Timestamp desc
```

### [LLM] Mass SMB exclusive-handle accumulation on a file server (single client/user)

`UC_14_9` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count as InboundConns, dc(All_Traffic.src) as DistinctClients, min(_time) as FirstConn, max(_time) as LastConn, values(All_Traffic.src) as Clients from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=445 AND All_Traffic.action="allowed" by All_Traffic.dest, All_Traffic.src, _time span=10m | `drop_dm_object_name(All_Traffic)` | where InboundConns > 500 | eval DurationSec = LastConn - FirstConn | sort 0 - InboundConns
```

**Defender KQL:**
```kql
// Defender XDR does not log per-file remote SMB access events the way
// Windows Security 5145 does. Closest server-side proxy: inbound SMB
// connection storm against a host whose 445 port is internet/network-facing.
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort == 445
| summarize InboundConns = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            SampleProcesses = make_set(InitiatingProcessFileName, 5)
            by FileServer=DeviceName, ClientIP=RemoteIP, bin_at(Timestamp, 10m, ago(1h))
| where InboundConns > 500
| extend DurationSec = datetime_diff('second', LastSeen, FirstSeen)
| order by InboundConns desc
```

### [LLM] Python (or LOLBin) interpreter sustaining SMB connection burst to file servers

`UC_14_10` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count as SmbConns, dc(All_Traffic.dest) as DistinctServers, min(_time) as FirstConn, max(_time) as LastConn from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=445 AND All_Traffic.action="allowed" AND (All_Traffic.app="python.exe" OR All_Traffic.app="pythonw.exe" OR All_Traffic.app="python3.exe" OR All_Traffic.app="py.exe" OR All_Traffic.app="powershell.exe" OR All_Traffic.app="pwsh.exe") AND NOT All_Traffic.user="*$" by All_Traffic.src, All_Traffic.user, All_Traffic.app, _time span=10m | `drop_dm_object_name(All_Traffic)` | where SmbConns > 200 | eval DurationSec = LastConn - FirstConn | sort 0 - SmbConns
```

**Defender KQL:**
```kql
// GhostLock PoC is delivered as a Python ctypes wrapper. Catch interpreters
// generating a sustained burst of internal SMB sessions from one user context.
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemotePort == 445
| where RemoteIPType == "Private"
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName in~ (
    "python.exe","pythonw.exe","python3.exe","py.exe",
    "powershell.exe","pwsh.exe"
  )
| summarize SmbConns = count(),
            DistinctServers = dcount(RemoteIP),
            FirstConn = min(Timestamp),
            LastConn = max(Timestamp),
            Servers = make_set(RemoteIP, 25),
            SampleCmd = any(InitiatingProcessCommandLine)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
               InitiatingProcessId, bin_at(Timestamp, 10m, ago(1h))
| where SmbConns > 200
| extend DurationSec = datetime_diff('second', LastConn, FirstConn),
         ConnsPerSec = todouble(SmbConns) / todouble(max_of(DurationSec, 1))
| order by SmbConns desc
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
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


## Why this matters

Severity classified as **CRIT** based on: 11 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
