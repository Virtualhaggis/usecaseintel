# [CRIT] EtherRAT Campaign Uses SEO Poisoning and GitHub Facades to Target Enterprise Admins

**Source:** Cyber Security News
**Published:** 2026-05-01
**Article:** https://cybersecuritynews.com/etherrat-campaign-uses-seo-poisoning/

## Threat Profile

Home Cyber Security News 
EtherRAT Campaign Uses SEO Poisoning and GitHub Facades to Target Enterprise Admins 
By Tushar Subhra Dutta 
May 1, 2026 
A new and well-planned malware campaign has been actively targeting enterprise administrators, DevOps engineers, and security analysts by hijacking their everyday search habits. 
Rather than using mass phishing or broad spam waves, threat actors behind this operation have carefully crafted a delivery chain that puts dangerous software directly in fro…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

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
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1547.001** — Persistence (article-specific)
- **T1564.003** — Hide Artifacts: Hidden Window
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1218.007** — System Binary Proxy Execution: Msiexec
- **T1027.010** — Obfuscated Files or Information: Command Obfuscation
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] EtherRAT Stage 3: conhost.exe --headless launching node.exe payload

`UC_17_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent values(Processes.process_path) as path values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name=conhost.exe (Processes.process="*--headless*" OR Processes.process="*-headless*") (Processes.process="*node.exe*" OR Processes.process="*\\node.exe*" OR Processes.process="*.dat*") by host Processes.process_name Processes.process_id Processes.parent_process_name Processes.dest | `drop_dm_object_name(Processes)` | where NOT match(user, "(?i)^(NT AUTHORITY|SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$") OR like(parent, "%msiexec%") | sort - lastTime
```

**Defender KQL:**
```kql
// EtherRAT Stage 3 — conhost.exe spawned with --headless that hosts node.exe
// Atos / Sysdig 2026 — JavaScript RAT runs persistently inside conhost to avoid Task Manager visibility
let _lookback = 14d;
let _conhost_headless = DeviceProcessEvents
    | where Timestamp > ago(_lookback)
    | where FileName =~ "conhost.exe"
    | where ProcessCommandLine has_any ("--headless","-headless")
    | project Timestamp, DeviceId, DeviceName, AccountName,
              ConhostPid = ProcessId, ConhostCmd = ProcessCommandLine,
              ConhostParent = InitiatingProcessFileName,
              ConhostParentCmd = InitiatingProcessCommandLine;
// Either the conhost cmdline itself references node.exe, OR a node.exe child appears within 5s on the same host
_conhost_headless
| where ConhostCmd has_any ("node.exe",".dat","AppData\\Roaming","AppData\\Local\\Temp")
| union (
    _conhost_headless
    | join kind=inner (
        DeviceProcessEvents
        | where Timestamp > ago(_lookback)
        | where InitiatingProcessFileName =~ "conhost.exe"
        | where FileName =~ "node.exe"
        | project NodeTime = Timestamp, DeviceId, NodeParentPid = InitiatingProcessId,
                  NodeCmd = ProcessCommandLine, NodePath = FolderPath, NodeSha256 = SHA256
      ) on $left.DeviceId == $right.DeviceId and $left.ConhostPid == $right.NodeParentPid
    | where NodeTime between (Timestamp .. Timestamp + 5s)
)
| project Timestamp, DeviceName, AccountName, ConhostCmd, ConhostParent, ConhostParentCmd, NodeCmd, NodePath, NodeSha256
| order by Timestamp desc
```

### [LLM] EtherRAT Stage 1: msiexec SYSTEM-spawned cmd.exe with SET-concatenation obfuscation of curl/tar/cmd

`UC_17_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.process_path) as path values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name=msiexec.exe Processes.process_name IN (cmd.exe, conhost.exe) (Processes.process="*set *" Processes.process="*curl*" OR Processes.process="*set *" Processes.process="*tar*" OR Processes.process="*&&set *") by host Processes.process_name Processes.parent_process_name Processes.process_id Processes.dest | `drop_dm_object_name(Processes)` | eval set_count=mvcount(split(lower(cmd),"set "))-1 | where set_count >= 5 AND match(user, "(?i)(SYSTEM|S-1-5-18)") | sort - lastTime
```

**Defender KQL:**
```kql
// EtherRAT Stage 1 — msiexec Custom Action launches obfuscated cmd.exe at SYSTEM
// Article: 'splits all sensitive command names, including curl, tar, copy, start, and cmd, across multiple SET variable assignments'
let _lookback = 14d;
let _impersonated_tools = dynamic(["psexec","azcopy","sysmon","laps","kustoexplorer","tftpd64","procexp","tcpview"]);
DeviceProcessEvents
| where Timestamp > ago(_lookback)
| where InitiatingProcessFileName =~ "msiexec.exe"
| where FileName in~ ("cmd.exe","conhost.exe")
| where ProcessIntegrityLevel in ("System","high")
   or InitiatingProcessIntegrityLevel == "System"
// SET-concat obfuscation: many SET= assignments inside one cmd-line
| extend SetCount = countof(tolower(ProcessCommandLine), "set ")
| where SetCount >= 5
   or ProcessCommandLine matches regex @"(?i)set\s+\w+=\w?\s*&\s*set\s+\w+=\w?\s*&\s*set\s+\w+="
// Either references the obfuscated tokens directly OR the parent MSI impersonates an admin tool
| extend MsiPath = tolower(InitiatingProcessCommandLine)
| where ProcessCommandLine has_any ("curl","tar","%comspec%","!cmd!","!curl!","!tar!")
   or MsiPath has_any (_impersonated_tools)
| project Timestamp, DeviceName, AccountName, ProcessIntegrityLevel,
          MsiCmd = InitiatingProcessCommandLine,
          MsiSha256 = InitiatingProcessSHA256,
          BatchCmd = ProcessCommandLine,
          SetCount
| order by Timestamp desc
```

### [LLM] EtherRAT C2 lookup: node.exe / conhost.exe contacting public Ethereum JSON-RPC endpoints

`UC_17_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dport values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.process_name IN (node.exe, conhost.exe) (All_Traffic.dest IN ("cloudflare-eth.com","mainnet.infura.io","eth.llamarpc.com","ethereum-rpc.publicnode.com","rpc.ankr.com","eth.public-rpc.com","rpc.flashbots.net","eth.drpc.org","rpc.builder0x69.io") OR All_Traffic.url IN ("*eth_call*","*jsonrpc*")) by host All_Traffic.src All_Traffic.process_name All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | stats count as conn_count dc(dest) as distinct_eth_rpcs values(dest) as endpoints min(firstTime) as first max(lastTime) as last by host process_name | where conn_count >= 3 AND distinct_eth_rpcs >= 2 | sort - last
```

**Defender KQL:**
```kql
// EtherRAT C2 — node.exe / headless-conhost contacting public Ethereum RPC endpoints to read C2 from a smart contract
// Article: 'periodic outbound requests (every ~5 minutes) to public ETH RPC endpoints'
let _lookback = 7d;
let _eth_rpc_hosts = dynamic([
    "cloudflare-eth.com",
    "mainnet.infura.io",
    "eth.llamarpc.com",
    "ethereum-rpc.publicnode.com",
    "rpc.ankr.com",
    "eth.public-rpc.com",
    "rpc.flashbots.net",
    "eth.drpc.org",
    "rpc.builder0x69.io",
    "api.mycryptoapi.com",
    "rpc.payload.de"
]);
let _eth_callers = DeviceNetworkEvents
    | where Timestamp > ago(_lookback)
    | where InitiatingProcessFileName in~ ("node.exe","conhost.exe","wscript.exe","cscript.exe")
    | where RemoteIPType == "Public"
    | where RemoteUrl has_any (_eth_rpc_hosts) or RemoteUrl has "jsonrpc";
_eth_callers
| summarize ConnCount = count(),
            DistinctRpcs = dcount(RemoteUrl),
            DistinctMinutes = dcount(bin(Timestamp, 1m)),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp),
            SampleEndpoints = make_set(RemoteUrl, 10),
            SampleParentCmds = make_set(InitiatingProcessCommandLine, 5)
            by DeviceId, DeviceName, InitiatingProcessFileName,
               InitiatingProcessAccountName
| where ConnCount >= 3 and DistinctRpcs >= 2     // the implant queries multiple RPCs in parallel; >=2 distinct + repeat is the signal
   or DistinctMinutes >= 3                        // OR sustained ~5-min cadence over >=15 min
| order by LastSeen desc
```

### Beaconing â€” periodic outbound to small set of destinations

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

### Article-specific behavioural hunt — EtherRAT Campaign Uses SEO Poisoning and GitHub Facades to Target Enterprise Adm

`UC_17_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — EtherRAT Campaign Uses SEO Poisoning and GitHub Facades to Target Enterprise Adm ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","conhost.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","conhost.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — EtherRAT Campaign Uses SEO Poisoning and GitHub Facades to Target Enterprise Adm
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "conhost.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "conhost.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 13 use case(s) fired, 26 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
