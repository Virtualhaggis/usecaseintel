# [CRIT] Dysphoria IoT Botnet Adds Blockchain C2 and Victim Relays After JackSkid Disruption

**Source:** The Hacker News, BleepingComputer
**Published:** 2026-07-27
**Article:** https://thehackernews.com/2026/07/dysphoria-iot-botnet-adds-blockchain-c2.html

## Threat Profile

Dysphoria IoT Botnet Adds Blockchain C2 and Victim Relays After JackSkid Disruption 
 Swati Khandelwal  Jul 27, 2026 Botnet / IoT Security 
Dysphoria , an Internet of Things (IoT) botnet line tracked by CNCERT and XLab, has adopted blockchain-based name services and infected-device relays after a March law-enforcement operation against JackSkid infrastructure. The researchers say the design makes the botnet harder to disrupt.
CNCERT, China's national computer emergency response team, and XLab,…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-9528`
- **IPv4 (defanged):** `194.87.198.208`
- **IPv4 (defanged):** `194.87.198.104`
- **IPv4 (defanged):** `194.58.38.79`
- **IPv4 (defanged):** `194.58.38.49`
- **IPv4 (defanged):** `194.58.38.96`
- **Domain (defanged):** `m3rnbvs5d.eth`
- **Domain (defanged):** `burrberry.eth`
- **Domain (defanged):** `24carnforth2merseyside.sol`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1568** — Dynamic Resolution
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090.002** — Proxy: External Proxy
- **T1102** — Web Service
- **T1110.001** — Brute Force: Password Guessing
- **T1078.001** — Valid Accounts: Default Accounts
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1090.001** — Proxy: Internal Proxy
- **T1571** — Non-Standard Port

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Dysphoria IoT botnet blockchain (ENS/SNS) C2 name resolution

`UC_8_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query IN ("m3rnbvs5d.eth","burrberry.eth","24carnforth2merseyside.sol") OR DNS.query IN ("*.m3rnbvs5d.eth","*.burrberry.eth","*.24carnforth2merseyside.sol") OR DNS.query="*.eth.link" OR DNS.query="*.eth.limo" OR DNS.query="*.eth" OR DNS.query="*.sol") by DNS.src DNS.dest DNS.query
| `drop_dm_object_name("DNS")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("m3rnbvs5d.eth","burrberry.eth","24carnforth2merseyside.sol")
    or RemoteUrl endswith ".eth" or RemoteUrl endswith ".sol"
    or RemoteUrl has_any (".eth.link",".eth.limo",".sol.link")
| where InitiatingProcessAccountName !endswith "$"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count(), Urls=make_set(RemoteUrl,10)
    by DeviceName, InitiatingProcessFileName, RemoteIP
| order by LastSeen desc
```

### Callout to Dysphoria distribution-node IPv4 addresses

`UC_8_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("194.87.198.208","194.87.198.104","194.58.38.79","194.58.38.49","194.58.38.96") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name("All_Traffic")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("194.87.198.208","194.87.198.104","194.58.38.79","194.58.38.49","194.58.38.96")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count()
    by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by LastSeen desc
```

### IoT/server host contacting public blockchain RPC or ENS/SNS gateways

`UC_8_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("*cloudflare-eth.com","*infura.io","*ankr.com","*llamarpc.com","*publicnode.com","*mainnet-beta.solana.com","*eth.limo","*eth.link") by DNS.src DNS.query
| `drop_dm_object_name("DNS")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any ("cloudflare-eth.com","mainnet.infura.io","eth-mainnet","rpc.ankr.com","llamarpc.com","publicnode.com","api.mainnet-beta.solana.com","solana-mainnet","eth.limo","eth.link")
| where InitiatingProcessAccountName !endswith "$"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count(), Hosts=make_set(RemoteUrl,10)
    by DeviceName, InitiatingProcessFileName
| order by Count desc
```

### Telnet/SSH weak-credential brute-force into edge/IoT devices (Dysphoria re-infection)

`UC_8_10` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication.Authentication where Authentication.app IN ("ssh","sshd","telnet","telnetd") Authentication.action=failure by Authentication.src Authentication.dest Authentication.user _time span=1h
| `drop_dm_object_name("Authentication")`
| where count > 20
| join type=inner src dest [| tstats `summariesonly` count as success_count from datamodel=Authentication.Authentication where Authentication.app IN ("ssh","sshd","telnet","telnetd") Authentication.action=success by Authentication.src Authentication.dest | `drop_dm_object_name("Authentication")`]
| sort - count
```

**Defender KQL:**
```kql
let Failed = DeviceLogonEvents
    | where Timestamp > ago(7d)
    | where ActionType == "LogonFailed"
    | where RemotePort in (22, 23)
    | summarize FailCount=count() by DeviceName, RemoteIP, bin(Timestamp, 1h)
    | where FailCount > 20;   // >20 failed edge-device logons/hr = guessing
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where RemotePort in (22, 23)
| join kind=inner Failed on DeviceName, RemoteIP
| project Timestamp, DeviceName, RemoteIP, AccountName, RemotePort, FailCount
| order by Timestamp desc
```

### CVE-2025-9528 Linksys E1700 /goform/systemCommand command injection

`UC_8_11` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*/goform/systemCommand*" AND Web.url="*command=*" by Web.src Web.dest Web.http_method Web.url Web.status
| `drop_dm_object_name("Web")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

### IoT victim-relay node behavior (fan-in relay with UPnP NAT traversal)

`UC_8_12` · phase: **c2** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(All_Traffic.src_ip) as inbound_sources count from datamodel=Network_Traffic.All_Traffic where All_Traffic.direction="inbound" All_Traffic.dest_category!="internal_service" by All_Traffic.dest _time span=1h
| `drop_dm_object_name("All_Traffic")`
| where inbound_sources > 30
| sort - inbound_sources
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(3d)
| where RemoteIPType == "Public"
| summarize InboundSources = dcountif(RemoteIP, ActionType == "InboundConnectionAccepted"),
            OutboundDests = dcountif(RemoteIP, ActionType in ("ConnectionSuccess","ConnectionRequest")),
            Ports = make_set(LocalPort, 15)
    by DeviceName, bin(Timestamp, 1h)
| where InboundSources > 30 and OutboundDests between (1 .. 5)   // heavy fan-in, thin upstream = relay
| order by InboundSources desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `194.87.198.208`, `194.87.198.104`, `194.58.38.79`, `194.58.38.49`, `194.58.38.96`, `m3rnbvs5d.eth`, `burrberry.eth`, `24carnforth2merseyside.sol`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-9528`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 13 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
