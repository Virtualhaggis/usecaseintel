# [CRIT] Iranian-Nexus Operation Targets Oman Ministries With Webshells, SQL Escalation, and Data Theft

**Source:** Cyber Security News
**Published:** 2026-05-06
**Article:** https://cybersecuritynews.com/iranian-nexus-operation-targets-oman-ministries-with-webshells/

## Threat Profile

Home Cyber Security News 
Iranian-Nexus Operation Targets Oman Ministries With Webshells, SQL Escalation, and Data Theft 
By Tushar Subhra Dutta 
May 6, 2026 
A sophisticated cyber operation linked to an Iranian-nexus threat actor has quietly worked through at least 12 Omani government ministries, stealing tens of thousands of citizen records and leaving persistent backdoors behind. 
The attackers used webshells, SQL server escalation, and old but effective exploits to move through government ne…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `172.86.76.127`
- **IPv4 (defanged):** `172.86.76.101`
- **IPv4 (defanged):** `172.86.76.94`
- **IPv4 (defanged):** `172.86.76.108`
- **IPv4 (defanged):** `172.86.76.112`
- **IPv4 (defanged):** `172.86.76.120`
- **IPv4 (defanged):** `172.86.76.121`
- **IPv4 (defanged):** `172.86.76.124`
- **IPv4 (defanged):** `172.86.76.129`
- **IPv4 (defanged):** `172.86.76.130`
- **IPv4 (defanged):** `45.59.114.60`
- **IPv4 (defanged):** `104.21.27.95`
- **IPv4 (defanged):** `172.67.142.35`
- **Domain (defanged):** `dubai-1.vaermb.com`
- **Domain (defanged):** `regorixa.com`
- **Domain (defanged):** `dubai-2.vaermb.com`
- **Domain (defanged):** `dubai-3.vaermb.com`
- **Domain (defanged):** `myjitsi.exceptionnotfound.ir`
- **Domain (defanged):** `dubai-4.vaermb.com`
- **Domain (defanged):** `s5.sideliner.ir`
- **Domain (defanged):** `dubai-5.vaermb.com`
- **Domain (defanged):** `dubai-6.vaermb.com`
- **Domain (defanged):** `dubai-7.vaermb.com`
- **Domain (defanged):** `suanefllix.com`
- **Domain (defanged):** `brnettlix.com`
- **Domain (defanged):** `brttfrixx.com`
- **Domain (defanged):** `realprimefix.com`
- **Domain (defanged):** `identificara.com`
- **Domain (defanged):** `dubai-10.vaermb.com`
- **Domain (defanged):** `dubai-8.vaermb.com`
- **Domain (defanged):** `dubai-9.vaermb.com`
- **Domain (defanged):** `shop.exceptionnotfound.ir`
- **Domain (defanged):** `price.exceptionnotfound.ir`
- **Domain (defanged):** `myjitsi.mrnajafipour.ir`
- **Domain (defanged):** `tools.exceptionnotfound.ir`

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
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1505.003** — Server Software Component: Web Shell
- **T1190** — Exploit Public-Facing Application
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090** — Proxy
- **T1568** — Dynamic Resolution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Iranian-Nexus webshells hc2.aspx / health_check_t.aspx written to IIS or Exchange web roots

`UC_13_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("hc2.aspx","health_check_t.aspx") AND (Filesystem.file_path="*\\inetpub\\*" OR Filesystem.file_path="*\\wwwroot\\*" OR Filesystem.file_path="*\\Exchange Server\\*" OR Filesystem.file_path="*\\FrontEnd\\HttpProxy\\*" OR Filesystem.file_path="*\\ClientAccess\\*") by Filesystem.dest Filesystem.file_name Filesystem.user | `drop_dm_object_name(Filesystem)` | sort 0 -lastTime
```

**Defender KQL:**
```kql
// Iranian-nexus Oman campaign — webshell drop on disk
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in~ ("hc2.aspx","health_check_t.aspx")
| where FolderPath has_any (@"\inetpub\", @"\wwwroot\", @"\Exchange Server\", @"\FrontEnd\HttpProxy\", @"\ClientAccess\")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessAccountDomain, InitiatingProcessAccountName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] IIS w3wp.exe spawns recon/shell binaries on hosts where Iranian-nexus webshells were observed

`UC_13_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("hc2.aspx","health_check_t.aspx") by Filesystem.dest | `drop_dm_object_name(Filesystem)` | rename dest as victim_dest | join type=inner victim_dest [| tstats summariesonly=t count values(Processes.process) as cmd values(Processes.process_name) as child_proc from datamodel=Endpoint.Processes where Processes.parent_process_name="w3wp.exe" AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","certutil.exe","net.exe","reg.exe","whoami.exe","quser.exe","systeminfo.exe","tasklist.exe","ipconfig.exe","netstat.exe","nltest.exe","dsquery.exe") by Processes.dest Processes.user Processes.parent_process Processes.process_name _time | `drop_dm_object_name(Processes)` | rename dest as victim_dest] | sort 0 -lastTime
```

**Defender KQL:**
```kql
// Iranian-nexus Oman — operator activity through hc2/health_check_t webshells
let _victims = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("hc2.aspx","health_check_t.aspx")
    | where FolderPath has_any (@"\inetpub\", @"\wwwroot\", @"\Exchange Server\", @"\FrontEnd\HttpProxy\", @"\ClientAccess\")
    | summarize by DeviceId;
DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceId in (_victims)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","certutil.exe","net.exe","net1.exe","reg.exe","whoami.exe","quser.exe","systeminfo.exe","tasklist.exe","ipconfig.exe","netstat.exe","nltest.exe","dsquery.exe")
| project Timestamp, DeviceName, AccountName,
          ChildImage = FileName, ChildCmd = ProcessCommandLine,
          ParentCmd  = InitiatingProcessCommandLine,
          InitiatingProcessIntegrityLevel,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Egress or DNS to Iranian-nexus Oman C2 cluster (vaermb.com / exceptionnotfound.ir / 172.86.76.0/24 RouterHosting LLC)

`UC_13_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app values(All_Traffic.dest_port) as dest_port values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("172.86.76.94","172.86.76.101","172.86.76.108","172.86.76.112","172.86.76.120","172.86.76.121","172.86.76.124","172.86.76.127","172.86.76.129","172.86.76.130","45.59.114.60","104.21.27.95","172.67.142.35") by All_Traffic.src All_Traffic.src_ip All_Traffic.dest_ip | `drop_dm_object_name(All_Traffic)` | append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*.vaermb.com" OR DNS.query="*.exceptionnotfound.ir" OR DNS.query="*.sideliner.ir" OR DNS.query="*.mrnajafipour.ir" OR DNS.query="regorixa.com") by DNS.src DNS.query | `drop_dm_object_name(DNS)` | rename src as src_ip, query as dest_ip] | sort 0 -lastTime
```

**Defender KQL:**
```kql
// Iranian-nexus Oman C2 — IP and DNS sweep
let _c2_ips = dynamic([
    "172.86.76.94","172.86.76.101","172.86.76.108","172.86.76.112",
    "172.86.76.120","172.86.76.121","172.86.76.124","172.86.76.127",
    "172.86.76.129","172.86.76.130","45.59.114.60",
    "104.21.27.95","172.67.142.35"
]);
let _c2_apex = dynamic([
    "vaermb.com","exceptionnotfound.ir","sideliner.ir",
    "mrnajafipour.ir","regorixa.com"
]);
union isfuzzy=true
    ( DeviceNetworkEvents
        | where Timestamp > ago(30d)
        | where RemoteIP in (_c2_ips)
           or RemoteUrl has_any (_c2_apex)
        | project Timestamp, Source="NetworkConn", DeviceName, RemoteIP, RemoteUrl, RemotePort,
                  InitiatingProcessFileName, InitiatingProcessAccountName,
                  InitiatingProcessCommandLine ),
    ( DeviceEvents
        | where Timestamp > ago(30d)
        | where ActionType == "DnsQueryResponse"
        | extend Q = tostring(parse_json(AdditionalFields).QueryName)
        | where Q has_any (_c2_apex)
        | project Timestamp, Source="DnsQuery", DeviceName, RemoteIP="", RemoteUrl=Q, RemotePort=53,
                  InitiatingProcessFileName, InitiatingProcessAccountName,
                  InitiatingProcessCommandLine )
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `172.86.76.127`, `172.86.76.101`, `172.86.76.94`, `172.86.76.108`, `172.86.76.112`, `172.86.76.120`, `172.86.76.121`, `172.86.76.124` _(+27 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
