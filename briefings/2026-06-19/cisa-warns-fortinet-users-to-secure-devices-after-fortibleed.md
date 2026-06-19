# [HIGH] CISA warns Fortinet users to secure devices after FortiBleed leak

**Source:** BleepingComputer
**Published:** 2026-06-19
**Article:** https://www.bleepingcomputer.com/news/security/cisa-warns-fortinet-users-to-secure-devices-after-fortibleed-leak/

## Threat Profile

CISA warns Fortinet users to secure devices after FortiBleed leak 
By Sergiu Gatlan 
June 19, 2026
02:47 AM
0 


The U.S. Cybersecurity and Infrastructure Security Agency (CISA) urged Fortinet customers to secure their devices after nearly 74,000 firewall and VPN credentials were exposed in a data leak dubbed "FortiBleed."


This warning comes after threat actors used compromised credentials to target internet-accessible Fortinet devices across government and private-sector organizations wor…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `motionposse.com`
- **Domain (defanged):** `stategun.cc`
- **Domain (defanged):** `toyotaio.cc`
- **Domain (defanged):** `foxconn.com`
- **Domain (defanged):** `chevron.com`
- **Domain (defanged):** `mercedes-benz.com`
- **Domain (defanged):** `comcast.com`
- **Domain (defanged):** `at&t.net`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1110.001** — Password Guessing
- **T1110.003** — Password Spraying
- **T1557** — Adversary-in-the-Middle
- **T1078** — Valid Accounts
- **T1133** — External Remote Services
- **T1602.002** — Network Device Configuration Dump
- **T1005** — Data from Local System
- **T1567** — Exfiltration Over Web Service
- **T1021.001** — Remote Desktop Protocol
- **T1021.006** — Windows Remote Management
- **T1136.001** — Create Account: Local Account
- **T1098** — Account Manipulation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### FortiGate SSL VPN brute-force / credential stuffing surge against /remote/login

`UC_0_8` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Authentication.user) as distinct_users, values(Authentication.user) as users, values(Authentication.dest) as dest from datamodel=Authentication where Authentication.app="fortigate-sslvpn" Authentication.action="failure" by Authentication.src, _time span=5m | `drop_dm_object_name(Authentication)` | where count>50 OR distinct_users>25 | sort - count
```

**Defender KQL:**
```kql
// Defender XDR does not natively ingest FortiGate VPN logs; this query targets Defender for Identity/IdentityLogonEvents when FortiGate auth is forwarded via SAML to AAD
IdentityLogonEvents
| where Timestamp > ago(1h)
| where Application has_any ("FortiGate","Fortinet","SSLVPN")
| where ActionType == "LogonFailed"
| summarize FailedCount = count(), DistinctUsers = dcount(AccountUpn), Users = make_set(AccountUpn, 25) by IPAddress, bin(Timestamp, 5m)
| where FailedCount > 50 or DistinctUsers > 25
| order by FailedCount desc
```

### First-seen successful FortiGate SSL VPN logon for user from new source IP (FortiBleed reuse)

`UC_0_9` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as firstSeen, count from datamodel=Authentication where Authentication.app="fortigate-sslvpn" Authentication.action="success" by Authentication.user, Authentication.src | `drop_dm_object_name(Authentication)` | eventstats min(firstSeen) as userFirstSeen by user | where firstSeen=userFirstSeen AND firstSeen > relative_time(now(),"-1h") | join type=left user [| tstats `summariesonly` count as historicalLogins from datamodel=Authentication where Authentication.app="fortigate-sslvpn" Authentication.action="success" earliest=-30d@d latest=-1h by Authentication.user | `drop_dm_object_name(Authentication)`] | where historicalLogins > 5
```

**Defender KQL:**
```kql
let Window = 1h;
let Baseline = IdentityLogonEvents
    | where Timestamp between (ago(30d) .. ago(Window))
    | where Application has_any ("FortiGate","Fortinet","SSLVPN")
    | where ActionType == "LogonSuccess"
    | summarize by AccountUpn, IPAddress;
IdentityLogonEvents
| where Timestamp > ago(Window)
| where Application has_any ("FortiGate","Fortinet","SSLVPN")
| where ActionType == "LogonSuccess"
| join kind=leftanti Baseline on AccountUpn, IPAddress
| project Timestamp, AccountUpn, IPAddress, Location, DeviceName, Application
| order by Timestamp desc
```

### FortiGate configuration backup / export to non-routine destination

`UC_0_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`fortigate_admin_logs` (subtype=system OR logid=0100032002 OR logid=0100044546) (msg="Configuration backed up" OR action="backup" OR "execute backup config") | stats min(_time) as firstSeen, count, values(srcip) as src, values(user) as admin, values(dstip) as dst by devname | join type=left admin [| tstats `summariesonly` count as priorBackups from datamodel=Change where Change.action="backup" Change.object_category="firewall" earliest=-30d@d latest=-1h by Change.user | `drop_dm_object_name(Change)`] | where priorBackups < 3 OR isnull(priorBackups)
```

**Defender KQL:**
```kql
// Defender does not ingest FortiGate admin events; this targets the case where the config artefact is dropped onto a Windows jump host
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName matches regex @"(?i)^(fgt|fortigate|firewall|backup|sys)[A-Za-z0-9_\-\.]*\.(conf|cfg|backup|bak)$"
   or FileName endswith ".conf.gz"
| where InitiatingProcessFileName !in~ ("backupexec.exe","veeam.backup.shell.exe")
| project Timestamp, DeviceName, FileName, FolderPath, FileSize, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### VPN-pool IP fan-out — single SSL VPN user touching multiple internal hosts post-auth

`UC_0_11` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(All_Traffic.dest) as distinctDests, values(All_Traffic.dest) as dests, count from datamodel=Network_Traffic where All_Traffic.dest_port IN (445,3389,5985,5986,22) (All_Traffic.src IN (`fortigate_sslvpn_pool`)) by All_Traffic.src, All_Traffic.user, _time span=10m | `drop_dm_object_name(All_Traffic)` | where distinctDests > 8
```

**Defender KQL:**
```kql
let SSLVPNPools = dynamic(["10.212.134.0/24","10.212.135.0/24"]); // adjust to your FortiGate SSL VPN address-objects
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (445, 3389, 5985, 5986, 22)
| where ipv4_is_in_any_range(LocalIP, SSLVPNPools) or ipv4_is_in_any_range(RemoteIP, SSLVPNPools)
| summarize DistinctDests = dcount(RemoteIP), Dests = make_set(RemoteIP, 20), Ports = make_set(RemotePort) by DeviceId, DeviceName, InitiatingProcessAccountName, bin(Timestamp, 10m)
| where DistinctDests > 8
| order by DistinctDests desc
```

### FortiGate admin account creation or privilege escalation following anomalous logon

`UC_0_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Authentication.src) as adminSrc, min(_time) as authTime from datamodel=Authentication where Authentication.app="fortigate-admin" Authentication.action="success" by Authentication.user, Authentication.dest | `drop_dm_object_name(Authentication)` | rename user as admin, dest as firewall | join type=inner admin firewall [| tstats `summariesonly` min(_time) as adminAddTime, values(All_Changes.object) as newAdmins from datamodel=Change where Change.action IN ("created","modified") Change.object_category="firewall_admin" by Change.user, Change.dest | `drop_dm_object_name(Change)` | rename user as admin, dest as firewall] | where adminAddTime > authTime AND adminAddTime < authTime + 600
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `motionposse.com`, `stategun.cc`, `toyotaio.cc`, `foxconn.com`, `chevron.com`, `mercedes-benz.com`, `comcast.com`, `at&t.net`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 13 use case(s) fired, 26 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
