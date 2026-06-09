# [CRIT] Meta Blocks NSO Group's New WhatsApp Phishing Attack, Files Contempt Order

**Source:** The Hacker News
**Published:** 2026-06-08
**Article:** https://thehackernews.com/2026/06/meta-blocks-nso-groups-new-whatsapp.html

## Threat Profile

Critical Check Point VPN Flaw Exploited to Bypass Passwords in IKEv1 Setups 
 Ravie Lakshmanan  Jun 08, 2026 Vulnerability / Network Security 
Check Point has warned of active exploitation of a critical vulnerability impacting Remote Access VPN and Mobile Access deployments that are configured to use the deprecated IKEv1 key exchange protocol.
The vulnerability, tracked as CVE-2026-50751 (CVSS score: 9.3), is a case of a logic flow weakness in certificate validation that allows an unauthentica…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-50751`
- **CVE:** `CVE-2026-50752`
- **IPv4 (defanged):** `45.77.149.152`
- **IPv4 (defanged):** `209.182.225.136`
- **IPv4 (defanged):** `38.60.157.139`
- **IPv4 (defanged):** `162.33.177.101`
- **IPv4 (defanged):** `45.76.26.42`
- **IPv4 (defanged):** `144.208.127.155`
- **IPv4 (defanged):** `38.54.88.201`
- **IPv4 (defanged):** `38.54.107.167`
- **IPv4 (defanged):** `66.42.99.200`
- **MD5:** `52fda5c1b9704544f32ee98d9060e689`
- **MD5:** `51d39aa39478beeac94f2d12f682ecce`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1133** — External Remote Services
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1567.002** — Exfiltration to Cloud Storage
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Check Point Remote Access VPN inbound auth from CVE-2026-50751 actor VPS IPs

`UC_43_11` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(dest) as gateway values(dest_port) as dest_port values(action) as action from datamodel=Network_Traffic.All_Traffic where (sourcetype IN ("opsec","cp_log","checkpoint:firewall","checkpoint:vpn") OR All_Traffic.dest_port IN (500,4500,443) AND All_Traffic.action!="blocked") AND All_Traffic.src IN ("45.77.149.152","209.182.225.136","38.60.157.139","162.33.177.101","45.76.26.42","144.208.127.155","38.54.88.201","38.54.107.167") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.action | `drop_dm_object_name(All_Traffic)` | eval firstSeen=strftime(firstSeen,"%Y-%m-%dT%H:%M:%S"), lastSeen=strftime(lastSeen,"%Y-%m-%dT%H:%M:%S")
```

**Defender KQL:**
```kql
// Targets internet-facing CP gateway whose NIC is enrolled in Defender for Endpoint / Server
DeviceNetworkEvents
| where Timestamp > ago(45d)   // Check Point assesses earliest exploitation 2026-05-07
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess","ConnectionInbound")
| where RemoteIP in ("45.77.149.152","209.182.225.136","38.60.157.139","162.33.177.101","45.76.26.42","144.208.127.155","38.54.88.201","38.54.107.167")
| where LocalPort in (500, 4500, 443)
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

### Qilin Linux ransomware ELF payload (CVE-2026-50751 campaign) — known MD5 file event

`UC_43_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Filesystem.file_path) as file_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("52fda5c1b9704544f32ee98d9060e689","51d39aa39478beeac94f2d12f682ecce") by Filesystem.dest Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | append [| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_hash IN ("52fda5c1b9704544f32ee98d9060e689","51d39aa39478beeac94f2d12f682ecce") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
let qilinHashes = dynamic(["52fda5c1b9704544f32ee98d9060e689","51d39aa39478beeac94f2d12f682ecce"]);
union
  (DeviceFileEvents
    | where Timestamp > ago(45d)
    | where MD5 in (qilinHashes)
    | project Timestamp, DeviceName, Source="FileEvent", ActionType, FileName, FolderPath, MD5, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
  (DeviceProcessEvents
    | where Timestamp > ago(45d)
    | where MD5 in (qilinHashes)
    | project Timestamp, DeviceName, Source="ProcessEvent", ActionType="ProcessCreated", FileName, FolderPath, MD5, SHA256, InitiatingProcessFileName=InitiatingProcessFileName, InitiatingProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessAccountName=AccountName)
| order by Timestamp asc
```

### Rclone exfiltration from Check Point VPN gateway or post-bypass internal host

`UC_43_13` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name IN ("rclone","rclone.exe") AND Processes.process IN ("*copy*","*sync*","*move*","*cat*") AND Processes.process IN ("*mega:*","*s3:*","*b2:*","*drive:*","*dropbox:*","*onedrive:*","*pcloud:*","*box:*","*remote:*","*gcs:*","*azureblob:*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where user!="root" OR (user="root" AND parent!="cron" AND parent!="systemd")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(45d)
| where FileName =~ "rclone" or FileName =~ "rclone.exe" or ProcessCommandLine matches regex @"(?i)\brclone\b"
| where ProcessCommandLine has_any ("copy","sync","move","copyto","moveto","cat")
| where ProcessCommandLine matches regex @"(?i)\s(mega|s3|b2|drive|dropbox|onedrive|pcloud|box|gcs|azureblob|webdav|sftp|ftp|remote):"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Internal host outbound to CVE-2026-50751 Qilin actor IPs (post-bypass C2 / staging)

`UC_43_14` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen sum(All_Traffic.bytes_out) as bytes_out sum(All_Traffic.bytes_in) as bytes_in values(All_Traffic.dest_port) as dest_ports values(All_Traffic.app) as apps from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("45.77.149.152","209.182.225.136","38.60.157.139","162.33.177.101","45.76.26.42","144.208.127.155","38.54.88.201","38.54.107.167") AND All_Traffic.src_category!="external" by All_Traffic.src All_Traffic.dest All_Traffic.action | `drop_dm_object_name(All_Traffic)` | eval firstSeen=strftime(firstSeen,"%Y-%m-%dT%H:%M:%S"), lastSeen=strftime(lastSeen,"%Y-%m-%dT%H:%M:%S")
```

**Defender KQL:**
```kql
let actorIPs = dynamic(["45.77.149.152","209.182.225.136","38.60.157.139","162.33.177.101","45.76.26.42","144.208.127.155","38.54.88.201","38.54.107.167"]);
DeviceNetworkEvents
| where Timestamp > ago(45d)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","ConnectionFound")
| where RemoteIPType == "Public"
| where RemoteIP in (actorIPs)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), ConnCount = count(), Ports = make_set(RemotePort, 20), Processes = make_set(InitiatingProcessFileName, 20) by DeviceName, RemoteIP, InitiatingProcessAccountName
| order by FirstSeen asc
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-50751`, `CVE-2026-50752`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.77.149.152`, `209.182.225.136`, `38.60.157.139`, `162.33.177.101`, `45.76.26.42`, `144.208.127.155`, `38.54.88.201`, `38.54.107.167` _(+1 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `52fda5c1b9704544f32ee98d9060e689`, `51d39aa39478beeac94f2d12f682ecce`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 15 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
