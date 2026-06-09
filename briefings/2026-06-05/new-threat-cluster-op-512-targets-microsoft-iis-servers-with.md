# [HIGH] New Threat Cluster OP-512 Targets Microsoft IIS Servers with Custom Web Shell Framework

**Source:** The Hacker News
**Published:** 2026-06-05
**Article:** https://thehackernews.com/2026/06/new-threat-cluster-op-512-targets.html

## Threat Profile

New Threat Cluster OP-512 Targets Microsoft IIS Servers with Custom Web Shell Framework 
 Ravie Lakshmanan  Jun 05, 2026 Cyber Espionage / Threat Intelligence 
Cybersecurity researchers have discovered a previously unreported threat cluster dubbed OP-512 that has been observed targeting Microsoft Internet Information Services (IIS) servers to deploy a bespoke web shell framework.
ReliaQuest has assessed with moderate to high confidence that the espionage-focused activity is linked to China.
"O…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `ashx.lhlsjcb.com`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1071.004** — Application Layer Protocol: DNS
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1505.003** — Server Software Component: Web Shell
- **T1190** — Exploit Public-Facing Application
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1033** — System Owner/User Discovery
- **T1087** — Account Discovery
- **T1134.001** — Access Token Manipulation: Token Impersonation/Theft
- **T1068** — Exploitation for Privilege Escalation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] OP-512 C2 beacon to ashx.lhlsjcb[.]com from IIS host

`UC_55_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.query) as query from datamodel=Network_Resolution where DNS.query="*lhlsjcb.com" OR DNS.query="ashx.lhlsjcb.com" by host | `drop_dm_object_name(DNS)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.url) as url from datamodel=Web where Web.url="*lhlsjcb.com*" by host | `drop_dm_object_name(Web)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteUrl has "lhlsjcb.com" or RemoteUrl has_cs "ashx.lhlsjcb.com"
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp asc
```

### [LLM] IIS worker w3wp.exe writes .aspx/.ashx handler to upload/temp directory (OP-512 web shell drop)

`UC_55_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.process_name="w3wp.exe" (Filesystem.file_name="*.aspx" OR Filesystem.file_name="*.ashx" OR Filesystem.file_name="*.asmx" OR Filesystem.file_name="*.asax") (Filesystem.file_path="*\\upload*" OR Filesystem.file_path="*\\uploads*" OR Filesystem.file_path="*\\temp*" OR Filesystem.file_path="*\\tmp*" OR Filesystem.file_path="*\\App_Data*") by host Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName endswith ".aspx" or FileName endswith ".ashx" or FileName endswith ".asmx" or FileName endswith ".asax"
| where FolderPath has_any ("\\upload", "\\uploads", "\\temp", "\\tmp", "\\App_Data", "\\images", "\\files")
| project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine, InitiatingProcessAccountName, RequestSourceIP
| order by Timestamp desc
```

### [LLM] IIS w3wp.exe spawns whoami /priv or cmd.exe — OP-512 web shell command execution

`UC_55_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name="w3wp.exe" (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="whoami.exe" OR Processes.process_name="net.exe" OR Processes.process_name="net1.exe" OR Processes.process_name="systeminfo.exe" OR Processes.process_name="ipconfig.exe" OR Processes.process_name="tasklist.exe" OR Processes.process_name="hostname.exe") by host Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "net1.exe", "systeminfo.exe", "ipconfig.exe", "tasklist.exe", "hostname.exe", "wmic.exe", "reg.exe", "sc.exe")
| extend IsWhoamiPriv = (FileName =~ "whoami.exe" and ProcessCommandLine has_any ("/priv", "/all", "/groups"))
| project Timestamp, DeviceName, DeviceId, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, IsWhoamiPriv
| order by Timestamp desc
```

### [LLM] OP-512 Potato Suite SYSTEM escalation from IIS worker (SeImpersonate token abuse)

`UC_55_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_integrity_level) as integrity from datamodel=Endpoint.Processes where (Processes.parent_process_name="w3wp.exe" OR Processes.parent_process_path="*\\inetsrv\\w3wp.exe") (Processes.process_integrity_level="System" OR Processes.process_integrity_level="high") by host Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where user!="SYSTEM" OR process_name!="w3wp.exe" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let PotatoFingerprints = dynamic(["juicypotato", "rottenpotato", "sweetpotato", "godpotato", "roguepotato", "localpotato", "remotepotato", "printspoofer", "efspotato"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where ProcessIntegrityLevel in~ ("System", "High")
   or ProcessCommandLine has_any (PotatoFingerprints)
   or FileName has_any (PotatoFingerprints)
   or InitiatingProcessTokenElevation =~ "TokenElevationTypeFull" and AccountName =~ "SYSTEM" and InitiatingProcessAccountName !in~ ("system", "network service", "local service")
| project Timestamp, DeviceName, DeviceId, AccountName, FileName, FolderPath, ProcessCommandLine, ProcessIntegrityLevel, ProcessTokenElevation, InitiatingProcessAccountName, InitiatingProcessIntegrityLevel
| order by Timestamp desc
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

### Article-specific behavioural hunt — New Threat Cluster OP-512 Targets Microsoft IIS Servers with Custom Web Shell Fr

`UC_55_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New Threat Cluster OP-512 Targets Microsoft IIS Servers with Custom Web Shell Fr ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("w3wp.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("w3wp.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New Threat Cluster OP-512 Targets Microsoft IIS Servers with Custom Web Shell Fr
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("w3wp.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("w3wp.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `ashx.lhlsjcb.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
