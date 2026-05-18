# [CRIT] New Fragnesia Linux Kernel LPE Grants Root Access via Page Cache Corruption

**Source:** The Hacker News
**Published:** 2026-05-14
**Article:** https://thehackernews.com/2026/05/new-fragnesia-linux-kernel-lpe-grants.html

## Threat Profile

New Fragnesia Linux Kernel LPE Grants Root Access via Page Cache Corruption 
 Ravie Lakshmanan  May 14, 2026 Vulnerability / Linux 
Details have emerged about a new variant of the recent Dirty Frag Linux local privilege escalation (LPE) vulnerability that allows local attackers to gain root access, making it the third such bug to be identified in the kernel within a span of two weeks.
Codenamed Fragnesia , the security vulnerability is tracked as CVE-2026-46300 (CVSS score: 7.8) and is rooted …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-46300`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1068** — Exploitation for Privilege Escalation
- **T1548.001** — Abuse Elevation Control Mechanism: Setuid and Setgid
- **T1547.006** — Boot or Logon Autostart Execution: Kernel Modules and Extensions

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Microsoft Defender AV signature for DirtyFrag/Fragnesia kernel exploit family

`UC_70_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Alerts.signature) as signatures values(Alerts.severity) as severity from datamodel=Alerts.Alerts where (Alerts.signature="*DirtyFrag*" OR Alerts.signature="*Fragnesia*" OR Alerts.signature="Trojan:Linux/DirtyFrag*") by Alerts.dest Alerts.user Alerts.vendor | `drop_dm_object_name(Alerts)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let DirtyFragSigs = dynamic(["DirtyFrag","Fragnesia","Trojan:Linux/DirtyFrag.Z!MTB","Trojan:Linux/DirtyFrag.DA!MTB"]);
let HitAlerts = AlertInfo
| where Timestamp > ago(14d)
| where Title has_any (DirtyFragSigs) or Category in ("Execution","PrivilegeEscalation")
| where ServiceSource =~ "Microsoft Defender for Endpoint"
| project AlertId, AlertTitle = Title, Severity, Category;
HitAlerts
| join kind=inner (
    AlertEvidence
    | where Timestamp > ago(14d)
  ) on AlertId
| where AlertTitle has_any (DirtyFragSigs) or ThreatFamily has_any (DirtyFragSigs)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Devices = make_set_if(DeviceName, EntityType == "Machine"),
            Users = make_set_if(strcat(AccountDomain, "\\", AccountName), EntityType == "User"),
            Files = make_set_if(FileName, EntityType == "File"),
            CmdLines = make_set_if(ProcessCommandLine, EntityType == "Process"),
            ThreatFamilies = make_set(ThreatFamily)
            by AlertId, AlertTitle, Severity
| order by LastSeen desc
```

### [LLM] Linux /usr/bin/su invoked by exploit binary in /tmp or /dev/shm (Fragnesia page-cache PoC pattern)

`UC_70_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process) as parent_cmds values(Processes.process_hash) as hashes from datamodel=Endpoint.Processes where Processes.os="Linux" AND Processes.process_path="/usr/bin/su" AND Processes.user!="root" AND Processes.user!="" AND (Processes.parent_process_path="/tmp/*" OR Processes.parent_process_path="/dev/shm/*" OR Processes.parent_process_path="/var/tmp/*" OR Processes.parent_process_path="/home/*") AND Processes.parent_process_name!="bash" AND Processes.parent_process_name!="sh" AND Processes.parent_process_name!="zsh" AND Processes.parent_process_name!="dash" AND Processes.parent_process_name!="fish" AND Processes.parent_process_name!="ksh" by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process_path Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LinuxHosts = DeviceInfo
| where Timestamp > ago(1d)
| where OSPlatform =~ "Linux"
| distinct DeviceId;
let ShellNames = dynamic(["bash","sh","zsh","dash","fish","ksh","ash","tcsh","csh"]);
let SuspectParents = dynamic(["/tmp/","/dev/shm/","/var/tmp/","/home/"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId in (LinuxHosts)
| where FolderPath =~ "/usr/bin/su" or (FileName =~ "su" and FolderPath endswith "/bin/su")
| where InitiatingProcessAccountName !in ("root","","systemd","systemd-network")
| where InitiatingProcessFolderPath has_any (SuspectParents)
| where InitiatingProcessFileName !in~ (ShellNames)
| where InitiatingProcessFileName !in~ ("sudo","login","sshd","systemd","cron","crond","at","atd","runuser","machinectl","docker","podman","containerd-shim","runc")
| project Timestamp, DeviceName, DeviceId,
          ExploitingUser = InitiatingProcessAccountName,
          ParentBinary = InitiatingProcessFolderPath,
          ParentName = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ParentSHA256 = InitiatingProcessSHA256,
          SuCmd = ProcessCommandLine,
          SuAccount = AccountName
| order by Timestamp desc
```

### [LLM] Fragnesia/Dirty Frag attack-surface activation: esp4, esp6, or rxrpc kernel module loaded from non-init context

`UC_70_8` · phase: **weapon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents values(Processes.user) as users from datamodel=Endpoint.Processes where Processes.os="Linux" AND (Processes.process_name="modprobe" OR Processes.process_name="insmod" OR Processes.process_name="kmod") AND (Processes.process="*esp4*" OR Processes.process="*esp6*" OR Processes.process="*rxrpc*") AND Processes.parent_process_name!="systemd" AND Processes.parent_process_name!="udevd" AND Processes.parent_process_name!="systemd-udevd" AND Processes.parent_process_name!="NetworkManager" AND Processes.parent_process_name!="ipsec" AND Processes.parent_process_name!="charon" AND Processes.parent_process_name!="pluto" AND Processes.parent_process_name!="swanctl" by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.parent_process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LinuxHosts = DeviceInfo
| where Timestamp > ago(1d)
| where OSPlatform =~ "Linux"
| distinct DeviceId;
let IPsecParents = dynamic(["systemd","systemd-udevd","udevd","NetworkManager","ipsec","charon","pluto","swanctl","strongswan","libreswan","wg-quick","openafs","cron","crond"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId in (LinuxHosts)
| where FileName in~ ("modprobe","insmod","kmod")
| where ProcessCommandLine has_any ("esp4","esp6","rxrpc")
| where InitiatingProcessFileName !in~ (IPsecParents)
| where InitiatingProcessParentFileName !in~ (IPsecParents)
| extend ModuleLoaded = case(
    ProcessCommandLine has "esp4", "esp4",
    ProcessCommandLine has "esp6", "esp6",
    ProcessCommandLine has "rxrpc", "rxrpc",
    "unknown")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          LoaderTool = FileName,
          LoaderCmd = ProcessCommandLine,
          ParentName = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ParentPath = InitiatingProcessFolderPath,
          Grandparent = InitiatingProcessParentFileName,
          ModuleLoaded
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

### Article-specific behavioural hunt — New Fragnesia Linux Kernel LPE Grants Root Access via Page Cache Corruption

`UC_70_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New Fragnesia Linux Kernel LPE Grants Root Access via Page Cache Corruption ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/su*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New Fragnesia Linux Kernel LPE Grants Root Access via Page Cache Corruption
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/su"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-46300`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 9 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
