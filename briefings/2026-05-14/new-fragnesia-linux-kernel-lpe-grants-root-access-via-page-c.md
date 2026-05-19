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
- **T1548.003** — Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- **T1574.006** — Hijack Execution Flow: Dynamic Linker Hijacking
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1611** — Escape to Host
- **T1548** — Abuse Elevation Control Mechanism

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Fragnesia LPE: /usr/bin/su grants root session with no preceding PAM authentication

`UC_83_6` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent_proc from datamodel=Endpoint.Processes where Processes.process_name="su" AND (Processes.process_path="/usr/bin/su" OR Processes.process_path="/bin/su") AND Processes.user!="root" AND Processes.user!="" by Processes.dest Processes.user | `drop_dm_object_name(Processes)` | join type=left dest [ search index=os (sourcetype=linux_secure OR sourcetype=syslog) "pam_unix(su:auth)" earliest=-1d | rex field=_raw "by\s+(?<user>[a-z][a-z0-9_-]*)\(" | stats count as pam_auth_count by host user | rename host as dest ] | where isnull(pam_auth_count) OR pam_auth_count=0 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "su" and FolderPath in~ ("/usr/bin","/bin")
| where AccountName =~ "root"
| where InitiatingProcessAccountName !in~ ("root","")
| extend ElapsedMs = datetime_diff('millisecond', ProcessCreationTime, InitiatingProcessCreationTime)
| project Timestamp, DeviceName, Caller=InitiatingProcessAccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, ElapsedMs
| order by Timestamp desc
```

### [LLM] berz0k Linux LPE: .so payload dropped in /tmp followed by LD_PRELOAD execution

`UC_83_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t min(_time) as drop_time values(Filesystem.file_path) as so_path values(Filesystem.process_name) as dropper from datamodel=Endpoint.Filesystem where Filesystem.file_path="/tmp/*.so" AND Filesystem.action="created" AND Filesystem.user!="root" by Filesystem.dest Filesystem.user | `drop_dm_object_name(Filesystem)` | join type=inner dest user [ | tstats summariesonly=t min(_time) as exec_time values(Processes.process) as cmd values(Processes.process_name) as proc from datamodel=Endpoint.Processes where Processes.process="*LD_PRELOAD*/tmp/*" by Processes.dest Processes.user | `drop_dm_object_name(Processes)` ] | where exec_time >= drop_time AND exec_time - drop_time < 600 | eval delta_sec=exec_time-drop_time | table dest user so_path dropper cmd proc drop_time exec_time delta_sec
```

**Defender KQL:**
```kql
let LookbackDays = 1d;
let WindowMin = 10m;
let SoDrops = DeviceFileEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType in ("FileCreated","FileModified")
    | where FolderPath startswith "/tmp" and FileName endswith ".so"
    | where InitiatingProcessAccountName !in~ ("root","")
    | project SoDropTime = Timestamp, DeviceId, DeviceName, DroppedSo = strcat(FolderPath, "/", FileName), Dropper = InitiatingProcessFileName, Caller = InitiatingProcessAccountName;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where ProcessCommandLine has "LD_PRELOAD" and ProcessCommandLine has "/tmp/"
| where ProcessCommandLine matches regex @"LD_PRELOAD\s*=\s*[\"']?/tmp/[^ ;\"']+\.so"
| join kind=inner SoDrops on DeviceId
| where Timestamp between (SoDropTime .. SoDropTime + WindowMin)
| extend DelaySec = datetime_diff('second', Timestamp, SoDropTime)
| project Timestamp, DeviceName, AccountName, Caller, ProcessCommandLine, DroppedSo, Dropper, SoDropTime, DelaySec, InitiatingProcessFileName
| order by Timestamp desc
```

### [LLM] Unprivileged user namespace creation by non-root account (Fragnesia/Dirty Frag prerequisite)

`UC_83_8` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name="unshare" AND (Processes.process="*-U*" OR Processes.process="*--user*" OR Processes.process="*--map-root-user*" OR Processes.process="*-r *") AND Processes.user!="root" AND Processes.user!="" by Processes.dest Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | where parent_process_name!="podman" AND parent_process_name!="buildah" AND parent_process_name!="snap-confine" AND parent_process_name!="bwrap" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "unshare"
| where ProcessCommandLine matches regex @"(?i)(\s|^)(-U|--user|--map-root-user|-r(\s|$))"
| where InitiatingProcessAccountName !in~ ("root","")
| where InitiatingProcessFileName !in~ ("podman","buildah","snap-confine","bwrap","flatpak","crun","runc")
| project Timestamp, DeviceName, Caller=InitiatingProcessAccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
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

`UC_83_5` · phase: **install** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, 9 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
