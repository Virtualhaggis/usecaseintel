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
- **T1548.003** — Sudo and Sudo Caching
- **T1611** — Escape to Host
- **T1574.006** — Dynamic Linker Hijacking

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Unprivileged user invokes ip xfrm / IPsec configuration (Fragnesia CVE-2026-46300 primitive)

`UC_158_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.os=linux Processes.process_name=ip Processes.process="*xfrm*" (Processes.user!=root AND Processes.user_id!=0) by Processes.dest Processes.user Processes.user_id Processes.process Processes.parent_process_name Processes.process_path | `drop_dm_object_name(Processes)` | where match(process, "(?i)\\b(state|policy)\\b") AND match(process, "(?i)esp(4|6)?") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceInfo has "Linux" or FolderPath startswith "/"
| where FileName == "ip" or InitiatingProcessCommandLine has "ip xfrm"
| where ProcessCommandLine has "xfrm"
| where ProcessCommandLine has_any ("state", "policy")
| where ProcessCommandLine matches regex @"(?i)\besp(4|6|-in-tcp)?\b|proto\s+esp"
| where AccountName !in~ ("root", "system", "network-manager", "systemd-network", "strongswan", "charon", "pluto")
| where isnotempty(AccountName)
| project Timestamp, DeviceName, AccountName, AccountSid, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath
| order by Timestamp desc
```

### [LLM] Root shell from /usr/bin/su without prior auth (Fragnesia page-cache corruption outcome)

`UC_158_7` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.os=linux Processes.process_path="/usr/bin/su" by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_id Processes.process | `drop_dm_object_name(Processes)` | join type=left dest user [ search index=linux_secure (sourcetype=linux_secure OR sourcetype=auth) ("pam_unix(su:session): session opened" OR "pam_unix(su:auth): authentication failure" OR "FAILED su") earliest=-5m latest=+5m | stats count as PamEvents by dest user ] | where isnull(PamEvents) OR PamEvents=0 | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let suExec =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FolderPath == "/usr/bin/su" or FileName == "su" and FolderPath startswith "/usr"
    | where AccountName !in~ ("root","system")
    | project SuTime = Timestamp, DeviceId, DeviceName, SuUser = AccountName, SuParent = InitiatingProcessFileName, SuParentCmd = InitiatingProcessCommandLine, ProcessId, ProcessCommandLine;
let rootSpawn =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName == "su" and InitiatingProcessFolderPath == "/usr/bin/su"
    | where AccountName =~ "root"
    | project RootTime = Timestamp, DeviceId, DeviceName, ChildImage = FileName, ChildCmd = ProcessCommandLine, InitiatingProcessId;
suExec
| join kind=inner rootSpawn on DeviceId
| where RootTime between (SuTime .. SuTime + 30s)
| join kind=leftanti (
    DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType has_any ("PamAuthentication","UserAccountModified") or AdditionalFields has "pam_unix(su:session): session opened"
  ) on DeviceId
| project SuTime, DeviceName, SuUser, SuParent, SuParentCmd, ChildImage, ChildCmd, DelaySec = datetime_diff('second', RootTime, SuTime)
| order by SuTime desc
```

### [LLM] Unprivileged user namespace creation followed by xfrm/esp activity (Fragnesia AppArmor bypass path)

`UC_158_8` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.os=linux (Processes.process_name=unshare OR Processes.process="*unshare*-U*" OR Processes.process="*clone(CLONE_NEWUSER*") (Processes.user!=root AND Processes.user_id!=0) by Processes.dest Processes.user Processes.parent_process_id Processes.process_id Processes.process | `drop_dm_object_name(Processes)` | join type=inner dest user [ | tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.os=linux Processes.process="*xfrm*" Processes.process="*esp*" by Processes.dest Processes.user Processes.parent_process_id _time | `drop_dm_object_name(Processes)` | rename _time as xfrm_time ] | where xfrm_time >= firstTime AND xfrm_time <= firstTime+60
```

**Defender KQL:**
```kql
let userns =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FolderPath startswith "/" 
    | where (FileName == "unshare" and ProcessCommandLine matches regex @"(?i)(^|\s)(-U|--user)(\s|$)")
         or ProcessCommandLine has "CLONE_NEWUSER"
    | where AccountName !in~ ("root","system")
    | project UnshareTime = Timestamp, DeviceId, DeviceName, AccountName, UnshareCmd = ProcessCommandLine, UnshareSid = ProcessId, UnshareParent = InitiatingProcessId;
let xfrm =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has "xfrm" and ProcessCommandLine matches regex @"(?i)\besp(4|6|-in-tcp)?\b|proto\s+esp"
    | project XfrmTime = Timestamp, DeviceId, AccountName, XfrmCmd = ProcessCommandLine, XfrmParent = InitiatingProcessId;
userns
| join kind=inner xfrm on DeviceId, AccountName
| where XfrmTime between (UnshareTime .. UnshareTime + 60s)
| project UnshareTime, XfrmTime, DelaySec = datetime_diff('second', XfrmTime, UnshareTime), DeviceName, AccountName, UnshareCmd, XfrmCmd
| order by UnshareTime desc
```

### [LLM] Unprivileged user drops .so payload in /tmp followed by dlopen/LD_PRELOAD (berz0k zero-day pattern)

`UC_158_9` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.os=linux Filesystem.file_path="/tmp/*" Filesystem.file_name="*.so*" (Filesystem.user!=root AND Filesystem.user_id!=0) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_id | `drop_dm_object_name(Filesystem)` | join type=inner dest user [ | tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.os=linux (Processes.process="*LD_PRELOAD=/tmp/*" OR Processes.process="*dlopen*/tmp/*.so*" OR Processes.process="*/tmp/*.so*") by Processes.dest Processes.user Processes.process Processes.parent_process_name _time | `drop_dm_object_name(Processes)` | rename _time as loadTime ] | where loadTime >= firstTime AND loadTime <= firstTime + 300
```

**Defender KQL:**
```kql
let soDrop =
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("FileCreated","FileModified")
    | where FolderPath startswith "/tmp"
    | where FileName matches regex @"(?i)\.so(\.[0-9]+)*$"
    | where InitiatingProcessAccountName !in~ ("root","system")
    | project DropTime = Timestamp, DeviceId, DeviceName, DroppedPath = strcat(FolderPath, "/", FileName), Dropper = InitiatingProcessFileName, DropperCmd = InitiatingProcessCommandLine, Uid = InitiatingProcessAccountName;
let soLoad =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine matches regex @"(?i)LD_PRELOAD\s*=\s*/tmp/[^\s]+\.so" 
         or ProcessCommandLine has "/tmp/" and ProcessCommandLine matches regex @"(?i)/tmp/[^\s]+\.so"
    | project LoadTime = Timestamp, DeviceId, LoaderCmd = ProcessCommandLine, LoaderAccount = AccountName, LoaderInitiator = InitiatingProcessCommandLine;
soDrop
| join kind=inner soLoad on DeviceId
| where LoadTime between (DropTime .. DropTime + 5m)
| project DropTime, LoadTime, DelaySec = datetime_diff('second', LoadTime, DropTime), DeviceName, Uid, DroppedPath, DropperCmd, LoaderCmd, LoaderAccount
| order by DropTime desc
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

`UC_158_5` · phase: **install** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
