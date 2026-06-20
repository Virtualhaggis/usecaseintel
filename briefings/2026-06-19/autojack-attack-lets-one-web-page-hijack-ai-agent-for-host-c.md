# [CRIT] AutoJack Attack Lets One Web Page Hijack AI Agent for Host Code Execution

**Source:** The Hacker News
**Published:** 2026-06-19
**Article:** https://thehackernews.com/2026/06/autojack-attack-lets-one-web-page.html

## Threat Profile

AutoJack Attack Lets One Web Page Hijack AI Agent for Host Code Execution 
 Swati Khandelwal  Jun 19, 2026 Vulnerability / Software Supply Chain 
Microsoft researchers have detailed an exploit chain, named  AutoJack , that turns an AI browsing agent into a delivery vehicle for remote code execution.
Steer the agent to load an attacker's web page, and that page's JavaScript can reach a privileged local service on the same machine and spawn a process on the host.
No credentials, no sign-in scree…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-26030`
- **CVE:** `CVE-2026-25592`
- **Domain (defanged):** `evil.com`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1203** — Exploitation for Client Execution
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1053.005** — Scheduled Task/Job: Scheduled Task

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AutoGen Studio Python process spawns shell or calc.exe (AutoJack MCP RCE outcome)

`UC_13_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmdline values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python.exe","pythonw.exe","python3.exe","python3.11.exe","python3.12.exe") Processes.parent_process="*autogenstudio*" Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","calc.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","bash.exe","sh.exe","wsl.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","python3.exe","python3.11.exe","python3.12.exe","py.exe")
| where InitiatingProcessCommandLine has "autogenstudio"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","calc.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","bash.exe","sh.exe","wsl.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256, InitiatingProcessId, ProcessId
| order by Timestamp desc
```

### Vulnerable AutoGen Studio pre-release installed via pip (autogenstudio 0.4.3.dev1/dev2)

`UC_13_8` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip.exe","pip3.exe","python.exe","pythonw.exe","python3.exe") Processes.process="*autogenstudio*" (Processes.process="*0.4.3.dev1*" OR Processes.process="*0.4.3.dev2*" OR Processes.process="*--pre*" OR Processes.process="*==0.4.3.dev*")) by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let PipInstalls = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where (FileName in~ ("pip.exe","pip3.exe") or ProcessCommandLine has_any ("pip install","-m pip install"))
    | where ProcessCommandLine has "autogenstudio"
    | where ProcessCommandLine has_any ("0.4.3.dev1","0.4.3.dev2","==0.4.3.dev","--pre");
let PackageDrops = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has @"\site-packages\autogenstudio"
    | where FileName in~ ("version.py","_version.py","__init__.py","METADATA","PKG-INFO")
    | where InitiatingProcessFileName in~ ("pip.exe","pip3.exe","python.exe","pythonw.exe","python3.exe");
PipInstalls
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, Source="pip-cmdline"
| union (PackageDrops | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, ProcessCommandLine=InitiatingProcessCommandLine, Source="site-packages-write")
| order by Timestamp desc
```

### Persistence written by AutoGen Studio Python process (Run keys / scheduled tasks)

`UC_13_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as registry_value_data values(Registry.registry_value_name) as registry_value_name values(Registry.process_path) as process_path from datamodel=Endpoint.Registry where Registry.registry_path IN ("*\\CurrentVersion\\Run\\*","*\\CurrentVersion\\RunOnce\\*","*\\CurrentVersion\\Explorer\\Shell Folders\\Startup","*\\Image File Execution Options\\*\\Debugger") Registry.process_name IN ("python.exe","pythonw.exe","python3.exe") Registry.process="*autogenstudio*" by Registry.dest Registry.user Registry.registry_path Registry.process_name | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let RegistryPersistence = DeviceRegistryEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","python3.exe","python3.11.exe","python3.12.exe")
    | where InitiatingProcessCommandLine has "autogenstudio"
    | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
    | where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"\Explorer\Shell Folders\Startup", @"\Image File Execution Options")
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              RegistryKey, RegistryValueName, RegistryValueData,
              InitiatingProcessCommandLine, Persistence="registry";
let TaskCreates = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","python3.exe","python3.11.exe","python3.12.exe")
    | where InitiatingProcessCommandLine has "autogenstudio"
    | where FileName in~ ("schtasks.exe","at.exe") or ProcessCommandLine has_any ("schtasks /create","Register-ScheduledTask","New-ScheduledTask")
    | project Timestamp, DeviceName, AccountName,
              RegistryKey="", RegistryValueName="", RegistryValueData=ProcessCommandLine,
              InitiatingProcessCommandLine, Persistence="scheduled-task";
RegistryPersistence
| union TaskCreates
| order by Timestamp desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-26030`, `CVE-2026-25592`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `evil.com`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 10 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
