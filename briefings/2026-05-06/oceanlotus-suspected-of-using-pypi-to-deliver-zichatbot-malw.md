# [CRIT] OceanLotus suspected of using PyPI to deliver ZiChatBot malware

**Source:** Securelist (Kaspersky)
**Published:** 2026-05-06
**Article:** https://securelist.com/oceanlotus-suspected-pypi-zichatbot-campaign/119603/

## Threat Profile

Table of Contents
Introduction 
Technical details 
Spreading 
Malicious wheel packages 
Initial infection 
Windows version 
Dropper for ZiChatBot 
Linux version 
ZiChatBot 
Infrastructure 
Victims 
Attribution 
Conclusions 
Indicators of compromise 
Authors
GReAT 
Introduction 
Through our daily threat hunting, we noticed that, beginning in July 2025, a series of malicious wheel packages were uploaded to PyPI (the Python Package Index). We shared this information with the public security communi…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `helper.zulipchat.com`
- **MD5:** `48be833b0b0ca1ad3cf99c66dc89c3f4`

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
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1543** — Create or Modify System Process
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1053.003** — Scheduled Task/Job: Cron
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1102.002** — Web Service: Bidirectional Communication
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Pip install of OceanLotus-attributed ZiChatBot PyPI wheels (uuid32-utils, colorinal, termncolor)

`UC_252_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name IN ("pip.exe","pip3.exe","python.exe","python3.exe","pip","python","python3") (Processes.process="*uuid32-utils*" OR Processes.process="*uuid32_utils*" OR Processes.process="*colorinal*" OR Processes.process="*termncolor*") Processes.process="*install*" by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("pip.exe","pip3.exe","python.exe","python3.exe","pip","python","python3")
| where ProcessCommandLine has "install"
| where ProcessCommandLine has_any ("uuid32-utils","uuid32_utils","colorinal","termncolor")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### [LLM] ZiChatBot runner vcpktsvr.exe executed from %LOCALAPPDATA%\vcpacket\

`UC_252_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name="vcpktsvr.exe" OR Processes.process_path="*\\AppData\\Local\\vcpacket\\*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "vcpktsvr.exe"
   or FolderPath has @"\AppData\Local\vcpacket\"
| where AccountName !endswith "$"
| extend SuspectedLibcef = iff(FolderPath has @"\vcpacket\", "yes (check libcef.dll side-load)", "no")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, MD5, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SuspectedLibcef
| order by Timestamp desc
```

### [LLM] ZiChatBot persistence Run-key write 'pkt-update' pointing to vcpacket\vcpktsvr.exe

`UC_252_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as data values(Registry.process_name) as writer from datamodel=Endpoint.Registry where Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*" (Registry.registry_value_name="pkt-update" OR Registry.registry_value_data="*\\vcpacket\\vcpktsvr.exe*") by Registry.dest Registry.user Registry.registry_value_name Registry.registry_value_data | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName =~ "pkt-update"
   or RegistryValueData has @"\vcpacket\vcpktsvr.exe"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] ZiChatBot Linux persistence /tmp/obsHub/obs-check-update via crontab

`UC_252_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process="*/tmp/obsHub/obs-check-update*" OR Processes.process="*chmod +x /tmp/obsHub*" OR (Processes.process_name="crontab" AND Processes.process="*obs-check-update*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(
  DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where ProcessCommandLine has "/tmp/obsHub/obs-check-update"
     or (FileName == "crontab" and ProcessCommandLine has "obs-check-update")
     or (ProcessCommandLine has "chmod" and ProcessCommandLine has "/tmp/obsHub")
  | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Source="Process"
),
(
  DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FolderPath has "/tmp/obsHub" or FileName == "obs-check-update"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Source="File"
)
| order by Timestamp desc
```

### [LLM] ZiChatBot Zulip C2 beacon to helper.zulipchat.com from non-browser process

`UC_252_13` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as port from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="helper.zulipchat.com" OR All_Traffic.dest="*.zulipchat.com") by All_Traffic.dest All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | where NOT match(process_name, "(?i)^(chrome|msedge|firefox|brave|opera|safari|iexplore|zulip|electron|slack)\.exe$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "zulipchat.com" or RemoteUrl =~ "helper.zulipchat.com"
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","safari.exe","iexplore.exe","zulip.exe","electron.exe","slack.exe","teams.exe")
| where InitiatingProcessFileName !endswith "\\msedgewebview2.exe"
| where InitiatingProcessAccountName !endswith "$"
| extend HighFidelity = iff(InitiatingProcessFileName =~ "vcpktsvr.exe" or InitiatingProcessFolderPath has @"\vcpacket\" or InitiatingProcessFolderPath has "/tmp/obsHub/" or InitiatingProcessFileName =~ "obs-check-update", "yes-known-ZiChatBot", "hunt")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, HighFidelity
| order by HighFidelity asc, Timestamp desc
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

### Article-specific behavioural hunt — OceanLotus suspected of using PyPI to deliver ZiChatBot malware

`UC_252_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — OceanLotus suspected of using PyPI to deliver ZiChatBot malware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("terminate.dll","__init__.py","unicode.py","libcef.dll","vcpktsvr.exe","policy.dllcppage.dll","backward.dll") OR Processes.process_path="*\AppData\Local\vcpacket\vcpktsvr.exe*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*\AppData\Local\vcpacket\vcpktsvr.exe*" OR Filesystem.file_path="*/tmp/obsHub/obs-check-update*" OR Filesystem.file_name IN ("terminate.dll","__init__.py","unicode.py","libcef.dll","vcpktsvr.exe","policy.dllcppage.dll","backward.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — OceanLotus suspected of using PyPI to deliver ZiChatBot malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("terminate.dll", "__init__.py", "unicode.py", "libcef.dll", "vcpktsvr.exe", "policy.dllcppage.dll", "backward.dll") or FolderPath has_any ("\AppData\Local\vcpacket\vcpktsvr.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("\AppData\Local\vcpacket\vcpktsvr.exe", "/tmp/obsHub/obs-check-update") or FileName in~ ("terminate.dll", "__init__.py", "unicode.py", "libcef.dll", "vcpktsvr.exe", "policy.dllcppage.dll", "backward.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `helper.zulipchat.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `48be833b0b0ca1ad3cf99c66dc89c3f4`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 14 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
