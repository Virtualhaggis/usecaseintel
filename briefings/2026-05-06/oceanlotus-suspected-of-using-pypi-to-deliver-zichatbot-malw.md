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

- **MD5:** `48be833b0b0ca1ad3cf99c66dc89c3f4`
- **MD5:** `5152410aeef667ffaf42d40746af4d84`
- **MD5:** `0a5a06fa2e74a57fd5ed8e85f04a483a`
- **MD5:** `e4a0ad38fd18a0e11199d1c52751908b`
- **MD5:** `5598baa59c716590d8841c6312d8349e`
- **MD5:** `968782b4feb4236858e3253f77ecf4b0`
- **MD5:** `b55b6e364be44f27e3fecdce5ad69eca`
- **MD5:** `02f4701559fc40067e69bb426776a54f`
- **MD5:** `e200f2f6a2120286f9056743bc94a49d`
- **MD5:** `22538214a3c917ff3b13a9e2035ca521`
- **MD5:** `ba2f1868f2af9e191ebf47a5fab5cbab`
- **MD5:** `c33782c94c29dd268a42cbe03542bca5`
- **MD5:** `454b85dc32dc8023cd2be04e4501f16a`
- **MD5:** `fce65c540d8186d9506e2f84c38a57c4`
- **MD5:** `652f4da6c467838957de19eed40d39da`
- **MD5:** `1995682d600e329b7833003a01609252`
- **MD5:** `38b75af6cbdb60127decd59140d10640`
- **MD5:** `a26019b68ef060e593b8651262cbd0f6`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
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
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1132.001** — Data Encoding: Standard Encoding
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1027.013** — Encrypted/Encoded File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] OceanLotus ZiChatBot persistence: 'pkt-update' Run key → vcpacket\vcpktsvr.exe

`UC_57_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\Microsoft\\Windows\\CurrentVersion\\Run*" AND (Registry.registry_value_name="pkt-update" OR Registry.registry_value_data="*\\vcpacket\\vcpktsvr.exe*")) by Registry.dest Registry.user Registry.process_name Registry.registry_path Registry.registry_value_name Registry.registry_value_data | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName =~ "pkt-update"
   or RegistryValueData has @"\vcpacket\vcpktsvr.exe"
   or RegistryValueData has_all (@"\AppData\Local\vcpacket\", "vcpktsvr.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RegistryKey, RegistryValueName, RegistryValueData
```

### [LLM] ZiChatBot C2 to helper.zulipchat.com via Zulip REST API

`UC_57_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="helper.zulipchat.com" OR All_Traffic.dest_url="*helper.zulipchat.com*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_url All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="helper.zulipchat.com" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let lookback = 30d;
let zulip_c2 = dynamic(["helper.zulipchat.com"]);
let zulip_auth_b64 = "TW9yaWFuLWJvdEBoZWxwZXIuenVsaXBjaGF0LmNvbTpVOFJFWGxJNktmOHFYQjlyUXpPUEJpSUE0YnJKNThxRw==";
(
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where RemoteUrl in~ (zulip_c2)
       or InitiatingProcessFileName in~ ("vcpktsvr.exe")
       or InitiatingProcessFolderPath has @"\AppData\Local\vcpacket\"
    | project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl,
              InitiatingProcessFileName, InitiatingProcessFolderPath,
              InitiatingProcessCommandLine, InitiatingProcessSHA256
)
| union (
    DeviceEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tostring(parse_json(AdditionalFields).QueryName)
    | where Q in~ (zulip_c2)
       and InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","slack.exe","teams.exe")
    | project Timestamp, DeviceName, ActionType, Q, InitiatingProcessFileName,
              InitiatingProcessFolderPath, InitiatingProcessCommandLine
)
| order by Timestamp desc
```

### [LLM] Malicious PyPI wheel (colorinal/uuid32-utils/termncolor) drops terminate.dll loaded by python.exe

`UC_57_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","python3.exe","pythonw.exe","pip.exe","pip3.exe") AND (Processes.process_name="vcpktsvr.exe" OR Processes.process IN ("*\\colorinal*\\terminate.dll*","*\\uuid32_utils*\\terminate.dll*","*\\vcpacket\\vcpktsvr.exe*"))) OR (Processes.process_name="vcpktsvr.exe" AND Processes.parent_process_path="*\\AppData\\Local\\vcpacket\\*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("terminate.dll","terminate.so","libcef.dll","vcpktsvr.exe") AND (Filesystem.file_path IN ("*\\site-packages\\colorinal*","*\\site-packages\\uuid32_utils*","*\\AppData\\Local\\vcpacket\\*","/tmp/obsHub/*"))) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let known_md5 = dynamic([
    "c33782c94c29dd268a42cbe03542bca5","454b85dc32dc8023cd2be04e4501f16a",
    "1995682d600e329b7833003a01609252","38b75af6cbdb60127decd59140d10640",
    "a26019b68ef060e593b8651262cbd0f6","fce65c540d8186d9506e2f84c38a57c4",
    "652f4da6c467838957de19eed40d39da","48be833b0b0ca1ad3cf99c66dc89c3f4"]);
let wheel_paths = dynamic([@"\site-packages\colorinal",@"\site-packages\uuid32_utils",@"\colorinal-0.1.7-py3-none-",@"\uuid32_utils-1."]);
union isfuzzy=true
( DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","python3.exe","pip.exe")
    | where FileName =~ "terminate.dll"
       or FolderPath has_any (wheel_paths)
       or MD5 in (known_md5)
    | project Timestamp, DeviceName, InitiatingProcessFileName,
              InitiatingProcessCommandLine, FileName, FolderPath, MD5, SHA256 ),
( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("FileCreated","FileModified","FileRenamed")
    | where (FileName in~ ("terminate.dll","terminate.so","libcef.dll","vcpktsvr.exe")
             and (FolderPath has @"\site-packages\colorinal"
               or FolderPath has @"\site-packages\uuid32_utils"
               or FolderPath has @"\AppData\Local\vcpacket\"
               or FolderPath startswith "/tmp/obsHub/"))
         or MD5 in (known_md5)
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, MD5, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine ),
( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where (FileName =~ "vcpktsvr.exe" and FolderPath has @"\vcpacket\")
         or (InitiatingProcessFileName in~ ("python.exe","pythonw.exe","python3.exe","pip.exe")
             and (ProcessCommandLine has "terminate.dll" or ProcessCommandLine has "xterminalunicod"))
         or MD5 in (known_md5)
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath,
              ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, MD5, SHA256 )
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

`UC_57_7` · phase: **exploit** · confidence: **High**

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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `48be833b0b0ca1ad3cf99c66dc89c3f4`, `5152410aeef667ffaf42d40746af4d84`, `0a5a06fa2e74a57fd5ed8e85f04a483a`, `e4a0ad38fd18a0e11199d1c52751908b`, `5598baa59c716590d8841c6312d8349e`, `968782b4feb4236858e3253f77ecf4b0`, `b55b6e364be44f27e3fecdce5ad69eca`, `02f4701559fc40067e69bb426776a54f` _(+10 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
