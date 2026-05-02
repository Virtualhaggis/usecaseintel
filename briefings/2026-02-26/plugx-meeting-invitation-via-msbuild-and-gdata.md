# [CRIT] PlugX Meeting Invitation via MSBuild and GDATA

**Source:** Lab52
**Published:** 2026-02-26
**Article:** https://lab52.io/blog/plugx-meeting-invitation-via-msbuild-and-gdata/

## Threat Profile

In relation to the latest variant of the PlugX RAT executed by STATICPLUGIN analyzed by IIJ-SECT , LAB52 aims to complement this information with additional observed deployment activity and encryption characteristics in samples analyzed by this team.
PlugX 
PlugX is a long-running Remote Access Trojan (RAT) that has been consistently linked to multiple China-aligned threat actors and espionage operations worldwide. Since its public identification around 2008, it has been attributed to groups suc…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `onedown.gesecole.net`
- **Domain (defanged):** `decoraat.net`
- **Domain (defanged):** `decoorat.net`
- **Domain (defanged):** `onedow.gesecole.net`
- **SHA256:** `e7ed0cd4115f3ff35c38d36cc50c6a13eba2d845554439a36108789cd1e05b17`
- **SHA256:** `46314092c8d00ab93cbbdc824b9fc39dec9303169163b9625bae3b1717d70ebc`
- **SHA256:** `8421e7995778faf1f2a902fb2c51d85ae39481f443b7b3186068d5c33c472d99`
- **SHA256:** `29cd44aa2a51a200d82cca578d97dc13241bc906ea6a33b132c6ca567dc8f3ad`
- **SHA256:** `de8ddc2451fb1305d76ab20661725d11c77625aeeaa1447faf3fbf56706c87f1`
- **SHA256:** `5f9af68db10b029453264cfc9b8eee4265549a2855bb79668ccfc571fb11f5fc`
- **SHA256:** `d293ded5a63679b81556d2c622c78be6253f500b6751d4eeb271e6500a23b21e`
- **SHA256:** `6df8649bf4e233ee86a896ee8e5a3b3179c168ef927ac9283b945186f8629ee7`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PlugX persistence: HKCU Run value 'G DATA' pointing to Public\GDatas\Avk.exe

`UC_189_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*" Registry.registry_value_name="G DATA" Registry.registry_value_data="*\\Users\\Public\\GDatas\\Avk.exe*" by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName =~ "G DATA"
| where RegistryValueData has_cs @"\Users\Public\GDatas\Avk.exe"
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
```

### [LLM] G DATA Avk.exe side-loaded from %Public%\GDatas with two numeric runtime arguments

`UC_189_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.process_hash) as process_hash from datamodel=Endpoint.Processes where (Processes.process_name=Avk.exe OR Processes.original_file_name=Avk.exe) Processes.process_path="*\\Users\\Public\\GDatas\\*" by Processes.dest Processes.user Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)` | rex field=process "Avk\.exe\"?\s+(?<arg1>\d{1,5})\s+(?<arg2>\d{1,5})" | where isnotnull(arg1) AND isnotnull(arg2) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where FileName =~ "Avk.exe" or ProcessVersionInfoOriginalFileName =~ "Avk.exe"
| where FolderPath has_cs @"\Users\Public\GDatas\"
| where ProcessCommandLine matches regex @"(?i)Avk\.exe\"?\s+\d{1,5}\s+\d{1,5}\s*$"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, SHA256
| join kind=leftouter (
    DeviceImageLoadEvents
    | where FileName =~ "Avk.dll"
    | where FolderPath has_cs @"\Users\Public\GDatas\"
    | project Timestamp, DeviceName, DllSHA256=SHA256, DllFolderPath=FolderPath
) on DeviceName
```

### [LLM] PlugX Meeting-Invitation C2 beacons to decoraat[.]net / decoorat[.]net / gesecole[.]net

`UC_189_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where DNS.query IN ("decoraat.net","decoorat.net","*.decoraat.net","*.decoorat.net","gesecole.net","*.gesecole.net","onedown.gesecole.net","onedow.gesecole.net") by DNS.query DNS.src | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=true count from datamodel=Web where Web.url="*decoraat.net*" OR Web.url="*decoorat.net*" OR Web.url="*gesecole.net*" OR Web.dest="decoraat.net" OR Web.dest="decoorat.net" by Web.src Web.dest Web.url Web.user_agent Web.app | `drop_dm_object_name(Web)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let plugx_domains = dynamic(["decoraat.net","decoorat.net","gesecole.net","onedown.gesecole.net","onedow.gesecole.net"]);
DeviceNetworkEvents
| where ActionType in ("ConnectionSuccess","DnsConnectionInspected","HttpConnectionInspected","ConnectionAttempt")
| where RemoteUrl has_any (plugx_domains) or tostring(parse_json(AdditionalFields).query) has_any (plugx_domains)
| extend SuspiciousInitiator = iff(InitiatingProcessFileName in~ ("Avk.exe","MSBuild.exe") or InitiatingProcessFolderPath has @"\Users\Public\GDatas\", 1, 0)
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, SuspiciousInitiator
| union (
    DeviceEvents
    | where ActionType == "DnsQueryResponse"
    | extend q = tostring(parse_json(AdditionalFields).DnsQueryString)
    | where q has_any (plugx_domains)
    | project Timestamp, DeviceName, RemoteUrl=q, RemoteIP="", RemotePort=int(0), InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, SuspiciousInitiator=0
)
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — PlugX Meeting Invitation via MSBuild and GDATA

`UC_189_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — PlugX Meeting Invitation via MSBuild and GDATA ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("avk.exe","avk.dll","invitation_letter_no.02_2026.exe","msbuild.exe","kernel32.dll","ntdll.dll","kernelbase.dll","winhttp.dll","ws2_32.dll") OR Processes.process_path="*C:\Users\Public\GDatas\Avk.exe*" OR Processes.process_path="*C:\Users\Public\GDatas*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Users\Public\GDatas\Avk.exe*" OR Filesystem.file_path="*C:\Users\Public\GDatas*" OR Filesystem.file_name IN ("avk.exe","avk.dll","invitation_letter_no.02_2026.exe","msbuild.exe","kernel32.dll","ntdll.dll","kernelbase.dll","winhttp.dll","ws2_32.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — PlugX Meeting Invitation via MSBuild and GDATA
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("avk.exe", "avk.dll", "invitation_letter_no.02_2026.exe", "msbuild.exe", "kernel32.dll", "ntdll.dll", "kernelbase.dll", "winhttp.dll", "ws2_32.dll") or FolderPath has_any ("C:\Users\Public\GDatas\Avk.exe", "C:\Users\Public\GDatas"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Users\Public\GDatas\Avk.exe", "C:\Users\Public\GDatas") or FileName in~ ("avk.exe", "avk.dll", "invitation_letter_no.02_2026.exe", "msbuild.exe", "kernel32.dll", "ntdll.dll", "kernelbase.dll", "winhttp.dll", "ws2_32.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `onedown.gesecole.net`, `decoraat.net`, `decoorat.net`, `onedow.gesecole.net`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `e7ed0cd4115f3ff35c38d36cc50c6a13eba2d845554439a36108789cd1e05b17`, `46314092c8d00ab93cbbdc824b9fc39dec9303169163b9625bae3b1717d70ebc`, `8421e7995778faf1f2a902fb2c51d85ae39481f443b7b3186068d5c33c472d99`, `29cd44aa2a51a200d82cca578d97dc13241bc906ea6a33b132c6ca567dc8f3ad`, `de8ddc2451fb1305d76ab20661725d11c77625aeeaa1447faf3fbf56706c87f1`, `5f9af68db10b029453264cfc9b8eee4265549a2855bb79668ccfc571fb11f5fc`, `d293ded5a63679b81556d2c622c78be6253f500b6751d4eeb271e6500a23b21e`, `6df8649bf4e233ee86a896ee8e5a3b3179c168ef927ac9283b945186f8629ee7`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
