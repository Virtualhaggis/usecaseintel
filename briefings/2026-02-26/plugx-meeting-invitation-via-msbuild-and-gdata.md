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
- **T1127.001** — Trusted Developer Utilities Proxy Execution: MSBuild
- **T1566.002** — Phishing: Spearphishing Link
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1573.001** — Encrypted Channel: Symmetric Cryptography

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Renamed MSBuild auto-loading sibling .csproj from user-writable path

`UC_389_8` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where (Processes.original_file_name="MSBuild.exe" AND Processes.process_name!="MSBuild.exe" AND Processes.process_name!="msbuild.exe") OR (Processes.process_name="MSBuild.exe" AND (Processes.process_path="*\\Users\\*\\Downloads\\*" OR Processes.process_path="*\\AppData\\Local\\Temp\\*" OR Processes.process_path="*\\Users\\Public\\*" OR Processes.process_path="*\\Desktop\\*") AND Processes.process="*.csproj*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_path Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// PlugX/STATICPLUGIN — renamed MSBuild or MSBuild auto-loading a sibling .csproj from a user-writable path
let _user_writable = dynamic([@"\Users\Public\", @"\AppData\Local\Temp\", @"\Downloads\", @"\Desktop\", @"\AppData\Roaming\"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
// (a) MSBuild renamed to anything else (the Invitation_Letter_*.exe trick)
| where (ProcessVersionInfoOriginalFileName =~ "MSBuild.exe" and FileName !~ "MSBuild.exe")
     // (b) Real MSBuild but launched from a user-writable path with a .csproj sibling on the cmdline / cwd
     or (FileName =~ "MSBuild.exe"
         and (FolderPath has_any (_user_writable)
              or InitiatingProcessFolderPath has_any (_user_writable)
              or ProcessCommandLine matches regex @"(?i)[a-z]:\\.*\\(downloads|temp|public|desktop|appdata)\\.*\.csproj"))
| project Timestamp, DeviceName, AccountName,
          FileName, OriginalName = ProcessVersionInfoOriginalFileName,
          FolderPath, ProcessCommandLine, SHA256,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
          ParentPath = InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] G DATA Avk.exe sideload from C:\Users\Public\GDatas with numeric-arg persistence

`UC_389_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.process_hash) as sha256 from datamodel=Endpoint.Processes where Processes.process_name="Avk.exe" AND Processes.process_path!="*\\Program Files*\\G Data*" AND (Processes.process_path="*\\Users\\Public\\GDatas\\*" OR Processes.process_path="*\\Users\\Public\\*" OR match(Processes.process,"(?i)Avk\.exe\"?\s+\d{2,4}\s+\d{2,4}")) by Processes.dest Processes.user Processes.process Processes.process_path Processes.parent_process_name | `drop_dm_object_name(Processes)` | join type=outer dest [| tstats `summariesonly` count values(Registry.registry_value_name) as registry_value_name values(Registry.registry_value_data) as registry_value_data from datamodel=Endpoint.Registry where Registry.registry_path="*\\CurrentVersion\\Run*" AND (Registry.registry_value_name="G DATA" OR Registry.registry_value_data="*\\Users\\Public\\GDatas\\Avk.exe*") by Registry.dest | `drop_dm_object_name(Registry)` | rename count as registry_count] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// PlugX — G DATA Avk.exe side-load from C:\Users\Public\GDatas with numeric-arg persistence
let _bad_hashes = dynamic([
    "8421e7995778faf1f2a902fb2c51d85ae39481f443b7b3186068d5c33c472d99", // legitimate AVK.exe used by attacker
    "46314092c8d00ab93cbbdc824b9fc39dec9303169163b9625bae3b1717d70ebc", // Avk.dll Korplug
    "e7ed0cd4115f3ff35c38d36cc50c6a13eba2d845554439a36108789cd1e05b17"  // AVKTray.dat
]);
let _proc =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "avk.exe"
    | where FolderPath !startswith @"C:\Program Files"
    | where FolderPath has @"\Users\Public\"
          or ProcessCommandLine matches regex @"(?i)avk\.exe\"?\s+\d{2,4}\s+\d{2,4}"
          or SHA256 in (_bad_hashes)
    | project Timestamp, DeviceId, DeviceName, AccountName,
              FolderPath, ProcessCommandLine, SHA256,
              Parent = InitiatingProcessFileName, ParentPath = InitiatingProcessFolderPath;
let _reg =
    DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
    | where RegistryKey has @"\CurrentVersion\Run"
    | where RegistryValueName =~ "G DATA"
         or RegistryValueData has @"\Users\Public\GDatas"
    | project RegTime = Timestamp, DeviceId, RegistryKey, RegistryValueName, RegistryValueData,
              RegInitiatingProc = InitiatingProcessFileName;
let _imgload =
    DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName =~ "avk.exe"
    | where FileName =~ "avk.dll"
    | where FolderPath !startswith @"C:\Program Files"
    | project LoadTime = Timestamp, DeviceId, LoadedDll = FolderPath, DllSHA256 = SHA256;
_proc
| join kind=leftouter _reg on DeviceId
| join kind=leftouter _imgload on DeviceId
| order by Timestamp desc
```

### [LLM] PlugX STATICPLUGIN C2 / staging-domain contact (decoraat[.]net, gesecole[.]net)

`UC_389_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_host IN ("decoraat.net","decoorat.net","onedown.gesecole.net","onedow.gesecole.net","gesecole.net") OR All_Traffic.url IN ("*decoraat.net*","*decoorat.net*","*gesecole.net*") by All_Traffic.dest_host All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("e7ed0cd4115f3ff35c38d36cc50c6a13eba2d845554439a36108789cd1e05b17","46314092c8d00ab93cbbdc824b9fc39dec9303169163b9625bae3b1717d70ebc","8421e7995778faf1f2a902fb2c51d85ae39481f443b7b3186068d5c33c472d99","5f9af68db10b029453264cfc9b8eee4265549a2855bb79668ccfc571fb11f5fc","de8ddc2451fb1305d76ab20661725d11c77625aeeaa1447faf3fbf56706c87f1","29cd44aa2a51a200d82cca578d97dc13241bc906ea6a33b132c6ca567dc8f3ad","d293ded5a63679b81556d2c622c78be6253f500b6751d4eeb271e6500a23b21e","6df8649bf4e233ee86a896ee8e5a3b3179c168ef927ac9283b945186f8629ee7") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// PlugX STATICPLUGIN — C2 / staging domain contact + on-disk hash sweep
let _domains = dynamic(["decoraat.net","decoorat.net","onedown.gesecole.net","onedow.gesecole.net","gesecole.net"]);
let _hashes = dynamic([
    "e7ed0cd4115f3ff35c38d36cc50c6a13eba2d845554439a36108789cd1e05b17",  // AVKTray.dat
    "46314092c8d00ab93cbbdc824b9fc39dec9303169163b9625bae3b1717d70ebc",  // Avk.dll (Korplug)
    "8421e7995778faf1f2a902fb2c51d85ae39481f443b7b3186068d5c33c472d99",  // AVK.exe
    "5f9af68db10b029453264cfc9b8eee4265549a2855bb79668ccfc571fb11f5fc",  // Invitation_Letter_No.02_2026.exe (renamed MSBuild)
    "de8ddc2451fb1305d76ab20661725d11c77625aeeaa1447faf3fbf56706c87f1",  // .csproj
    "29cd44aa2a51a200d82cca578d97dc13241bc906ea6a33b132c6ca567dc8f3ad",  // .zip
    "d293ded5a63679b81556d2c622c78be6253f500b6751d4eeb271e6500a23b21e",  // AVKTray.dat decrypted
    "6df8649bf4e233ee86a896ee8e5a3b3179c168ef927ac9283b945186f8629ee7"   // PDF decoy
]);
union isfuzzy=true
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (_domains)
         or tostring(parse_url(RemoteUrl)["Host"]) in~ (_domains)
    | project Timestamp, Source = "NetworkEvents", DeviceName, AccountName = InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              RemoteIP, RemotePort, RemoteUrl, ProtocolField = Protocol ),
  ( DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tostring(parse_json(AdditionalFields).QueryName)
    | where Q in~ (_domains) or Q endswith ".gesecole.net"
    | project Timestamp, Source = "DnsQuery", DeviceName, AccountName = InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              RemoteIP = "", RemotePort = int(null), RemoteUrl = Q, ProtocolField = "DNS" ),
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (_hashes)
    | project Timestamp, Source = "FileEvents", DeviceName, AccountName = InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              RemoteIP = "", RemotePort = int(null), RemoteUrl = strcat(FolderPath, FileName),
              ProtocolField = SHA256 )
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

### Article-specific behavioural hunt — PlugX Meeting Invitation via MSBuild and GDATA

`UC_389_7` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
