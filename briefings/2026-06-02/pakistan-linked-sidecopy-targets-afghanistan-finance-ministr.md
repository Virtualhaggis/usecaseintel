# [CRIT] Pakistan-Linked SideCopy Targets Afghanistan Finance Ministry with Xeno RAT

**Source:** The Hacker News
**Published:** 2026-06-02
**Article:** https://thehackernews.com/2026/06/pakistan-linked-sidecopy-targets.html

## Threat Profile

Pakistan-Linked SideCopy Targets Afghanistan Finance Ministry with Xeno RAT 
 Ravie Lakshmanan  Jun 02, 2026 Cyber Espionage / Threat Intelligence 
Cybersecurity researchers have disclosed details of a spear-phishing campaign likely undertaken by the Pakistan-aligned SideCopy group targeting Afghanistan's Ministry of Finance with an open-source remote access trojan called Xeno RAT .
"The campaign opens with a spear phishing delivery - a ZIP archive containing a malicious LNK file bearing a car…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `185.235.137.106`
- **IPv4 (defanged):** `103.132.98.224`
- **IPv4 (defanged):** `103.132.98.226`
- **Domain (defanged):** `abimj.edu.af`
- **SHA256:** `194b912c242604d6f9a79369f22338c58a13ce0cc2ed280ce505075808bc2f14`
- **SHA256:** `3b4194bdfe40d94031a94b30397ffd8a4b09d0a4057668e897b8bdcd1703dd01`
- **SHA256:** `df9173a28c0b0b878c10a53d35cd7ce6f6ed66d207b6b7c4ff723721f1c027ab`
- **SHA256:** `a63e90ee57a1f213a8fe76ef1a6cff5ae9ed7ebceda258431533825e648c0c67`
- **SHA256:** `5833917bd137804f5a021d2cb37adfe5c4b7b67dbb06d59c3b9c5cf393835e45`
- **SHA256:** `99127c8c67d90e2776beeb85281f9c68399bf4567b07a6b638d68b760212e88d`
- **SHA256:** `8f2d979ef33b2900351c94c7335275a9342c75189e1a901998e90a539e944a1a`
- **SHA256:** `0019212f25eb04bbb33bb194879c095265db7855d6003bdd777cf0cbb90eb772`
- **SHA256:** `9ae3d785486022af82ea92e51b26e3f55c1bba88a7be2ad9790f4240e8499d14`
- **MD5:** `3563518ef8389c7c7ac2a80984a2c4cd`

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
- **T1053.005** — Scheduled Task
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1218.005** — System Binary Proxy Execution: Mshta
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1571** — Non-Standard Port
- **T1095** — Non-Application Layer Protocol
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SideCopy LNK-via-ZIP spawning mshta.exe with remote HTA URL

`UC_37_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name=mshta.exe (Processes.parent_process_name=explorer.exe OR Processes.parent_process_name="WinRAR.exe" OR Processes.parent_process_name="7zG.exe" OR Processes.parent_process_name="7zFM.exe") (Processes.process="*http://*" OR Processes.process="*https://*" OR Processes.process="*.hta*") by host Processes.user Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "mshta.exe"
| where InitiatingProcessFileName in~ ("explorer.exe","winrar.exe","7zg.exe","7zfm.exe","winzip64.exe","winzip32.exe")
| where ProcessCommandLine has_any ("http://","https://",".hta")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] Xeno RAT staging — mshta/wscript fetching HTA from abimj.edu.af

`UC_37_11` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="abimj.edu.af" OR All_Traffic.dest="*.abimj.edu.af" OR All_Traffic.url="*abimj.edu.af*") by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process="*abimj.edu.af*") by host Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let staging_domain = "abimj.edu.af";
let proc = DeviceProcessEvents
    | where Timestamp > ago(60d)
    | where ProcessCommandLine has staging_domain or InitiatingProcessCommandLine has staging_domain
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Source="Process";
let net = DeviceNetworkEvents
    | where Timestamp > ago(60d)
    | where RemoteUrl has staging_domain
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName=InitiatingProcessFileName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine=tostring(RemoteUrl), Source="Network";
proc
| union net
| order by Timestamp desc
```

### [LLM] Xeno RAT Registry Run-key persistence impersonating Microsoft Edge

`UC_37_12` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as value_data values(Registry.process_name) as proc from datamodel=Endpoint.Registry where Registry.registry_path="*\\CurrentVersion\\Run*" (Registry.registry_value_name="*Edge*" OR Registry.registry_value_name="*msedge*" OR Registry.registry_value_name="*EdgeUpdate*") (Registry.registry_value_data="*\\AppData\\*" OR Registry.registry_value_data="*\\ProgramData\\*" OR Registry.registry_value_data="*\\Public\\*" OR Registry.registry_value_data="*\\Temp\\*" OR Registry.registry_value_data="*\\Users\\Public\\*") by host Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(60d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\CurrentVersion\Run"
| where RegistryValueName has_any ("Edge","msedge","MicrosoftEdge","EdgeUpdate")
| where RegistryValueData has_any (@"\AppData\", @"\ProgramData\", @"\Users\Public\", @"\Temp\", ".hta", "mshta", "rundll32", "regsvr32", "wscript", "cscript")
| where RegistryValueData !has @"\Program Files\Microsoft\Edge\"
     and RegistryValueData !has @"\Program Files (x86)\Microsoft\Edge\"
     and RegistryValueData !has @"\Microsoft\EdgeUpdate\"
| where InitiatingProcessFileName !in~ ("msedge.exe","msedgewebview2.exe","setup.exe","msiexec.exe","microsoftedgeupdate.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] SideCopy Xeno RAT C2 egress to 185.235.137.106 / 103.132.98.224 / 103.132.98.226

`UC_37_13` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.bytes_in) as bytes_in values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("185.235.137.106","103.132.98.224","103.132.98.226") by All_Traffic.src All_Traffic.src_ip All_Traffic.user All_Traffic.process_name All_Traffic.dest_ip | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteIP in ("185.235.137.106","103.132.98.224","103.132.98.226")
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, LocalIP, RemoteIP, RemotePort, Protocol, InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] Known Xeno RAT 1.8.7 (Operation XENOFISCAL) hash execution or drop

`UC_37_14` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_hash IN ("194b912c242604d6f9a79369f22338c58a13ce0cc2ed280ce505075808bc2f14","3b4194bdfe40d94031a94b30397ffd8a4b09d0a4057668e897b8bdcd1703dd01","df9173a28c0b0b878c10a53d35cd7ce6f6ed66d207b6b7c4ff723721f1c027ab","a63e90ee57a1f213a8fe76ef1a6cff5ae9ed7ebceda258431533825e648c0c67","5833917bd137804f5a021d2cb37adfe5c4b7b67dbb06d59c3b9c5cf393835e45","99127c8c67d90e2776beeb85281f9c68399bf4567b07a6b638d68b760212e88d","8f2d979ef33b2900351c94c7335275a9342c75189e1a901998e90a539e944a1a","0019212f25eb04bbb33bb194879c095265db7855d6003bdd777cf0cbb90eb772") OR Processes.process_hash="3563518ef8389c7c7ac2a80984a2c4cd") by host Processes.user Processes.process_name Processes.process_hash Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let sha256s = dynamic(["194b912c242604d6f9a79369f22338c58a13ce0cc2ed280ce505075808bc2f14","3b4194bdfe40d94031a94b30397ffd8a4b09d0a4057668e897b8bdcd1703dd01","df9173a28c0b0b878c10a53d35cd7ce6f6ed66d207b6b7c4ff723721f1c027ab","a63e90ee57a1f213a8fe76ef1a6cff5ae9ed7ebceda258431533825e648c0c67","5833917bd137804f5a021d2cb37adfe5c4b7b67dbb06d59c3b9c5cf393835e45","99127c8c67d90e2776beeb85281f9c68399bf4567b07a6b638d68b760212e88d","8f2d979ef33b2900351c94c7335275a9342c75189e1a901998e90a539e944a1a","0019212f25eb04bbb33bb194879c095265db7855d6003bdd777cf0cbb90eb772"]);
let md5s = dynamic(["3563518ef8389c7c7ac2a80984a2c4cd"]);
union isfuzzy=true
  (DeviceProcessEvents
     | where Timestamp > ago(90d)
     | where SHA256 in (sha256s) or MD5 in (md5s) or InitiatingProcessSHA256 in (sha256s) or InitiatingProcessMD5 in (md5s)
     | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, MD5, ProcessCommandLine, InitiatingProcessFileName, Source="Process"),
  (DeviceFileEvents
     | where Timestamp > ago(90d)
     | where SHA256 in (sha256s) or MD5 in (md5s)
     | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, MD5, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, Source="FileWrite"),
  (DeviceImageLoadEvents
     | where Timestamp > ago(90d)
     | where SHA256 in (sha256s) or MD5 in (md5s)
     | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, MD5, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, Source="ImageLoad")
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

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `185.235.137.106`, `103.132.98.224`, `103.132.98.226`, `abimj.edu.af`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `194b912c242604d6f9a79369f22338c58a13ce0cc2ed280ce505075808bc2f14`, `3b4194bdfe40d94031a94b30397ffd8a4b09d0a4057668e897b8bdcd1703dd01`, `df9173a28c0b0b878c10a53d35cd7ce6f6ed66d207b6b7c4ff723721f1c027ab`, `a63e90ee57a1f213a8fe76ef1a6cff5ae9ed7ebceda258431533825e648c0c67`, `5833917bd137804f5a021d2cb37adfe5c4b7b67dbb06d59c3b9c5cf393835e45`, `99127c8c67d90e2776beeb85281f9c68399bf4567b07a6b638d68b760212e88d`, `8f2d979ef33b2900351c94c7335275a9342c75189e1a901998e90a539e944a1a`, `0019212f25eb04bbb33bb194879c095265db7855d6003bdd777cf0cbb90eb772` _(+2 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 15 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
