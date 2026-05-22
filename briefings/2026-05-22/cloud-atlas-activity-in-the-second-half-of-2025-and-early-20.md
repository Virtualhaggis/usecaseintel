# [CRIT] Cloud Atlas activity in the second half of 2025 and early 2026: new tools and a new payload

**Source:** Securelist (Kaspersky)
**Published:** 2026-05-22
**Article:** https://securelist.com/cloud-atlas-2026/119895/

## Threat Profile

Table of Contents
Technical details 
Initial infection 
Fixed.ps1 (loader) 
Fixed.ps1::Payload (VBCloud dropper) 
Fixed.ps1::Payload (PowerShower) 
PowerShower::Payload (credential grabber) 
Multi-user RDP by patching termsrv.dll 
Reverse SSH tunneling 
Patched OpenSSH 
RevSocks 
Tor tunneling 
PowerCloud 
Browser checker 
Victims 
Conclusion 
Indicators of compromise 
Domains and IPs 
File paths 
Authors
Kaspersky 
In 2025, we observed pervasive SSH tunnel activity, which has remained active in…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2018-0802`
- **IPv4 (defanged):** `194.102.104.207`
- **IPv4 (defanged):** `46.17.45.56`
- **IPv4 (defanged):** `46.17.45.49`
- **IPv4 (defanged):** `46.17.44.125`
- **IPv4 (defanged):** `46.17.44.212`
- **IPv4 (defanged):** `185.22.154.73`
- **IPv4 (defanged):** `194.87.196.163`
- **IPv4 (defanged):** `195.58.49.9`
- **IPv4 (defanged):** `93.125.114.193`
- **IPv4 (defanged):** `93.125.114.57`
- **IPv4 (defanged):** `45.87.219.116`
- **IPv4 (defanged):** `37.228.129.224`
- **IPv4 (defanged):** `185.53.179.136`
- **IPv4 (defanged):** `185.126.239.77`
- **IPv4 (defanged):** `5.181.21.75`
- **IPv4 (defanged):** `146.70.53.171`
- **IPv4 (defanged):** `45.15.65.134`
- **IPv4 (defanged):** `185.250.181.207`
- **IPv4 (defanged):** `81.30.105.71`
- **Domain (defanged):** `tenkoff.org`
- **Domain (defanged):** `cloudguide.in`
- **Domain (defanged):** `goverru.com`
- **Domain (defanged):** `kufar.org`
- **Domain (defanged):** `ultimatecore.net`
- **Domain (defanged):** `spbnews.net`
- **Domain (defanged):** `onedrivesupport.net`
- **Domain (defanged):** `amerikastaj.com`
- **Domain (defanged):** `bigbang.me`
- **Domain (defanged):** `paleturquoise-dragonfly-364512.hostingersite.com`
- **Domain (defanged):** `wizzifi.com`
- **Domain (defanged):** `totallegacy.org`
- **Domain (defanged):** `mamurjor.com`
- **Domain (defanged):** `landscapeuganda.com`
- **Domain (defanged):** `lafortunaitalian.co.uk`
- **Domain (defanged):** `kommando.live`
- **Domain (defanged):** `internationalcommoditiesllc.com`
- **Domain (defanged):** `humanitas.si`
- **Domain (defanged):** `fishingflytackle.com`
- **Domain (defanged):** `firsai.tipshub.net`
- **Domain (defanged):** `alnakhlah.com.sa`
- **Domain (defanged):** `allgoodsdirect.com.au`
- **Domain (defanged):** `agenciakharis.com.br`
- **Domain (defanged):** `istochnik.org`
- **Domain (defanged):** `znews.net`
- **Domain (defanged):** `investika-club.com`
- **MD5:** `1A11B26DD0261EF27A112CE8B361C247`
- **MD5:** `5329F7BFF9D0D5DB28821B86C26D628F`
- **MD5:** `7A95360B7E0EB5B107A3D231ABBC541A`
- **MD5:** `C0D1EAA15A2CEFBAB9735787575C8D8E`
- **MD5:** `D5B38B252CF212A4A32763DE36732D40`
- **MD5:** `3C75CEDB1196DF5EAB91F31411ED4B33`
- **MD5:** `42AC350BFBC5B4EB0FEDBA16C81919C7`
- **MD5:** `493B901D1B33EB577DB64AADD948F9CE`
- **MD5:** `2CABB721681455DAE1B6A26709DEF453`
- **MD5:** `1B39E86EB772A0E40060B672B7F574F1`
- **MD5:** `1D401D6E6FC0B00AAA2C65A0AC0CFD6B`
- **MD5:** `40A562B8600F843B717BC5951B2E3C29`
- **MD5:** `F721A76DEB28FD0B80D27FCE6B8F5016`
- **MD5:** `D3C8AFD22BAA306FF659DB1FAC28574A`
- **MD5:** `6D7B2D1172BBDB7340972D844F6F0717`
- **MD5:** `9769F43B9DE8D19E803263267FA6D62E`
- **MD5:** `63B6BE9AE8D8024A40B200CCCB438F1D`
- **MD5:** `6AA586BCC45CA2E92A4F0EF47E086FA1`
- **MD5:** `EBA3BCDB19A7E256BF8E2CC5B9C1CCA9`
- **MD5:** `B4E183627B7399006C1BC47B3711E419`
- **MD5:** `F56B31A4B47AD3365B18A7E922FBA1A8`
- **MD5:** `F6F62456FB0FCC396FB654CBED339BC3`
- **MD5:** `25C8ED0511375DCA57EF136AC3FA0CCA`
- **MD5:** `2B4BA4FACF8C299749771A3A4369782E`
- **MD5:** `BA9CE06641067742F2AFC9691FAFF1DC`
- **MD5:** `FB0F8027ACF1B1E47E07A63D8812ED50`
- **MD5:** `BBF1FA694122E07635DEEAC11AD712F8`
- **MD5:** `F301AA3D62B5095EEC4D8E34201A4769`
- **MD5:** `F9C3BBE108566D1A6B070F9C5FB03160`
- **MD5:** `369B75BDCDED16469EDE7AB8BEDCFAE1`
- **MD5:** `9EAAE9491F6A50D6DF0BE393734A44CB`
- **MD5:** `3E6E9DF00A764B348EC611EE8504ACA0`
- **MD5:** `9BD788F285E32A05E6591D1EB36EBFFC`
- **MD5:** `F42085522EC2EBB16EDCF814E7C330AD`
- **MD5:** `2042EB5D52F0B535A1CE6B6F954C8C2B`
- **MD5:** `2AA1E9765EF6B00B94A9B6BE0041436A`
- **MD5:** `36120F5E9411BCBAC7104EF3FA964ED2`
- **MD5:** `5000A353399500BC78381DC95B6ED2DC`
- **MD5:** `579A9952D31CAD801A3988DBE7914CE7`
- **MD5:** `867B634588C0FD6B26684D502C15AB03`
- **MD5:** `38FA4306FA4406BA31CF171AF4D36E34`
- **MD5:** `83EDDE9F7EEEFAC0363413972F35572B`
- **MD5:** `CC751619BFEC0DC4607C17112B9E3B2C`
- **MD5:** `A632858F14B36F03D0F213F5F5D6BFF2`
- **MD5:** `097CA205AD9E3B72018750280904718C`
- **MD5:** `69121C36EB8BF77962DCA825FCFFD873`
- **MD5:** `C5702EB250F855C8C872FFFB9BB656ED`
- **MD5:** `ED34F5A136FBA4FDEA976570FAA33ED7`
- **MD5:** `0577DB70844E88B32B954906E2F20798`
- **MD5:** `28ECF8FB6719E14231B94B4D37629B0E`
- **MD5:** `0857C84B62289A1A9F29E19244E9A499`
- **MD5:** `0C514E137860F489E3801213460EF938`
- **MD5:** `50568B1F9335A7E3BA4E5DF035A8FB86`
- **MD5:** `7F776AD200287D6DE14A29158C457179`
- **MD5:** `51F7F794ED43FB90D0F8EBBB5EFFE628`
- **MD5:** `B8C753DD254509FBA5077FFD5067EAB0`
- **MD5:** `BC3739DEC8CD8F54F3F60A85F3ED600E`
- **MD5:** `EC076CD21C483A40156F4E40D08DADED`
- **MD5:** `216CB7F31D383C0DD892B284DF05A495`
- **MD5:** `116F59E70A9DF97F4ADAEA71EECB1E9A`
- **MD5:** `7242AC065B50BCDE9308756B49DBADCB`
- **MD5:** `8158552950D2E13B075001CE0C52AA97`
- **MD5:** `A75DBED984963B9AB21309C5B2F8FD9B`
- **MD5:** `0320DD389FDBAB25D46792BD2817675E`
- **MD5:** `5339D1A666F3E40FE756505CF1D87D4B`
- **MD5:** `67D7E3AEEB673BF60C59361C12A4ED81`
- **MD5:** `89572F0ED20791A5AC9FC4267D67CCB0`
- **MD5:** `B6AAE073E7BFEBF4D643C2BBEB5C02E1`
- **MD5:** `344CA9EA07CD4AC90EF27F8890D4EC05`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1053.005** — Scheduled Task
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1053.005** — Persistence (article-specific)
- **T1547.001** — Persistence (article-specific)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
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

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — Cloud Atlas activity in the second half of 2025 and early 2026: new tools and a

`UC_13_11` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Cloud Atlas activity in the second half of 2025 and early 2026: new tools and a ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("fixed.ps1","termsrv.dll","winrar.exe","video.vbs","googleearth.ps1","fodhelper.exe","rdp_new.ps1","gen.vbs","writetoschedulergeneratekey.vbs","run.vbs","writetoschedulerrunssh.vbs","kill.vbs","writetoschedulerkillssh.vbs","libcrypto.dll","syruntime.dll") OR Processes.process_path="*C:\Users\Public\Documents\*" OR Processes.process_path="*C:\Windows\ime*" OR Processes.process_path="*C:\Windows\System32\ime*" OR Processes.process_path="*C:\Windows\pla*" OR Processes.process_path="*C:\Windows\inf*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Users\Public\Documents\*" OR Filesystem.file_path="*C:\Windows\ime*" OR Filesystem.file_path="*C:\Windows\System32\ime*" OR Filesystem.file_path="*C:\Windows\pla*" OR Filesystem.file_path="*C:\Windows\inf*" OR Filesystem.file_path="*C:\Windows\migration*" OR Filesystem.file_path="*C:\Windows\System32\timecontrolsvc*" OR Filesystem.file_path="*C:\Windows\SKB*" OR Filesystem.file_name IN ("fixed.ps1","termsrv.dll","winrar.exe","video.vbs","googleearth.ps1","fodhelper.exe","rdp_new.ps1","gen.vbs","writetoschedulergeneratekey.vbs","run.vbs","writetoschedulerrunssh.vbs","kill.vbs","writetoschedulerkillssh.vbs","libcrypto.dll","syruntime.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Cloud Atlas activity in the second half of 2025 and early 2026: new tools and a
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("fixed.ps1", "termsrv.dll", "winrar.exe", "video.vbs", "googleearth.ps1", "fodhelper.exe", "rdp_new.ps1", "gen.vbs", "writetoschedulergeneratekey.vbs", "run.vbs", "writetoschedulerrunssh.vbs", "kill.vbs", "writetoschedulerkillssh.vbs", "libcrypto.dll", "syruntime.dll") or FolderPath has_any ("C:\Users\Public\Documents\", "C:\Windows\ime", "C:\Windows\System32\ime", "C:\Windows\pla", "C:\Windows\inf"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Users\Public\Documents\", "C:\Windows\ime", "C:\Windows\System32\ime", "C:\Windows\pla", "C:\Windows\inf", "C:\Windows\migration", "C:\Windows\System32\timecontrolsvc", "C:\Windows\SKB") or FileName in~ ("fixed.ps1", "termsrv.dll", "winrar.exe", "video.vbs", "googleearth.ps1", "fodhelper.exe", "rdp_new.ps1", "gen.vbs", "writetoschedulergeneratekey.vbs", "run.vbs", "writetoschedulerrunssh.vbs", "kill.vbs", "writetoschedulerkillssh.vbs", "libcrypto.dll", "syruntime.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `194.102.104.207`, `46.17.45.56`, `46.17.45.49`, `46.17.44.125`, `46.17.44.212`, `185.22.154.73`, `194.87.196.163`, `195.58.49.9` _(+37 more)_

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2018-0802`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `1A11B26DD0261EF27A112CE8B361C247`, `5329F7BFF9D0D5DB28821B86C26D628F`, `7A95360B7E0EB5B107A3D231ABBC541A`, `C0D1EAA15A2CEFBAB9735787575C8D8E`, `D5B38B252CF212A4A32763DE36732D40`, `3C75CEDB1196DF5EAB91F31411ED4B33`, `42AC350BFBC5B4EB0FEDBA16C81919C7`, `493B901D1B33EB577DB64AADD948F9CE` _(+61 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 12 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
