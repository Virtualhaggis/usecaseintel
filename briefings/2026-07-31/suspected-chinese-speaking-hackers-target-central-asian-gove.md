# [CRIT] Suspected Chinese-Speaking Hackers Target Central Asian Governments With OctLurk and SilkLurk

**Source:** The Hacker News
**Published:** 2026-07-31
**Article:** https://thehackernews.com/2026/08/suspected-chinese-speaking-hackers.html

## Threat Profile

Suspected Chinese-Speaking Hackers Target Central Asian Governments With OctLurk and SilkLurk 
 Ravie Lakshmanan  Jul 31, 2026 Malware / Threat Intelligence 
A Chinese-speaking threat actor is suspected to be behind a fresh wave of cyber attacks targeting government organizations mainly located in Central Asia, including Afghanistan, Kyrgyzstan, Tajikistan, Uzbekistan, Kazakhstan, and the Syrian Arab Republic, since January 2025.
These targeted organizations operate across several sectors, suc…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `154.196.162.76`
- **IPv4 (defanged):** `45.138.157.165`
- **IPv4 (defanged):** `95.179.210.138`
- **IPv4 (defanged):** `45.77.136.228`
- **IPv4 (defanged):** `95.179.141.26`
- **IPv4 (defanged):** `45.32.152.50`
- **IPv4 (defanged):** `212.11.39.138`
- **IPv4 (defanged):** `195.86.120.2`
- **IPv4 (defanged):** `154.196.187.73`
- **IPv4 (defanged):** `45.61.149.112`
- **IPv4 (defanged):** `64.7.198.130`
- **Domain (defanged):** `dns.ssentialserv.xyz`
- **Domain (defanged):** `dns.multitoconference.com`
- **Domain (defanged):** `tj.tajikistandip.com`
- **Domain (defanged):** `fm01.clouddevicemetrics.com`
- **Domain (defanged):** `confbase.mdpsupport.net`
- **Domain (defanged):** `digital.leroymerlin.com`
- **Domain (defanged):** `api2.annoyingremote.com`
- **Domain (defanged):** `about.blsouqs.com`
- **Domain (defanged):** `ssl.blsouqs.com`
- **Domain (defanged):** `tyhbgtyuj.gleeze.com`
- **Domain (defanged):** `wedfcvbn.gleeze.com`
- **Domain (defanged):** `rgnojb.casacam.net`
- **Domain (defanged):** `ctyuhjerf.kozow.com`
- **Domain (defanged):** `uyhvfredc.accesscam.org`
- **Domain (defanged):** `gycudore.kozow.com`
- **MD5:** `082d49ef9f14e6811d68c7e0e82e5069`
- **MD5:** `f4578e869a735cfad691f927bae3e638`
- **MD5:** `7c2f64461bb519c6cbf1fc687675514c`
- **MD5:** `8269d6ba1b6842f9152c90cf7add9b93`
- **MD5:** `a0cc7accc79abb0287aaba825d0351f0`
- **MD5:** `a56cce62930a6bee80d679b4c495a340`
- **MD5:** `1415a78b75de7db4ba3d1e61d7db4501`
- **MD5:** `a4d550a3ba0cd073fe3839b99d98a7a8`
- **MD5:** `2a571f6cee42a17d873f4c942649813f`
- **MD5:** `37dc84e4bcad92fa28f1e7778d088283`
- **MD5:** `cf903e4a1629aa0582fd0363b5786676`
- **MD5:** `3c9a1ba8e0c7475706adc6376e9d7b7c`
- **MD5:** `ef59aad625eebda8650aec5820d6ce69`
- **MD5:** `32a5985543433a4f60da2fafd873b927`
- **MD5:** `18dc8bff47cc282508354771d0c8cf8c`
- **MD5:** `9a1dd1d96481d61934dcc2d568971d06`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1090** — Proxy
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1055** — Process Injection
- **T1003.006** — OS Credential Dumping: DCSync
- **T1003.003** — OS Credential Dumping: NTDS
- **T1056.001** — Input Capture: Keylogging
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1046** — Network Service Discovery
- **T1110.001** — Brute Force: Password Guessing
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1039** — Data from Network Shared Drive

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### OctLurk/LurkProxy/SilkLurk C2 beacon to campaign-specific domains & VPS IPs

`UC_74_11` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query IN ("*ssentialserv.xyz","*multitoconference.com","*tajikistandip.com","*clouddevicemetrics.com","*mdpsupport.net","*annoyingremote.com","*blsouqs.com","*gleeze.com","*casacam.net","*kozow.com","*accesscam.org")) by DNS.src DNS.dest DNS.query | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
let c2Domains = dynamic(["dns.ssentialserv.xyz","dns.multitoconference.com","tj.tajikistandip.com","fm01.clouddevicemetrics.com","confbase.mdpsupport.net","api2.annoyingremote.com","about.blsouqs.com","ssl.blsouqs.com","tyhbgtyuj.gleeze.com","wedfcvbn.gleeze.com","rgnojb.casacam.net","ctyuhjerf.kozow.com","uyhvfredc.accesscam.org","gycudore.kozow.com","digital.leroymerlin.com"]);
let c2IPs = dynamic(["154.196.162.76","45.138.157.165","95.179.210.138","45.77.136.228","95.179.141.26","45.32.152.50","212.11.39.138","195.86.120.2","154.196.187.73","45.61.149.112","64.7.198.130"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (c2Domains) or RemoteIP in (c2IPs)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### OctLurk/SilkLurk/LurkProxy/PlugX known sample hash execution or drop

`UC_74_12` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("082d49ef9f14e6811d68c7e0e82e5069","f4578e869a735cfad691f927bae3e638","7c2f64461bb519c6cbf1fc687675514c","8269d6ba1b6842f9152c90cf7add9b93","a0cc7accc79abb0287aaba825d0351f0","a56cce62930a6bee80d679b4c495a340","1415a78b75de7db4ba3d1e61d7db4501","a4d550a3ba0cd073fe3839b99d98a7a8","2a571f6cee42a17d873f4c942649813f","37dc84e4bcad92fa28f1e7778d088283","cf903e4a1629aa0582fd0363b5786676","3c9a1ba8e0c7475706adc6376e9d7b7c","ef59aad625eebda8650aec5820d6ce69","32a5985543433a4f60da2fafd873b927","18dc8bff47cc282508354771d0c8cf8c","9a1dd1d96481d61934dcc2d568971d06") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let hashes = dynamic(["082d49ef9f14e6811d68c7e0e82e5069","f4578e869a735cfad691f927bae3e638","7c2f64461bb519c6cbf1fc687675514c","8269d6ba1b6842f9152c90cf7add9b93","a0cc7accc79abb0287aaba825d0351f0","a56cce62930a6bee80d679b4c495a340","1415a78b75de7db4ba3d1e61d7db4501","a4d550a3ba0cd073fe3839b99d98a7a8","2a571f6cee42a17d873f4c942649813f","37dc84e4bcad92fa28f1e7778d088283","cf903e4a1629aa0582fd0363b5786676","3c9a1ba8e0c7475706adc6376e9d7b7c","ef59aad625eebda8650aec5820d6ce69","32a5985543433a4f60da2fafd873b927","18dc8bff47cc282508354771d0c8cf8c","9a1dd1d96481d61934dcc2d568971d06"]);
union
(DeviceProcessEvents | where Timestamp > ago(30d) | where MD5 in (hashes) | project Timestamp, DeviceName, Source="ProcessCreate", MD5, FileName, FolderPath, Actor=InitiatingProcessCommandLine),
(DeviceImageLoadEvents | where Timestamp > ago(30d) | where MD5 in (hashes) | project Timestamp, DeviceName, Source="ImageLoad", MD5, FileName, FolderPath, Actor=InitiatingProcessCommandLine),
(DeviceFileEvents | where Timestamp > ago(30d) | where MD5 in (hashes) | project Timestamp, DeviceName, Source="FileWrite", MD5, FileName, FolderPath, Actor=InitiatingProcessCommandLine)
| order by Timestamp desc
```

### Impacket secretsdump domain-controller hash extraction

`UC_74_13` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*secretsdump*" OR Processes.process="*-just-dc-ntlm*" OR Processes.process="*-just-dc-user*" OR Processes.process="* -just-dc *") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where ProcessCommandLine has_any ("secretsdump", "-just-dc-ntlm", "-just-dc-user", "-just-dc ")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### AnyDesk-masquerading keylogger execution from non-standard path

`UC_74_14` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="anydesk.exe" AND NOT (Processes.process_path="*\\AnyDesk\\*" OR Processes.process_path="*\\Program Files*\\AnyDesk*") by Processes.dest Processes.user Processes.process_path Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has "anydesk"
| where not (FolderPath has @"\AnyDesk\" and (ProcessVersionInfoCompanyName has "AnyDesk" or ProcessVersionInfoProductName has "AnyDesk"))
| where FolderPath has_any (@"\Users\", @"\AppData\", @"\ProgramData\", @"\Temp\", @"\Public\")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### Fscan internal/public port scan using 'pp.txt' credential file

`UC_74_15` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*pp.txt*" OR Processes.process_name="fscan.exe" OR Processes.process="*fscan*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | search (process="*pp.txt*" OR process="*fscan*") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where ProcessCommandLine has "pp.txt"
    or FileName has "fscan"
    or ProcessCommandLine has "fscan"
    or (ProcessCommandLine has_all ("-pwdf", "3306"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### SilkLurk collection: admin-share doc staging archived with WinRAR/7-Zip

`UC_74_16` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("rar.exe","winrar.exe","7z.exe","7za.exe","7zg.exe") AND Processes.parent_process_name IN ("cmd.exe","powershell.exe","pwsh.exe") AND (Processes.process="* a *" OR Processes.process="*-hp*" OR Processes.process="* -p*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName in~ ("rar.exe","winrar.exe","7z.exe","7za.exe","7zg.exe")
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (" a ", "-hp", " -p", "-r ", "a -r")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
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

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
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

### Article-specific behavioural hunt — Suspected Chinese-Speaking Hackers Target Central Asian Governments With OctLurk

`UC_74_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Suspected Chinese-Speaking Hackers Target Central Asian Governments With OctLurk ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("secretsdump.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("secretsdump.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Suspected Chinese-Speaking Hackers Target Central Asian Governments With OctLurk
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("secretsdump.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("secretsdump.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `154.196.162.76`, `45.138.157.165`, `95.179.210.138`, `45.77.136.228`, `95.179.141.26`, `45.32.152.50`, `212.11.39.138`, `195.86.120.2` _(+18 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `082d49ef9f14e6811d68c7e0e82e5069`, `f4578e869a735cfad691f927bae3e638`, `7c2f64461bb519c6cbf1fc687675514c`, `8269d6ba1b6842f9152c90cf7add9b93`, `a0cc7accc79abb0287aaba825d0351f0`, `a56cce62930a6bee80d679b4c495a340`, `1415a78b75de7db4ba3d1e61d7db4501`, `a4d550a3ba0cd073fe3839b99d98a7a8` _(+8 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 17 use case(s) fired, 28 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
