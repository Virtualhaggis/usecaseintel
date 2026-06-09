# [MED] Pirates in the crosshairs: how one cybercrime gang has been infecting book, movie, and TV show fans for years

**Source:** Securelist (Kaspersky)
**Published:** 2026-05-28
**Article:** https://securelist.com/video-books-pirates-miners-rat/119943/

## Threat Profile

Table of Contents
Introduction 
Link to previous campaigns 
Potential distribution scale 
The downloadable archive 
DLL analysis 
Main module 
Watchdog 
RAT agent 
The miners 
Conclusion 
Indicators of Compromise 
Authors
Konstantin Krasilnikov 
Valery Akulenko 
Artem Snegirev 
Introduction 
In late April 2026, a client reached out to us for incident response support after discovering a miner running on users’ computers. We later discovered that the malware was being distributed via illegal movi…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `107.172.212.235`
- **Domain (defanged):** `urush1bar4.online`
- **Domain (defanged):** `file.ipfs.us.69.mu`
- **Domain (defanged):** `5d14vnfb.space`
- **Domain (defanged):** `r7mvjl67.space`
- **Domain (defanged):** `zgj1tam9.space`
- **Domain (defanged):** `jeaw520i.space`
- **Domain (defanged):** `qdmagva5.space`
- **Domain (defanged):** `m4yuri.online`
- **Domain (defanged):** `kristina.quest`
- **MD5:** `6a0fe6065d76715feebc1526d456db73`
- **MD5:** `7f624407ae489324e96a708a09c17e6f`
- **MD5:** `02a43b3423367b9dddc24cc7dfc070df`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1027** — Obfuscated Files or Information
- **T1574.002** — DLL Side-Loading
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1112** — Modify Registry
- **T1496** — Resource Hijacking
- **T1071.004** — Application Layer Protocol: DNS
- **T1572** — Protocol Tunneling

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### HLS Installer.874.exe DLL side-load from pirate-streaming ZIP lure

`UC_159_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="HLS Installer.874.exe" (Processes.process_path="*\\Downloads\\*" OR Processes.process_path="*\\Desktop\\*" OR Processes.process_path="*\\Temp\\*" OR Processes.process_path="*\\AppData\\Local\\Temp\\*") by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "HLS Installer.874.exe"
| where FolderPath has_any (@"\Downloads\", @"\Desktop\", @"\Temp\", @"\AppData\Local\Temp\")
| join kind=inner (
    DeviceImageLoadEvents
    | where Timestamp > ago(14d)
    | where InitiatingProcessFileName =~ "HLS Installer.874.exe"
    | where FolderPath has_any (@"\Downloads\", @"\Desktop\", @"\Temp\", @"\AppData\Local\Temp\")
    | where FileName endswith ".dll"
) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| project Timestamp, DeviceName, AccountName, ProcessFolder=FolderPath, ProcessCmd=ProcessCommandLine, SideLoadedDll=FileName1, DllFolder=FolderPath1, DllSha256=SHA2561
| order by Timestamp desc
```

### SilentCryptoMiner-fork: Defender exclusions added for %USERPROFILE%, %PROGRAMDATA%, %WINDIR%, .exe, .dll

`UC_159_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\Microsoft\\Windows Defender\\Exclusions\\Paths\\*" OR Registry.registry_path="*\\Microsoft\\Windows Defender\\Exclusions\\Extensions\\*") (Registry.registry_value_name="*%USERPROFILE%*" OR Registry.registry_value_name="*%PROGRAMDATA%*" OR Registry.registry_value_name="*%WINDIR%*" OR Registry.registry_value_name=".exe" OR Registry.registry_value_name=".dll") by Registry.dest Registry.user Registry.process_name Registry.registry_path Registry.registry_value_name | `drop_dm_object_name(Registry)` | stats values(registry_value_name) as exclusions dc(registry_value_name) as exclusion_count min(firstTime) as firstTime max(lastTime) as lastTime by dest user process_name | where exclusion_count >= 3
```

**Defender KQL:**
```kql
let WindowMins = 10m;
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has @"\Microsoft\Windows Defender\Exclusions"
| where RegistryValueName in~ (".exe", ".dll") or RegistryValueName has_any ("%USERPROFILE%", "%PROGRAMDATA%", "%WINDIR%")
| summarize ExclusionCount = dcount(RegistryValueName), Exclusions = make_set(RegistryValueName), Bucket = bin(Timestamp, WindowMins), Actor = any(InitiatingProcessFileName), ActorCmd = any(InitiatingProcessCommandLine) by DeviceId, DeviceName
| where ExclusionCount >= 3
| order by Bucket desc
```

### MSRT tampering: HKLM\Software\Policies\Microsoft\MRT DontOfferThroughWUAU = 1

`UC_159_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\Software\\Policies\\Microsoft\\MRT*" Registry.registry_value_name="DontOfferThroughWUAU" Registry.registry_value_data="0x00000001" by Registry.dest Registry.user Registry.process_name Registry.registry_path Registry.registry_value_name Registry.registry_value_data | `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
let Lookback = 14d;
let RegHit = DeviceRegistryEvents
| where Timestamp > ago(Lookback)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has @"\Software\Policies\Microsoft\MRT"
| where RegistryValueName =~ "DontOfferThroughWUAU"
| where tostring(RegistryValueData) in ("1", "0x1", "0x00000001")
| project Timestamp, DeviceId, DeviceName, AccountName=InitiatingProcessAccountName, Actor=InitiatingProcessFileName, ActorCmd=InitiatingProcessCommandLine, Signal="MRT_PolicyReg";
let FileHit = DeviceFileEvents
| where Timestamp > ago(Lookback)
| where ActionType in ("FileDeleted", "FileRenamed")
| where FolderPath has @"\System32\" and FileName =~ "mrt.exe"
| project Timestamp, DeviceId, DeviceName, AccountName=InitiatingProcessAccountName, Actor=InitiatingProcessFileName, ActorCmd=InitiatingProcessCommandLine, Signal="MRT_FileDelete";
union RegHit, FileHit
| order by Timestamp desc
```

### powercfg sleep/hibernate disable burst (4-command sequence)

`UC_159_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(Processes.process) as commands min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="powercfg.exe" (Processes.process="*-hibernate-timeout-ac*0*" OR Processes.process="*-hibernate-timeout-dc*0*" OR Processes.process="*-standby-timeout-ac*0*" OR Processes.process="*-standby-timeout-dc*0*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | where count >= 3
```

**Defender KQL:**
```kql
let WindowMins = 5m;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powercfg.exe"
| where ProcessCommandLine has_any ("-hibernate-timeout-ac 0", "-hibernate-timeout-dc 0", "-standby-timeout-ac 0", "-standby-timeout-dc 0", "/x -hibernate-timeout", "/x -standby-timeout")
| extend Flag = case(
    ProcessCommandLine has "hibernate-timeout-ac", "hib_ac",
    ProcessCommandLine has "hibernate-timeout-dc", "hib_dc",
    ProcessCommandLine has "standby-timeout-ac", "sby_ac",
    ProcessCommandLine has "standby-timeout-dc", "sby_dc",
    "other")
| summarize Variants = dcount(Flag), Cmds = make_set(ProcessCommandLine), Parent = any(InitiatingProcessFileName), ParentCmd = any(InitiatingProcessCommandLine), Bucket = bin(Timestamp, WindowMins) by DeviceId, DeviceName, AccountName
| where Variants >= 3
| order by Bucket desc
```

### SilentCryptoMiner DNS tunneling to *.microsoft.com lookalike and known C2 .space domains

`UC_159_12` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*.5d14vnfb.space" OR DNS.query="*.r7mvjl67.space" OR DNS.query="*.zgj1tam9.space" OR DNS.query="*.jeaw520i.space" OR DNS.query="*.qdmagva5.space" OR DNS.query="*.m4yuri.online" OR DNS.query="*.urush1bar4.online" OR DNS.query="file.ipfs.us.69.mu") by DNS.src DNS.dest DNS.query | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=t count from datamodel=Network_Resolution.DNS where DNS.query="*.microsoft.com" by DNS.src DNS.dest DNS.query DNS.answer | `drop_dm_object_name(DNS)` | eval qlen=len(query) | where qlen > 80 AND NOT match(answer,"^(13\.|20\.|23\.|40\.|52\.|104\.|131\.107\.|134\.170\.|137\.116\.|157\.55\.|168\.61\.|191\.236\.|207\.46\.)")]
```

**Defender KQL:**
```kql
let CampaignDomains = dynamic(["urush1bar4.online","file.ipfs.us.69.mu","5d14vnfb.space","r7mvjl67.space","zgj1tam9.space","jeaw520i.space","qdmagva5.space","m4yuri.online"]);
let CampaignIp = "107.172.212.235";
let IocHit = DeviceNetworkEvents
| where Timestamp > ago(14d)
| where (isnotempty(RemoteUrl) and RemoteUrl has_any (CampaignDomains)) or RemoteIP == CampaignIp
| project Timestamp, DeviceId, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, Signal="IOC_Hit";
let TunnelHit = DeviceEvents
| where Timestamp > ago(14d)
| where ActionType == "DnsQueryResponse" or ActionType has "Dns"
| where RemoteUrl endswith ".microsoft.com"
| extend QueryLen = strlen(RemoteUrl)
| where QueryLen > 80
| where not(RemoteIP startswith "13." or RemoteIP startswith "20." or RemoteIP startswith "23." or RemoteIP startswith "40." or RemoteIP startswith "52." or RemoteIP startswith "104." or RemoteIP startswith "131.107." or RemoteIP startswith "134.170." or RemoteIP startswith "137.116." or RemoteIP startswith "157.55." or RemoteIP startswith "168.61." or RemoteIP startswith "191.236." or RemoteIP startswith "207.46.")
| project Timestamp, DeviceId, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, Signal="DNS_Tunnel_MSLookalike";
union IocHit, TunnelHit
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

### DNS tunneling / TXT-heavy domain queries

`UC_DNS_TUNNEL` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
    where DNS.message_type="QUERY"
    by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| eval qlen=len(query)
| where qlen > 50
| rex field=query "(?<second_level_domain>[\w-]+\.[\w-]+)$"
| stats sum(count) AS qcount, dc(query) AS unique_subs, max(qlen) AS max_label
    by src, second_level_domain
| where qcount > 100 AND unique_subs > 20
| sort - qcount
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 53 and isnotempty(RemoteUrl)
| extend qlen = strlen(RemoteUrl)
| where qlen > 50
| extend SecondLevelDomain = extract(@"([\w-]+\.[a-zA-Z]{2,})$", 1, RemoteUrl)
| summarize qcount = count(), uniqueSubs = dcount(RemoteUrl), maxLabel = max(qlen)
    by DeviceName, SecondLevelDomain
| where qcount > 100 and uniqueSubs > 20
| order by qcount desc
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

### Article-specific behavioural hunt — Pirates in the crosshairs: how one cybercrime gang has been infecting book, movi

`UC_159_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Pirates in the crosshairs: how one cybercrime gang has been infecting book, movi ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("installer.874.exe","mrt.exe","conhost.exe",".ftp.sh") OR Processes.process_path="*C:\ProgramData\Google\Chrome*" OR Processes.process_path="*%USERPROFILE%\AppData\Roaming\Sandboxie*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\ProgramData\Google\Chrome*" OR Filesystem.file_path="*%USERPROFILE%\AppData\Roaming\Sandboxie*" OR Filesystem.file_name IN ("installer.874.exe","mrt.exe","conhost.exe",".ftp.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\Software\\Policies\\Microsoft\\MRT*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Pirates in the crosshairs: how one cybercrime gang has been infecting book, movi
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("installer.874.exe", "mrt.exe", "conhost.exe", ".ftp.sh") or FolderPath has_any ("C:\ProgramData\Google\Chrome", "%USERPROFILE%\AppData\Roaming\Sandboxie"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\ProgramData\Google\Chrome", "%USERPROFILE%\AppData\Roaming\Sandboxie") or FileName in~ ("installer.874.exe", "mrt.exe", "conhost.exe", ".ftp.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\Software\Policies\Microsoft\MRT")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `107.172.212.235`, `urush1bar4.online`, `file.ipfs.us.69.mu`, `5d14vnfb.space`, `r7mvjl67.space`, `zgj1tam9.space`, `jeaw520i.space`, `qdmagva5.space` _(+2 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `6a0fe6065d76715feebc1526d456db73`, `7f624407ae489324e96a708a09c17e6f`, `02a43b3423367b9dddc24cc7dfc070df`


## Why this matters

Severity classified as **MED** based on: IOCs present, 13 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
