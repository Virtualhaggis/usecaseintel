# [CRIT] OceanLotus Hits Vietnam Investors With SPECTRALVIPER in FireAnt Attack

**Source:** The Hacker News
**Published:** 2026-06-11
**Article:** https://thehackernews.com/2026/06/oceanlotus-hits-vietnam-investors-with.html

## Threat Profile

OceanLotus Hits Vietnam Investors With SPECTRALVIPER in FireAnt Attack 
 Ravie Lakshmanan  Jun 11, 2026 Supply Chain Attack / Cyber Espionage 
The Vietnam-aligned threat actor known as OceanLotus has been attributed to two distinct campaigns that targeted domestic entities and stock investors with a backdoor known as SPECTRALVIPER.
The campaigns involve a prolonged cyber espionage operation aimed at a Vietnamese infrastructure and transport construction corporation between mid-2024 and Februar…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `38.60.245.37`
- **IPv4 (defanged):** `139.99.33.239`
- **IPv4 (defanged):** `139.162.11.152`
- **IPv4 (defanged):** `139.180.128.42`
- **IPv4 (defanged):** `142.91.98.77`
- **IPv4 (defanged):** `166.88.77.186`
- **IPv4 (defanged):** `194.68.26.241`
- **IPv4 (defanged):** `103.119.47.104`
- **Domain (defanged):** `financemachinelearning.com`
- **Domain (defanged):** `gatewayrvcenter.com`
- **Domain (defanged):** `coachcybersecurity.com`
- **Domain (defanged):** `mxprodesign.com`
- **Domain (defanged):** `power-sync-services.com`
- **Domain (defanged):** `leadingfilipinoteams.com`
- **SHA1:** `865A1739337D3303B3AB02C5E694C22B79C42B7D`
- **SHA1:** `B0FEA981D02F6F76DE81EBAEFCB68B7D205D6194`
- **SHA1:** `48FEBB91A10D1462461A012FAFC0918BB028E947`
- **SHA1:** `511B77459673EC42163F19E300FF1D233B6C39FB`
- **SHA1:** `8CD78B8DB76563E4F972ABE817CEEE9CF9B00037`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1059** — Command and Scripting Interpreter
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1055.012** — Process Hollowing
- **T1055** — Process Injection
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1190** — Exploit Public-Facing Application
- **T1059.003** — Windows Command Shell
- **T1505.001** — SQL Stored Procedures
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### FireAnt Metakit.exe spawns unsigned setup.exe from update path (SPECTRALVIPER supply-chain delivery)

`UC_95_10` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="Metakit.exe" Processes.process_name="setup.exe" by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "Metakit.exe"
| where FileName =~ "setup.exe"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, SHA1, SHA256, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### DtlCrashCatch.dll image-load by legitimate signed binary (OceanLotus DLL side-load)

`UC_95_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`sysmon` EventCode=7 ImageLoaded="*\\DtlCrashCatch.dll" | stats min(_time) as firstTime max(_time) as lastTime values(Image) as host_process values(Hashes) as hashes by host user ImageLoaded | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName =~ "DtlCrashCatch.dll"
| project Timestamp, DeviceName, FolderPath, SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```

### OneDrive.Sync.Service.exe spawned/injected outside legitimate OneDrive chain (SPECTRALVIPER injection target)

`UC_95_12` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="OneDrive.Sync.Service.exe" NOT Processes.parent_process_name IN ("OneDrive.exe","OneDriveSetup.exe","explorer.exe","svchost.exe","StandaloneUpdater.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "OneDrive.Sync.Service.exe"
| where not (InitiatingProcessFileName in~ ("OneDrive.exe","OneDriveSetup.exe","explorer.exe","svchost.exe","StandaloneUpdater.exe","FileCoAuth.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

### SPECTRALVIPER C2 callout to OceanLotus FireAnt infrastructure

`UC_95_13` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("38.60.245.37","139.99.33.239","139.162.11.152","139.180.128.42","142.91.98.77","166.88.77.186","194.68.26.241","103.119.47.104") OR All_Traffic.dest_host IN ("financemachinelearning.com","gatewayrvcenter.com","coachcybersecurity.com","mxprodesign.com","power-sync-services.com","leadingfilipinoteams.com") by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let badDomains = dynamic(["financemachinelearning.com","gatewayrvcenter.com","coachcybersecurity.com","mxprodesign.com","power-sync-services.com","leadingfilipinoteams.com"]);
let badIPs = dynamic(["38.60.245.37","139.99.33.239","139.162.11.152","139.180.128.42","142.91.98.77","166.88.77.186","194.68.26.241","103.119.47.104"]);
DeviceNetworkEvents
| where Timestamp > ago(180d)
| where RemoteIP in (badIPs) or RemoteUrl has_any (badDomains)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Public-facing MSSQL sqlservr.exe spawns suspicious child (OceanLotus transport-construction intrusion vector)

`UC_95_14` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="sqlservr.exe" Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","net.exe","net1.exe","whoami.exe") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(180d)
| where InitiatingProcessFileName =~ "sqlservr.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","net.exe","net1.exe","whoami.exe","setup.exe")
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### SPECTRALVIPER known-bad SHA1 observed on disk or in process

`UC_95_15` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("865A1739337D3303B3AB02C5E694C22B79C42B7D","B0FEA981D02F6F76DE81EBAEFCB68B7D205D6194","48FEBB91A10D1462461A012FAFC0918BB028E947","511B77459673EC42163F19E300FF1D233B6C39FB","8CD78B8DB76563E4F972ABE817CEEE9CF9B00037") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let badSHA1 = dynamic(["865A1739337D3303B3AB02C5E694C22B79C42B7D","B0FEA981D02F6F76DE81EBAEFCB68B7D205D6194","48FEBB91A10D1462461A012FAFC0918BB028E947","511B77459673EC42163F19E300FF1D233B6C39FB","8CD78B8DB76563E4F972ABE817CEEE9CF9B00037"]);
union
(DeviceProcessEvents | where Timestamp > ago(365d) | where SHA1 in (badSHA1) or InitiatingProcessSHA1 in (badSHA1) | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1, ProcessCommandLine, InitiatingProcessFileName),
(DeviceFileEvents   | where Timestamp > ago(365d) | where SHA1 in (badSHA1) or InitiatingProcessSHA1 in (badSHA1) | project Timestamp, DeviceName, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine),
(DeviceImageLoadEvents | where Timestamp > ago(365d) | where SHA1 in (badSHA1) | project Timestamp, DeviceName, FileName, FolderPath, SHA1, InitiatingProcessFileName)
| order by Timestamp desc
```

### Registry Run-key persistence written by SPECTRALVIPER side-load chain

`UC_95_16` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path IN ("*\\Microsoft\\Windows\\CurrentVersion\\Run\\*","*\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*") (Registry.registry_value_data="*DtlCrashCatch*" OR Registry.registry_value_data="*OneDrive.Sync.Service*" OR Registry.registry_value_data="*\\AppData\\Local\\Temp\\*" OR Registry.registry_value_data="*\\ProgramData\\*\\setup.exe*") by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(180d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("\\Microsoft\\Windows\\CurrentVersion\\Run","\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
| where RegistryValueData has_any ("DtlCrashCatch","OneDrive.Sync.Service","\\AppData\\Local\\Temp\\","\\ProgramData\\")
| where not (InitiatingProcessFileName in~ ("OneDriveSetup.exe","OneDrive.exe","msiexec.exe"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — OceanLotus Hits Vietnam Investors With SPECTRALVIPER in FireAnt Attack

`UC_95_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — OceanLotus Hits Vietnam Investors With SPECTRALVIPER in FireAnt Attack ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("metakit.exe","dtlcrashcatch.dll","onedrive.sync.service.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("metakit.exe","dtlcrashcatch.dll","onedrive.sync.service.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — OceanLotus Hits Vietnam Investors With SPECTRALVIPER in FireAnt Attack
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("metakit.exe", "dtlcrashcatch.dll", "onedrive.sync.service.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("metakit.exe", "dtlcrashcatch.dll", "onedrive.sync.service.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `38.60.245.37`, `139.99.33.239`, `139.162.11.152`, `139.180.128.42`, `142.91.98.77`, `166.88.77.186`, `194.68.26.241`, `103.119.47.104` _(+6 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `865A1739337D3303B3AB02C5E694C22B79C42B7D`, `B0FEA981D02F6F76DE81EBAEFCB68B7D205D6194`, `48FEBB91A10D1462461A012FAFC0918BB028E947`, `511B77459673EC42163F19E300FF1D233B6C39FB`, `8CD78B8DB76563E4F972ABE817CEEE9CF9B00037`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 17 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
