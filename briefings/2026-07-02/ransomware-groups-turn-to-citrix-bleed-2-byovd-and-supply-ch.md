# [CRIT] Ransomware Groups Turn to Citrix Bleed 2, BYOVD, and Supply Chain Credentials

**Source:** The Hacker News
**Published:** 2026-07-02
**Article:** https://thehackernews.com/2026/07/ransomware-groups-turn-to-citrix-bleed.html

## Threat Profile

Ransomware Groups Turn to Citrix Bleed 2, BYOVD, and Supply Chain Credentials 
 Ravie Lakshmanan  Jul 02, 2026 Malware / Cyber Attack 
Threat actors associated with the Anubis ransomware operation have been observed exploiting the Citrix Bleed 2 (CVE-2025-5777) vulnerability to obtain initial access.
"Although tactics differ between affiliates, common patterns emerged in tradecraft through use of legitimate Remote Management and Monitoring (RMM) tooling, credential access, and hands-on-keyboar…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-5777`
- **IPv4 (defanged):** `81.177.215.15`
- **MD5:** `3b46a729db7ae6af8b19711c9452194d`
- **MD5:** `02944c8a5535cdb5b2cbb893db2d5acf`
- **MD5:** `10ca9a4040001560d053b7e7885c1b95`
- **MD5:** `3c471ebc947cdf32240a90ffadf49b13`
- **MD5:** `4be8bb62f0ebbcf4ce52c35ab6f794f5`
- **MD5:** `53c616677bc7e2a0a03127f19166d007`
- **MD5:** `5c3b9821fc82a9028cb63b9671950919`
- **MD5:** `5f0b2c6d9f442754258bf4dd841c8341`
- **MD5:** `608faf58353b65c45ef9833358ac3787`
- **MD5:** `6ae7c9a7ea0b8c40a64225734f6bd01d`
- **MD5:** `846dc77c1246db20d976346e0e359502`
- **MD5:** `adac9984b3cc43d66a0d33079bbec299`
- **MD5:** `ae0e536766788478263bf448a9381641`
- **MD5:** `b3e418d30312c1b2c58a791286868f42`
- **MD5:** `c2764744dcb4b0e1db79ca1e8bf65368`
- **MD5:** `d12a5b36dd00586cc374a1cae43efed4`
- **MD5:** `d2f72897e8986303d5567eb2384932b8`
- **MD5:** `de1522f9219497632f30f8a6e72f26b6`
- **MD5:** `fdae2beb813778b4540a997706862096`
- **MD5:** `b9986a0f1f1f1a798dc3f0c59a80a1a3`
- **MD5:** `554e699c96b332468f1ae69c1ae81ef9`
- **MD5:** `5761bd63da03686fc480245da7bd1e9f`
- **MD5:** `b6b51508ad6f462c45fe102c85d246c8`
- **MD5:** `8f0577d28c4ff5f71b149f444bfaba8e`
- **MD5:** `525ef6014f0ef20e44fe47c1d9980b69`
- **MD5:** `407b6a136bbaa7172eb44ef9d08bb58a`
- **MD5:** `9321a61a25c7961d9f36852ecaa86f55`
- **MD5:** `73f0a8c3ea794a04e80c32038249f044`
- **MD5:** `eef8a950952696b018aa9c6da2f5d7ad`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1133** — External Remote Services
- **T1095** — Non-Application Layer Protocol
- **T1571** — Non-Standard Port
- **T1090** — Proxy
- **T1068** — Exploitation for Privilege Escalation
- **T1547.006** — Boot or Logon Autostart Execution: Kernel Modules and Extensions
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1572** — Protocol Tunneling
- **T1567.002** — Exfiltration to Cloud Storage
- **T1048** — Exfiltration Over Alternative Protocol
- **T1485** — Data Destruction
- **T1490** — Inhibit System Recovery
- **T1070.001** — Indicator Removal: Clear Windows Event Logs

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### CitrixBleed 2 (CVE-2025-5777) session-token scraping via repeated NetScaler auth POSTs

`UC_6_13` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web.Web where (Web.http_method=POST AND Web.url="*doAuthentication.do*") by Web.src, Web.dest, Web.http_user_agent, _time span=5m | `drop_dm_object_name(Web)` | stats sum(count) as auth_posts min(_time) as first_seen max(_time) as last_seen by src, dest | where auth_posts > 100
```

### Anubis VPN authentication from hosting ASNs (Constant Company AS20473 / ServerMania AS55286)

`UC_6_14` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication.Authentication where Authentication.action=success by Authentication.user, Authentication.src, Authentication.app, Authentication.src_asn, _time span=1h | `drop_dm_object_name(Authentication)` | search src_asn IN (20473, 55286) | stats count min(_time) as first_seen max(_time) as last_seen by user, src, src_asn, app
```

### The Gentlemen Go backdoor C2 to 81.177.215.15:9443

`UC_6_15` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="81.177.215.15" AND All_Traffic.dest_port=9443 by All_Traffic.src, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.app, _time span=1m | `drop_dm_object_name(All_Traffic)` | stats count min(_time) as first_seen max(_time) as last_seen by src, dest_ip, dest_port, app
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "81.177.215.15" and RemotePort == 9443
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort
| order by Timestamp desc
```

### The Gentlemen BYOVD: Kontron ktapi.sys vulnerable-driver load

`UC_6_16` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.file_name="ktapi.sys" by Endpoint.Filesystem.dest, Endpoint.Filesystem.file_path, Endpoint.Filesystem.process_name, _time span=1m | `drop_dm_object_name(Filesystem)` | stats count min(_time) as first_seen max(_time) as last_seen by dest, file_path, process_name
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName =~ "ktapi.sys"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Anubis affiliate RMM tooling first-seen deployment (ScreenConnect/Zoho/MeshAgent/Remotely/UltraVNC/TSD)

`UC_6_17` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process_name IN ("ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe","ZA_Access.exe","ZA_Connect.exe","meshagent.exe","meshagent64.exe","Remotely_Agent.exe","Remotely_Desktop.exe","winvnc.exe","winvnc64.exe","TSD.exe")) by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name, _time span=1h | `drop_dm_object_name(Processes)` | stats count min(_time) as first_seen max(_time) as last_seen by dest, user, process_name, process, parent_process_name
```

**Defender KQL:**
```kql
let RMM = dynamic(["screenconnect.clientservice.exe","screenconnect.windowsclient.exe","za_access.exe","za_connect.exe","zaservice.exe","meshagent.exe","meshagent64.exe","remotely_agent.exe","remotely_desktop.exe","winvnc.exe","winvnc64.exe","tsd.exe"]);
let Baseline = DeviceProcessEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where tolower(FileName) in (RMM)
    | summarize by DeviceName, FileName;
DeviceProcessEvents
| where Timestamp > ago(1d)
| where tolower(FileName) in (RMM)
| where AccountName !endswith "$"
| join kind=leftanti Baseline on DeviceName, FileName
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### Cloudflare Tunnel (cloudflared) covert egress setup

`UC_6_18` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process_name="cloudflared.exe" OR Processes.process="*cloudflared*") AND (Processes.process="*tunnel*" OR Processes.process="*--token*" OR Processes.process="*trycloudflare*") by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name, _time span=1h | `drop_dm_object_name(Processes)` | stats count min(_time) as first_seen max(_time) as last_seen by dest, user, process, parent_process_name
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "cloudflared.exe" or ProcessCommandLine has "cloudflared"
| where ProcessCommandLine has_any ("tunnel","--token","--url","trycloudflare")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### Anubis pre-encryption cloud-exfil tooling (rclone/s5cmd/S3 Browser/WinSCP)

`UC_6_19` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process_name IN ("rclone.exe","s5cmd.exe","s3browser.exe","s3browser-con.exe") OR (Processes.process_name IN ("WinSCP.exe","WinSCP.com","pscp.exe","psftp.exe") AND (Processes.process="*sftp*" OR Processes.process="*s3:*" OR Processes.process="* put *"))) by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name, _time span=1h | `drop_dm_object_name(Processes)` | stats count min(_time) as first_seen max(_time) as last_seen by dest, user, process_name, process, parent_process_name
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("rclone.exe","s5cmd.exe","s3browser.exe","s3browser-con.exe"))
   or (FileName in~ ("winscp.exe","winscp.com","pscp.exe","psftp.exe") and ProcessCommandLine has_any (" sftp"," s3:"," put ","-hostkey","open ftp"))
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### Anubis /WIPEMODE zero-KB in-place file truncation (data destruction)

`UC_6_20` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.action IN ("modified","renamed") AND Endpoint.Filesystem.file_size=0 by Endpoint.Filesystem.dest, Endpoint.Filesystem.process_name, Endpoint.Filesystem.process_guid, _time span=10m | `drop_dm_object_name(Filesystem)` | stats dc(process_guid) as procs count as zero_byte_events by dest, process_name, _time | where zero_byte_events > 200
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileModified","FileRenamed")
| where FileSize == 0
| where InitiatingProcessAccountName !endswith "$"
| summarize ZeroByteFiles = dcount(FolderPath), SampleFolders = make_set(FolderPath, 5), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
         by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessId
| where ZeroByteFiles > 200   // /WIPEMODE truncates many files to 0 KB in place; benign apps rarely zero-out hundreds of files from one process
| order by ZeroByteFiles desc
```

### Anubis/Gentlemen defense-evasion cluster: Defender disable, PCHunter, SophosUninstall, log clearing

`UC_6_21` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where ((Processes.process="*Set-MpPreference*" AND Processes.process="*DisableRealtimeMonitoring*") OR Processes.process_name IN ("PCHunter64.exe","PCHunter32.exe","PCHunter.exe") OR Processes.process="*SophosUninstall*" OR Processes.process="*uninstallcli.exe*" OR (Processes.process_name="wevtutil.exe" AND Processes.process="*cl *") OR Processes.process="*Clear-EventLog*") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name, _time span=1h | `drop_dm_object_name(Processes)` | stats count min(_time) as first_seen max(_time) as last_seen by dest, user, process_name, process, parent_process_name
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Set-MpPreference" and ProcessCommandLine has "DisableRealtimeMonitoring")
     or (FileName in~ ("PCHunter64.exe","PCHunter32.exe","PCHunter.exe"))
     or (ProcessCommandLine has_any ("SophosUninstall","uninstallcli.exe"))
     or (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any (" cl ","clear-log"))
     or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Clear-EventLog")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
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

### Article-specific behavioural hunt — Ransomware Groups Turn to Citrix Bleed 2, BYOVD, and Supply Chain Credentials

`UC_6_12` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Ransomware Groups Turn to Citrix Bleed 2, BYOVD, and Supply Chain Credentials ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("ktapi.sys"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("ktapi.sys"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Ransomware Groups Turn to Citrix Bleed 2, BYOVD, and Supply Chain Credentials
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("ktapi.sys"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("ktapi.sys"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-5777`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `81.177.215.15`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `3b46a729db7ae6af8b19711c9452194d`, `02944c8a5535cdb5b2cbb893db2d5acf`, `10ca9a4040001560d053b7e7885c1b95`, `3c471ebc947cdf32240a90ffadf49b13`, `4be8bb62f0ebbcf4ce52c35ab6f794f5`, `53c616677bc7e2a0a03127f19166d007`, `5c3b9821fc82a9028cb63b9671950919`, `5f0b2c6d9f442754258bf4dd841c8341` _(+21 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 22 use case(s) fired, 33 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
