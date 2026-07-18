# [HIGH] Microsoft warns of surge in ACR Stealer attacks on customers

**Source:** BleepingComputer
**Published:** 2026-07-18
**Article:** https://www.bleepingcomputer.com/news/security/microsoft-warns-of-surge-in-acr-stealer-attacks-on-customers/

## Threat Profile

Microsoft warns of surge in ACR Stealer attacks on customers 
By Bill Toulas 
July 18, 2026
10:17 AM
0 
Microsoft has observed a surge in attacks using the ACR Stealer malware to steal browser-stored passwords, authentication tokens, and sensitive documents from its enterprise customers.
Between late April and mid-June, the threat actor used the ClickFix social-engineering method, WebDAV servers, and the MSHTA (Microsoft HTML Application Host) utility to deliver the info-stealing payload.
ACR St…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `145.249.109.147`
- **IPv4 (defanged):** `8.217.190.58`
- **Domain (defanged):** `looksta.icu`
- **Domain (defanged):** `contrite.quirksturdy.icu`
- **Domain (defanged):** `ux.strainedeasily.icu`
- **Domain (defanged):** `cpppemwjewjoiwejow.sale`
- **Domain (defanged):** `breaksd.wifihot.icu`
- **Domain (defanged):** `walter.filloco.icu`
- **Domain (defanged):** `fast.raidher.icu`
- **Domain (defanged):** `apigrokcloud.icu`
- **Domain (defanged):** `enhanceblabber.cc`
- **Domain (defanged):** `deep-harborio.com`
- **Domain (defanged):** `auramatrixa.com`
- **Domain (defanged):** `zealpraxis.com`
- **Domain (defanged):** `prism-vertex.com`
- **Domain (defanged):** `prism-matrixs.com`
- **Domain (defanged):** `proton-network.com`
- **Domain (defanged):** `creativecommunityinfo.art`
- **Domain (defanged):** `sphere-api.dialectosphere.in.net`
- **Domain (defanged):** `claude-desktop.gitlab.io`
- **Domain (defanged):** `ravishingtattle.com`
- **Domain (defanged):** `clavdiydetka.com`
- **Domain (defanged):** `cludymians.com`
- **Domain (defanged):** `atlasgpt-browser.com`
- **Domain (defanged):** `strangerwrought.com`
- **Domain (defanged):** `dn8xpil.in.net`
- **Domain (defanged):** `ctr.accrabbleshowm.cfd`
- **Domain (defanged):** `ggx-tn-connectir.unwittingdork.digital`
- **Domain (defanged):** `claude-code.official-verazion.com`
- **Domain (defanged):** `hyuzoa1-guboitzyasi.com`
- **Domain (defanged):** `clabkjxkundgs.pages.dev`
- **Domain (defanged):** `clavycod.pages.dev`
- **SHA256:** `2546a45f0e751dc02630ee48ae624f2cf536cbe1978122785e9d395c789c46c5`
- **SHA256:** `d04208c041891beac90d0ef818310c7bd98b66d7bdb3d2ba523fb1939915ac90`
- **SHA256:** `39ff5c82fce4e2d4a2b001fbfb2a4dd39ba4e11e88ef6844af4e2119b426b116`
- **SHA256:** `cda84f0339e834c1d23572acc52cc02747776cc52d6b63f6ace9ea72d80a835e`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1053.005** — Scheduled Task
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1218.011** — System Binary Proxy Execution: Rundll32
- **T1105** — Ingress Tool Transfer
- **T1218.005** — System Binary Proxy Execution: Mshta
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1070.003** — Indicator Removal: Clear Command History
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Rundll32 loading remote WebDAV DLL via ClickFix (ACR Stealer chain 1)

`UC_2_9` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=rundll32.exe (Processes.process="*@SSL*" OR Processes.process="*@80*" OR Processes.process="*DavSetCookie*" OR Processes.process="*http://*" OR Processes.process="*https://*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("@SSL", "@80", "DavSetCookie", "http://", "https://")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### MSHTA fetching remote content then spawning PowerShell (ACR Stealer chain 2)

`UC_2_10` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=mshta.exe (Processes.process="*http://*" OR Processes.process="*https://*" OR Processes.process="*javascript:*" OR Processes.process="*vbscript:*")) OR (Processes.parent_process_name=mshta.exe (Processes.process_name=powershell.exe OR Processes.process_name=pwsh.exe)) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "mshta.exe" and ProcessCommandLine has_any ("http://","https://","javascript:","vbscript:"))
    or (InitiatingProcessFileName =~ "mshta.exe" and FileName in~ ("powershell.exe","pwsh.exe"))
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Outbound connection/DNS to ACR Stealer C2 dead-drop domains

`UC_2_11` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query IN ("looksta.icu","contrite.quirksturdy.icu","ux.strainedeasily.icu","cpppemwjewjoiwejow.sale","breaksd.wifihot.icu","walter.filloco.icu","fast.raidher.icu","apigrokcloud.icu","enhanceblabber.cc","deep-harborio.com","auramatrixa.com","zealpraxis.com","prism-vertex.com","prism-matrixs.com","proton-network.com","creativecommunityinfo.art")) by DNS.src DNS.query | `drop_dm_object_name(DNS)` | sort - lastTime
```

**Defender KQL:**
```kql
let c2Domains = dynamic(["looksta.icu","contrite.quirksturdy.icu","ux.strainedeasily.icu","cpppemwjewjoiwejow.sale","breaksd.wifihot.icu","walter.filloco.icu","fast.raidher.icu","apigrokcloud.icu","enhanceblabber.cc","deep-harborio.com","auramatrixa.com","zealpraxis.com","prism-vertex.com","prism-matrixs.com","proton-network.com","creativecommunityinfo.art","claude-desktop.gitlab.io","sphere-api.dialectosphere.in.net"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (c2Domains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Scheduled task masquerading as a software update launching a LOLBin

`UC_2_12` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=schtasks.exe Processes.process="*create*" Processes.process="*update*" (Processes.process="*powershell*" OR Processes.process="*pwsh*" OR Processes.process="*python*" OR Processes.process="*mshta*" OR Processes.process="*rundll32*" OR Processes.process="*AppData*" OR Processes.process="*\Temp*" OR Processes.process="*ProgramData*" OR Processes.process="*Public*") by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has "update"
| where ProcessCommandLine has_any ("powershell","pwsh","python","mshta","rundll32","AppData","Temp","ProgramData","Public")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Deletion of PowerShell PSReadline command history (anti-forensics)

`UC_2_13` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=deleted Filesystem.file_name="ConsoleHost_history.txt" by Filesystem.dest Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType == "FileDeleted"
| where FileName =~ "ConsoleHost_history.txt"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Non-browser process accessing Chromium credential databases (DPAPI browser theft)

`UC_2_14` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*User Data*") (Filesystem.file_name="Login Data" OR Filesystem.file_name="Cookies" OR Filesystem.file_name="Web Data" OR Filesystem.file_name="Local State") Filesystem.process_name!=chrome.exe Filesystem.process_name!=msedge.exe Filesystem.process_name!=brave.exe Filesystem.process_name!=msedgewebview2.exe by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath has "User Data"
| where FileName in~ ("Login Data","Local State","Web Data","Cookies")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","brave.exe","opera.exe","chrome_proxy.exe","msedgewebview2.exe","identity_helper.exe","elevation_service.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `145.249.109.147`, `8.217.190.58`, `looksta.icu`, `contrite.quirksturdy.icu`, `ux.strainedeasily.icu`, `cpppemwjewjoiwejow.sale`, `breaksd.wifihot.icu`, `walter.filloco.icu` _(+24 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `2546a45f0e751dc02630ee48ae624f2cf536cbe1978122785e9d395c789c46c5`, `d04208c041891beac90d0ef818310c7bd98b66d7bdb3d2ba523fb1939915ac90`, `39ff5c82fce4e2d4a2b001fbfb2a4dd39ba4e11e88ef6844af4e2119b426b116`, `cda84f0339e834c1d23572acc52cc02747776cc52d6b63f6ace9ea72d80a835e`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
