# [HIGH] Silent Swap Crypto Clipper Uses Fake Google Notes Extension to Replace Wallet Addresses

**Source:** The Hacker News
**Published:** 2026-06-30
**Article:** https://thehackernews.com/2026/06/silent-swap-crypto-clipper-uses-fake.html

## Threat Profile

Silent Swap Crypto Clipper Uses Fake Google Notes Extension to Replace Wallet Addresses 
 Ravie Lakshmanan  Jun 30, 2026 Browser Security / Cryptocurrency 
Cybersecurity researchers have flagged an active browser extension campaign that is designed to steal cryptocurrency by stealthily replacing wallet addresses when unsuspecting users initiate a transaction.
The cryptocurrency clipper activity has been codenamed Silent Swap by McAfee Labs.
"The campaign is delivered through unsigned installer…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `178.236.252.133`
- **IPv4 (defanged):** `77.91.123.187`
- **Domain (defanged):** `hell1-kitty.cc`
- **Domain (defanged):** `alphazero1-endscape.cc`
- **Domain (defanged):** `api-microservice-us1.com`
- **Domain (defanged):** `bucket-aws-s1.com`
- **Domain (defanged):** `bucket-aws-s2.com`
- **Domain (defanged):** `fileless-storage-s3.cc`
- **Domain (defanged):** `globalsnn1-new.cc`
- **Domain (defanged):** `globalsnn2-new.cc`
- **Domain (defanged):** `globalsnn3-new.cc`
- **Domain (defanged):** `handle-me-sv1.com`
- **Domain (defanged):** `hardware-office.cc`
- **Domain (defanged):** `health-smooth-eu1.com`
- **Domain (defanged):** `health-smooth-eu2.com`
- **Domain (defanged):** `health-smooth-eu3.com`
- **Domain (defanged):** `holiday-updateservice.com`
- **Domain (defanged):** `memory-protection-layer1.cc`
- **Domain (defanged):** `memory-protection-layer2.cc`
- **Domain (defanged):** `microservice-update-s1-bucket.cc`
- **Domain (defanged):** `microservice-update-s2-bucket.cc`
- **Domain (defanged):** `my-smart-house1.com`
- **Domain (defanged):** `polystore9-servicebucket.cc`
- **Domain (defanged):** `s3-updatehub.cc`
- **Domain (defanged):** `edr-security-bucket1.cc`
- **Domain (defanged):** `memory-scanner.cc`
- **SHA256:** `5f9ff671955a6d551595f9838aed063c496da5039be0d222fe84f96cb3e1d32a`
- **SHA256:** `3c278499c5e3ced3bf1a6a7287808c5267075f1dec0aa5c7be2c4c444f33f2bc`
- **SHA256:** `c68e436d4cb984db026210806f50d0c81eec5f6e4860197dab91fab6f31ef796`
- **SHA256:** `e2faad8111e7d47349cbc549b85e62231b8678057906bc813aad7242fa95ae63`
- **SHA256:** `e5e1d8ec4cd109df290752ee3d4b2cbc9de6df4360e9983548f1bc6b1d088540`
- **SHA256:** `cbdfb46b9265a3dfb3bc6b0aade472dde28b1660dbd3ded3b67b1530b4497cca`
- **SHA256:** `4a5e1d6ee1217e1fbacf54fc6017fbf9d24a25078266b02358d56a9c7437ceb7`
- **SHA256:** `05becb67d8bf1e49fcfccb0d346b82368a2b1c2bf07316078c364c7b020154de`
- **SHA256:** `44daa1b68737b55a711963eec211c7c018bcba4cb6d68c286a4b45ea781a7d73`
- **SHA256:** `dc602cb53a9c24abfcdaadf0ca8256b5fb5cac6d91d20ed8431bdaaf51c0cafe`
- **SHA256:** `10593dbe9edfde7943fdaadd7882f190216b2f6502667daf701088a6e810deaf`
- **SHA256:** `0a69a9cc75d65774e5eb90a4a739bd4335d33b176dc4923acb691bd45af66bdf`
- **SHA256:** `27c6a6bda2c0ef3ecb78dad9c6bb7c3abaf2e32b3ad96f372a0102c0c9c0f08d`
- **SHA256:** `2cd449f1bb24f05d2e240812a74bd62f2583bbbe4d0ccc9ae5736240e29a0068`
- **SHA256:** `30dcd5c71beb76d2f8df768d5fd9e9145cb8fbbfc951a63b969d26d3b64002b9`
- **SHA256:** `dd4c7f5aae404816cf447b8090b620c1a1971a35c6791116aa3f871f00ae011b`
- **SHA256:** `42a1fc74334c9a3b8720c79df55f84c7398bd31609eb10581e8c7155835498e3`
- **SHA256:** `9c0d334aac5a6f66016dc5ce8df75c46d519a4e6d16c68cf2b1405c81189186d`
- **SHA256:** `44f6313e9542c0d51937a70160fe4137012905d8c79ad27ccc0021788ecfaa4e`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1219** — Remote Access Software
- **T1027** — Obfuscated Files or Information
- **T1176.001** — Browser Extensions
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1657** — Financial Theft

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Non-browser process writing Chromium 'Secure Preferences'/'Preferences' (Silent Swap sideload)

`UC_116_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="Secure Preferences" OR Filesystem.file_name="Preferences") Filesystem.file_path="*\\User Data\\*" NOT (Filesystem.process_name IN ("chrome.exe","msedge.exe","brave.exe","vivaldi.exe","opera.exe","opera_gx.exe","update.exe","software_reporter_tool.exe","googleupdate.exe","elevation_service.exe","setup.exe","msiexec.exe")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("Secure Preferences","Preferences")
| where FolderPath has @"\User Data\"
| where FolderPath has_any (@"\Google\Chrome\", @"\Microsoft\Edge\", @"\BraveSoftware\Brave-Browser\", @"\Vivaldi\", @"\Opera Software\")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","brave.exe","vivaldi.exe","opera.exe","opera_gx.exe","update.exe","software_reporter_tool.exe","googleupdate.exe","elevation_service.exe","setup.exe","msiexec.exe","msedge_proxy.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

### Single process force-terminating multiple Chromium browsers (Silent Swap profile-unlock precursor)

`UC_116_11` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Processes.process) as process_cmds min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="taskkill.exe" (Processes.process="*chrome.exe*" OR Processes.process="*msedge.exe*" OR Processes.process="*brave.exe*" OR Processes.process="*vivaldi.exe*" OR Processes.process="*opera.exe*") by Processes.dest Processes.user Processes.parent_process_name _time span=10m
| `drop_dm_object_name(Processes)`
| rex max_match=0 field=process_cmds "(?i)(?<browsers>chrome|msedge|brave|vivaldi|opera)\.exe"
| eval distinct_browsers=mvcount(mvdedup(browsers))
| where distinct_browsers>=2
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "taskkill.exe"
| extend BrowserKilled = tolower(extract(@"(?i)(chrome|msedge|brave|vivaldi|opera|opera_gx)\.exe", 1, ProcessCommandLine))
| where isnotempty(BrowserKilled)
| where AccountName !endswith "$"
| summarize KilledBrowsers = make_set(BrowserKilled), KillCount = dcount(BrowserKilled), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleCmds = make_set(ProcessCommandLine, 8) by DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, bin(Timestamp, 10m)
| where KillCount >= 2
| order by LastSeen desc
```

### Silent Swap / VPN Go clipper C2 and clipboard-exfil to known infrastructure

`UC_116_12` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("178.236.252.133","77.91.123.187") OR All_Traffic.dest IN ("hell1-kitty.cc","alphazero1-endscape.cc","api-microservice-us1.com","bucket-aws-s1.com","bucket-aws-s2.com","fileless-storage-s3.cc","globalsnn1-new.cc","globalsnn2-new.cc","globalsnn3-new.cc","handle-me-sv1.com","hardware-office.cc","health-smooth-eu1.com","health-smooth-eu2.com","health-smooth-eu3.com","holiday-updateservice.com","memory-protection-layer1.cc","memory-protection-layer2.cc","microservice-update-s1-bucket.cc","microservice-update-s2-bucket.cc","my-smart-house1.com")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
| append [| tstats `summariesonly` count from datamodel=Network_Resolution.DNS where DNS.query IN ("hell1-kitty.cc","alphazero1-endscape.cc","api-microservice-us1.com","fileless-storage-s3.cc","globalsnn1-new.cc","globalsnn2-new.cc","globalsnn3-new.cc","handle-me-sv1.com","hardware-office.cc","health-smooth-eu1.com","health-smooth-eu2.com","health-smooth-eu3.com","holiday-updateservice.com","memory-protection-layer1.cc","memory-protection-layer2.cc","my-smart-house1.com") by DNS.src DNS.query | `drop_dm_object_name(DNS)`]
| sort - lastTime
```

**Defender KQL:**
```kql
let c2_ips = dynamic(["178.236.252.133","77.91.123.187"]);
let c2_domains = dynamic(["hell1-kitty.cc","alphazero1-endscape.cc","api-microservice-us1.com","bucket-aws-s1.com","bucket-aws-s2.com","fileless-storage-s3.cc","globalsnn1-new.cc","globalsnn2-new.cc","globalsnn3-new.cc","handle-me-sv1.com","hardware-office.cc","health-smooth-eu1.com","health-smooth-eu2.com","health-smooth-eu3.com","holiday-updateservice.com","memory-protection-layer1.cc","memory-protection-layer2.cc","microservice-update-s1-bucket.cc","microservice-update-s2-bucket.cc","my-smart-house1.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (c2_ips) or RemoteUrl has_any (c2_domains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessSHA256
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

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
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

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `178.236.252.133`, `77.91.123.187`, `hell1-kitty.cc`, `alphazero1-endscape.cc`, `api-microservice-us1.com`, `bucket-aws-s1.com`, `bucket-aws-s2.com`, `fileless-storage-s3.cc` _(+18 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `5f9ff671955a6d551595f9838aed063c496da5039be0d222fe84f96cb3e1d32a`, `3c278499c5e3ced3bf1a6a7287808c5267075f1dec0aa5c7be2c4c444f33f2bc`, `c68e436d4cb984db026210806f50d0c81eec5f6e4860197dab91fab6f31ef796`, `e2faad8111e7d47349cbc549b85e62231b8678057906bc813aad7242fa95ae63`, `e5e1d8ec4cd109df290752ee3d4b2cbc9de6df4360e9983548f1bc6b1d088540`, `cbdfb46b9265a3dfb3bc6b0aade472dde28b1660dbd3ded3b67b1530b4497cca`, `4a5e1d6ee1217e1fbacf54fc6017fbf9d24a25078266b02358d56a9c7437ceb7`, `05becb67d8bf1e49fcfccb0d346b82368a2b1c2bf07316078c364c7b020154de` _(+11 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 13 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
