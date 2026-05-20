# [HIGH] SHub macOS infostealer variant spoofs Apple security updates

**Source:** BleepingComputer
**Published:** 2026-05-18
**Article:** https://www.bleepingcomputer.com/news/security/shub-macos-infostealer-variant-spoofs-apple-security-updates/

## Threat Profile

SHub macOS infostealer variant spoofs Apple security updates 
By Bill Toulas 
May 18, 2026
05:42 PM
0 
A new variant of the ‘SHub’ macOS infostealer uses AppleScript to show a fake security update message and installs a backdoor.
Dubbed Reaper, the new version steals sensitive browser data, collects documents and files that may contain financial details, and hijacks crypto wallet apps.
Unlike earlier SHub campaigns that relied on “ClickFix” tactics, tricking users into pasting and executing comm…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `qq-0732gwh22.com`
- **Domain (defanged):** `mlcrosoft.co.com`
- **Domain (defanged):** `mlroweb.com`
- **Domain (defanged):** `hebsbsbzjsjshduxbs.xyz`
- **SHA256:** `6552824c59ddacb134073f24a4bd4724514a938a9dc59f1733503642faed3bd3`
- **MD5:** `c917fcf8314228862571f80c9e4a871e`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1059.002** — Command and Scripting Interpreter: AppleScript
- **T1218** — System Binary Proxy Execution
- **T1105** — Ingress Tool Transfer
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1553.001** — Subvert Trust Controls: Gatekeeper Bypass
- **T1565.001** — Stored Data Manipulation
- **T1554** — Compromise Client Software Binary
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] macOS Script Editor / osascript invoked via applescript:// URL scheme (SHub Reaper bypass)

`UC_11_8` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("Script Editor","osascript","open") OR Processes.process IN ("*applescript://*")) Processes.os="macOS" by host, user, Processes.process_name, Processes.process, Processes.parent_process_name, Processes.parent_process | `drop_dm_object_name(Processes)` | search process="*applescript://*" OR parent_process="*applescript://*" OR (process_name="Script Editor" AND parent_process_name IN ("Google Chrome","Google Chrome Helper","Safari","firefox","Microsoft Edge","Brave Browser","Opera","Arc","Vivaldi","Orion","open","launchd"))
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "applescript://" or InitiatingProcessCommandLine has "applescript://"
   or (FolderPath has "Script Editor.app" and InitiatingProcessFileName in~ ("Google Chrome","Google Chrome Helper","Safari","firefox","Microsoft Edge","Brave Browser","Opera","Arc","Vivaldi","Orion","open","launchd"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] osascript spawning curl/zsh fetch-and-execute loader chain (SHub Reaper)

`UC_11_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=osascript (Processes.process_name IN (curl,zsh,sh,bash) OR Processes.process IN ("*XProtectRemediator*","*curl *","*| zsh*","*|zsh*")) Processes.os="macOS" by host, user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "osascript"
| where FileName in~ ("curl","zsh","sh","bash") or ProcessCommandLine has_any ("curl ","| zsh","|zsh","XProtectRemediator")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] xattr -cr quarantine strip on crypto wallet bundle / app.asar replacement (SHub Reaper wallet hijack)

`UC_11_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.os="macOS" ((Processes.process_name=xattr Processes.process="*-cr*") OR (Processes.process_name=codesign Processes.process="*--sign -*") OR Processes.process="*app.asar*") by host, user, Processes.process_name, Processes.process, Processes.parent_process_name | `drop_dm_object_name(Processes)` | search process="*Exodus*" OR process="*Atomic*" OR process="*Ledger Live*" OR process="*Electrum*" OR process="*Trezor*" OR process="*app.asar*"
```

**Defender KQL:**
```kql
let WalletPaths = dynamic(["Exodus.app","Atomic.app","Atomic Wallet.app","Ledger Live.app","Electrum.app","Trezor Suite.app"]);
let ProcAbuse = DeviceProcessEvents
  | where Timestamp > ago(7d)
  | where (FileName =~ "xattr" and ProcessCommandLine has "-cr")
       or (FileName =~ "codesign" and ProcessCommandLine matches regex @"--sign\s+-(\s|$)")
  | where ProcessCommandLine has_any (WalletPaths) or ProcessCommandLine has "app.asar"
  | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
let FileAbuse = DeviceFileEvents
  | where Timestamp > ago(7d)
  | where FileName =~ "app.asar"
  | where FolderPath has_any (WalletPaths)
  | where InitiatingProcessFileName !in~ ("Exodus","Atomic Wallet","Ledger Live","Electrum","Trezor Suite","installd","Installer")
  | project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine;
union ProcAbuse, FileAbuse
| order by Timestamp desc
```

### [LLM] macOS LaunchAgent persistence impersonating Google software update (SHub Reaper beacon)

`UC_11_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*/Library/LaunchAgents/*" Filesystem.file_name="*.plist" by host, user, Filesystem.file_name, Filesystem.file_path, Filesystem.process_name | `drop_dm_object_name(Filesystem)` | search (file_name="*google*" OR file_name="*keystone*" OR file_name="*update*" OR file_name="*softwareupdate*") process_name!="Keystone" process_name!="GoogleSoftwareUpdateAgent" process_name!="GoogleUpdater" process_name!="installd" process_name!="Installer"
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has "/Library/LaunchAgents/"
| where FileName endswith ".plist"
| where FileName has_any ("google","keystone","softwareupdate","update")
| where InitiatingProcessFileName !in~ ("Keystone","GoogleSoftwareUpdateAgent","GoogleUpdater","ksinstall","installd","Installer","system_installd")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] macOS host beaconing to known SHub Reaper distribution / C2 infrastructure

`UC_11_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="qq-0732gwh22.com" OR All_Traffic.dest="mlcrosoft.co.com" OR All_Traffic.dest="mlroweb.com" OR All_Traffic.dest="hebsbsbzjsjshduxbs.xyz" OR All_Traffic.url="*qq-0732gwh22.com*" OR All_Traffic.url="*mlcrosoft.co.com*" OR All_Traffic.url="*mlroweb.com*" OR All_Traffic.url="*hebsbsbzjsjshduxbs.xyz*") by host, user, All_Traffic.src, All_Traffic.dest, All_Traffic.url, All_Traffic.app | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
let IOCDomains = dynamic(["qq-0732gwh22.com","mlcrosoft.co.com","mlroweb.com","hebsbsbzjsjshduxbs.xyz"]);
let IOCSha256 = dynamic(["6552824c59ddacb134073f24a4bd4724514a938a9dc59f1733503642faed3bd3"]);
let Net = DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has_any (IOCDomains)
  | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessSHA256;
let Hash = DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (IOCSha256)
  | project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine;
union Net, Hash
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `qq-0732gwh22.com`, `mlcrosoft.co.com`, `mlroweb.com`, `hebsbsbzjsjshduxbs.xyz`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `6552824c59ddacb134073f24a4bd4724514a938a9dc59f1733503642faed3bd3`, `c917fcf8314228862571f80c9e4a871e`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 13 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
