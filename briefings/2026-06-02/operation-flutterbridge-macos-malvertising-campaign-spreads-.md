# [CRIT] Operation FlutterBridge: macOS Malvertising Campaign Spreads New FlutterShell Backdoor

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-06-02
**Article:** https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/

## Threat Profile

Threat Research Center 
Threat Research 
Malware 
Malware 
Operation FlutterBridge: macOS Malvertising Campaign Spreads New FlutterShell Backdoor 
17 min read 
Related Products Advanced WildFire Cloud-Delivered Security Services Cortex Cortex XDR Cortex XSIAM Unit 42 Incident Response 
By: Ido Asher 
Noa Dekel 
Tom Fakterman 
Published: June 2, 2026 
Categories: Malware 
Threat Research 
Tags: CL-CRI-1089 
MacOS 
Malvertising 
Executive Summary 
We are tracking an increasingly widespread malvert…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `atsheisdomestic.org`
- **Domain (defanged):** `etoftheappyrince.org`
- **Domain (defanged):** `healightejustb.org`
- **Domain (defanged):** `sinterfumesco.com`
- **Domain (defanged):** `ads-parkpro.com`
- **Domain (defanged):** `adsparkpro.top`
- **Domain (defanged):** `adsparkpro.net`
- **Domain (defanged):** `softwe.art`
- **SHA256:** `021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845`
- **SHA256:** `363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34`
- **SHA256:** `8421c902364980e3d762ec6dbbe6b0f40577c27bd79b48c57d098328b2533109`
- **SHA256:** `644fc49fa1006a2a2acace694e5fb83753164e2617051ece6d9dc9ea32329e70`
- **SHA256:** `9053e8ddaecca1f960c041c944ca8799fc71dc86a4b50d2639ee4e0d2cb82f47`
- **SHA256:** `b60074d1ea2008a581f432f2dee5f84f78668d9dd8e66f75d03c42dabd89bdea`
- **SHA256:** `9425e8e39fa8a7212cdd07f0917cb3dfde38a90b87297de2c82a5850aff1e4de`
- **SHA256:** `30448686ec900d5213d74f08f0d2b7924c5336a29445b2a434aba8d8b19d7530`
- **SHA256:** `48047c34bbd57fe1e24bc538bc2ce9e0ac4c4eb48d3b0c195b414f0379dc0745`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1204.002** — User Execution: Malicious File
- **T1036.001** — Masquerading: Invalid Code Signature
- **T1185** — Browser Session Hijacking
- **T1583.008** — Acquire Infrastructure: Malvertising

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### FlutterShell macOS C2 contact (atsheisdomestic / etoftheappyrince / healightejustb)

`UC_141_8` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest) as dest values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_host IN ("atsheisdomestic.org","etoftheappyrince.org","healightejustb.org","*.atsheisdomestic.org","*.etoftheappyrince.org","*.healightejustb.org") by All_Traffic.src All_Traffic.dest_host All_Traffic.user host | `drop_dm_object_name(All_Traffic)` | appendpipe [| tstats summariesonly=t count from datamodel=Network_Resolution.DNS where DNS.query IN ("atsheisdomestic.org","etoftheappyrince.org","healightejustb.org","*.atsheisdomestic.org","*.etoftheappyrince.org","*.healightejustb.org") by DNS.src DNS.query host | `drop_dm_object_name(DNS)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let C2 = dynamic(["atsheisdomestic.org","etoftheappyrince.org","healightejustb.org"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (C2) or RemoteUrl endswith ".atsheisdomestic.org" or RemoteUrl endswith ".etoftheappyrince.org" or RemoteUrl endswith ".healightejustb.org"
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### FlutterShell macOS payload SHA256 IOC match

`UC_141_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845","363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34","8421c902364980e3d762ec6dbbe6b0f40577c27bd79b48c57d098328b2533109","644fc49fa1006a2a2acace694e5fb83753164e2617051ece6d9dc9ea32329e70","9053e8ddaecca1f960c041c944ca8799fc71dc86a4b50d2639ee4e0d2cb82f47","b60074d1ea2008a581f432f2dee5f84f78668d9dd8e66f75d03c42dabd89bdea","9425e8e39fa8a7212cdd07f0917cb3dfde38a90b87297de2c82a5850aff1e4de","30448686ec900d5213d74f08f0d2b7924c5336a29445b2a434aba8d8b19d7530") by Filesystem.dest Filesystem.file_path Filesystem.file_name host | `drop_dm_object_name(Filesystem)` | appendpipe [| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.process_hash IN ("021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845","363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34","8421c902364980e3d762ec6dbbe6b0f40577c27bd79b48c57d098328b2533109","644fc49fa1006a2a2acace694e5fb83753164e2617051ece6d9dc9ea32329e70","9053e8ddaecca1f960c041c944ca8799fc71dc86a4b50d2639ee4e0d2cb82f47","b60074d1ea2008a581f432f2dee5f84f78668d9dd8e66f75d03c42dabd89bdea","9425e8e39fa8a7212cdd07f0917cb3dfde38a90b87297de2c82a5850aff1e4de","30448686ec900d5213d74f08f0d2b7924c5336a29445b2a434aba8d8b19d7530") by Processes.dest Processes.process Processes.process_name host | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let Hashes = dynamic([
  "021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845",
  "363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34",
  "8421c902364980e3d762ec6dbbe6b0f40577c27bd79b48c57d098328b2533109",
  "644fc49fa1006a2a2acace694e5fb83753164e2617051ece6d9dc9ea32329e70",
  "9053e8ddaecca1f960c041c944ca8799fc71dc86a4b50d2639ee4e0d2cb82f47",
  "b60074d1ea2008a581f432f2dee5f84f78668d9dd8e66f75d03c42dabd89bdea",
  "9425e8e39fa8a7212cdd07f0917cb3dfde38a90b87297de2c82a5850aff1e4de",
  "30448686ec900d5213d74f08f0d2b7924c5336a29445b2a434aba8d8b19d7530"]);
DeviceFileEvents
| where Timestamp > ago(60d)
| where SHA256 in (Hashes)
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, FileOriginUrl, FileOriginReferrerUrl, InitiatingProcessFileName
| union (DeviceProcessEvents
    | where Timestamp > ago(60d)
    | where SHA256 in (Hashes)
    | project Timestamp, DeviceName, ActionType="ProcessCreated", FolderPath, FileName, SHA256, FileOriginUrl="", FileOriginReferrerUrl="", InitiatingProcessFileName)
| order by Timestamp desc
```

### Non-Chrome process modifies macOS Chrome Preferences (FlutterShell browser hijack)

`UC_141_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.process_path) as proc_path from datamodel=Endpoint.Filesystem where Filesystem.file_path="*/Library/Application Support/Google/Chrome/*" (Filesystem.file_name="Preferences" OR Filesystem.file_name="Secure Preferences" OR Filesystem.file_name="Local State") NOT (Filesystem.process_name IN ("Google Chrome","Google Chrome Helper","Google Chrome Helper (Renderer)","chrome","chrome_crashpad_handler")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.process_name host | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath contains "/Library/Application Support/Google/Chrome/"
| where FileName in ("Preferences","Secure Preferences","Local State")
| where ActionType in ("FileModified","FileCreated")
| where InitiatingProcessFileName !in~ ("Google Chrome","Google Chrome Helper","Google Chrome Helper (Renderer)","Google Chrome Helper (GPU)","chrome","chrome_crashpad_handler")
| where InitiatingProcessFolderPath !startswith "/Applications/Google Chrome.app/"
| where InitiatingProcessFolderPath !contains "jamf" and InitiatingProcessFolderPath !contains "intune" and InitiatingProcessFileName !in~ ("managedsoftwareupdate","munki")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessSHA256,
          InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### FlutterShell adware redirector contact (ads-parkpro / sinterfumesco / softwe.art)

`UC_141_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_host IN ("sinterfumesco.com","ads-parkpro.com","adsparkpro.top","adsparkpro.net","softwe.art","*.sinterfumesco.com","*.ads-parkpro.com","*.adsparkpro.top","*.adsparkpro.net","*.softwe.art") by All_Traffic.src All_Traffic.dest_host All_Traffic.user host | `drop_dm_object_name(All_Traffic)` | appendpipe [| tstats summariesonly=t count from datamodel=Web.Web where Web.url IN ("*sinterfumesco.com*","*ads-parkpro.com*","*adsparkpro.top*","*adsparkpro.net*","*softwe.art*") by Web.src Web.url Web.http_referrer host | `drop_dm_object_name(Web)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let Redirectors = dynamic(["sinterfumesco.com","ads-parkpro.com","adsparkpro.top","adsparkpro.net","softwe.art"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (Redirectors)
   or RemoteUrl endswith ".sinterfumesco.com"
   or RemoteUrl endswith ".ads-parkpro.com"
   or RemoteUrl endswith ".adsparkpro.top"
   or RemoteUrl endswith ".adsparkpro.net"
   or RemoteUrl endswith ".softwe.art"
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `atsheisdomestic.org`, `etoftheappyrince.org`, `healightejustb.org`, `sinterfumesco.com`, `ads-parkpro.com`, `adsparkpro.top`, `adsparkpro.net`, `softwe.art`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845`, `363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34`, `8421c902364980e3d762ec6dbbe6b0f40577c27bd79b48c57d098328b2533109`, `644fc49fa1006a2a2acace694e5fb83753164e2617051ece6d9dc9ea32329e70`, `9053e8ddaecca1f960c041c944ca8799fc71dc86a4b50d2639ee4e0d2cb82f47`, `b60074d1ea2008a581f432f2dee5f84f78668d9dd8e66f75d03c42dabd89bdea`, `9425e8e39fa8a7212cdd07f0917cb3dfde38a90b87297de2c82a5850aff1e4de`, `30448686ec900d5213d74f08f0d2b7924c5336a29445b2a434aba8d8b19d7530` _(+1 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
