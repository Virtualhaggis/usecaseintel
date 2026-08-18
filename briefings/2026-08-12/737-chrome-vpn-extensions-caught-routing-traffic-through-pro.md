# [HIGH] 737 Chrome VPN Extensions Caught Routing Traffic Through Proxies. Check If You Have One

**Source:** The Hacker News
**Published:** 2026-08-12
**Article:** https://thehackernews.com/2026/08/737-chrome-vpn-extensions-caught.html

## Threat Profile

737 Chrome VPN Extensions Caught Routing Traffic Through Proxies. Check If You Have One 
 Ravie Lakshmanan  Aug 12, 2026 Browser Security / Privacy 
A massive set of 737 free VPN and proxy extensions have been found to mainly target Russian-speaking users seeking access to blocked services with an aim to intercept browser traffic and route them through a proxy infrastructure.
The extensions, published across at least 40 Chrome Web Store developer accounts, racked up 75,486 installs. Of those i…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `212.192.14.75`
- **IPv4 (defanged):** `103.35.189.225`
- **IPv4 (defanged):** `103.35.191.173`
- **IPv4 (defanged):** `147.45.60.241`
- **IPv4 (defanged):** `147.45.60.252`
- **IPv4 (defanged):** `178.130.47.43`
- **IPv4 (defanged):** `178.130.47.44`
- **IPv4 (defanged):** `178.130.47.50`
- **IPv4 (defanged):** `178.130.47.129`
- **IPv4 (defanged):** `185.252.215.97`
- **IPv4 (defanged):** `185.252.215.98`
- **IPv4 (defanged):** `194.150.220.163`
- **IPv4 (defanged):** `45.89.110.227`
- **IPv4 (defanged):** `5.180.30.15`
- **IPv4 (defanged):** `5.180.30.122`
- **IPv4 (defanged):** `80.92.204.33`
- **IPv4 (defanged):** `80.92.204.47`
- **IPv4 (defanged):** `80.92.206.84`
- **IPv4 (defanged):** `86.104.74.110`
- **IPv4 (defanged):** `94.131.118.39`
- **IPv4 (defanged):** `94.131.118.237`
- **IPv4 (defanged):** `138.124.244.206`
- **IPv4 (defanged):** `130.17.1.19`
- **IPv4 (defanged):** `78.153.155.112`
- **IPv4 (defanged):** `81.90.31.73`
- **IPv4 (defanged):** `95.163.244.138`
- **IPv4 (defanged):** `158.160.228.178`
- **Domain (defanged):** `myxavpn.pro`
- **Domain (defanged):** `myxavpn.com`
- **Domain (defanged):** `myxavpn.space`
- **Domain (defanged):** `myxasafe.space`
- **Domain (defanged):** `myxasecure.space`
- **Domain (defanged):** `vpn-myxa.ru`
- **Domain (defanged):** `vpnmyxa.site`
- **Domain (defanged):** `vpnmyha.shop`
- **Domain (defanged):** `atlasvpn.space`
- **Domain (defanged):** `bezopasnet.space`
- **Domain (defanged):** `cipherway.space`
- **Domain (defanged):** `cloudmask.space`
- **Domain (defanged):** `echosecure.space`
- **Domain (defanged):** `gusenvpn.online`
- **Domain (defanged):** `horizonguard.space`
- **Domain (defanged):** `internetprvpn.ru`
- **Domain (defanged):** `ironproxy.space`
- **Domain (defanged):** `korovkavpn.space`
- **Domain (defanged):** `maskirovka.space`
- **Domain (defanged):** `murvpn.space`
- **Domain (defanged):** `neoncloak.space`
- **Domain (defanged):** `netroutehub.space`
- **Domain (defanged):** `nimbusshield.space`
- **Domain (defanged):** `osavpn.su`
- **Domain (defanged):** `primeproxy.space`
- **Domain (defanged):** `routekeeper.space`
- **Domain (defanged):** `securepulse.space`
- **Domain (defanged):** `shershvpn.space`
- **Domain (defanged):** `skorostvpn.space`
- **Domain (defanged):** `turbotunnel.space`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1090.002** — Proxy: External Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Browser egress to Myxa SOCKS5 proxy infrastructure (known IPs)

`UC_66_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("212.192.14.75","103.35.189.225","103.35.191.173","147.45.60.241","147.45.60.252","178.130.47.43","178.130.47.44","178.130.47.50","178.130.47.129","185.252.215.97","185.252.215.98","194.150.220.163","45.89.110.227","5.180.30.15","5.180.30.122","80.92.204.33","80.92.204.47","80.92.206.84","86.104.74.110","94.131.118.39") by All_Traffic.src, All_Traffic.user, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let ProxyIPs = dynamic(["212.192.14.75","103.35.189.225","103.35.191.173","147.45.60.241","147.45.60.252","178.130.47.43","178.130.47.44","178.130.47.50","178.130.47.129","185.252.215.97","185.252.215.98","194.150.220.163","45.89.110.227","5.180.30.15","5.180.30.122","80.92.204.33","80.92.204.47","80.92.206.84","86.104.74.110","94.131.118.39"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in (ProxyIPs)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine
| order by Timestamp desc
```

### DNS/connection to Myxa fake-VPN impersonation domains

`UC_66_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("myxavpn.pro","myxavpn.com","myxavpn.space","myxasafe.space","myxasecure.space","vpn-myxa.ru","vpnmyxa.site","vpnmyha.shop","atlasvpn.space","bezopasnet.space","cipherway.space","cloudmask.space","echosecure.space","gusenvpn.online","horizonguard.space","internetprvpn.ru","ironproxy.space","korovkavpn.space","maskirovka.space","murvpn.space") by DNS.src, DNS.query, DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let BadDomains = dynamic(["myxavpn.pro","myxavpn.com","myxavpn.space","myxasafe.space","myxasecure.space","vpn-myxa.ru","vpnmyxa.site","vpnmyha.shop","atlasvpn.space","bezopasnet.space","cipherway.space","cloudmask.space","echosecure.space","gusenvpn.online","horizonguard.space","internetprvpn.ru","ironproxy.space","korovkavpn.space","maskirovka.space","murvpn.space"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (BadDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Browser-initiated SOCKS5 to TCP/1082 — new proxy infrastructure

`UC_66_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=1082 (All_Traffic.app="chrome.exe" OR All_Traffic.app="msedge.exe" OR All_Traffic.app="brave.exe" OR All_Traffic.app="opera.exe" OR All_Traffic.app="vivaldi.exe") NOT All_Traffic.dest_ip IN ("212.192.14.75","103.35.189.225","103.35.191.173","147.45.60.241","147.45.60.252","178.130.47.43","178.130.47.44","178.130.47.50","178.130.47.129","185.252.215.97","185.252.215.98","194.150.220.163","45.89.110.227","5.180.30.15","5.180.30.122","80.92.204.33","80.92.204.47","80.92.206.84","86.104.74.110","94.131.118.39") by All_Traffic.src, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - firstTime
```

**Defender KQL:**
```kql
let KnownProxyIPs = dynamic(["212.192.14.75","103.35.189.225","103.35.191.173","147.45.60.241","147.45.60.252","178.130.47.43","178.130.47.44","178.130.47.50","178.130.47.129","185.252.215.97","185.252.215.98","194.150.220.163","45.89.110.227","5.180.30.15","5.180.30.122","80.92.204.33","80.92.204.47","80.92.206.84","86.104.74.110","94.131.118.39"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort == 1082
| where RemoteIPType == "Public"
| where RemoteIP !in (KnownProxyIPs)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","brave.exe","opera.exe","vivaldi.exe")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Conns=count(), Hosts=dcount(DeviceName) by RemoteIP, InitiatingProcessFileName
| order by FirstSeen desc
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

### Article-specific behavioural hunt — 737 Chrome VPN Extensions Caught Routing Traffic Through Proxies. Check If You H

`UC_66_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — 737 Chrome VPN Extensions Caught Routing Traffic Through Proxies. Check If You H ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_path="*C:\Users\ollob\OneDrive\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Users\ollob\OneDrive\*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — 737 Chrome VPN Extensions Caught Routing Traffic Through Proxies. Check If You H
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FolderPath has_any ("C:\Users\ollob\OneDrive\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Users\ollob\OneDrive\"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `212.192.14.75`, `103.35.189.225`, `103.35.191.173`, `147.45.60.241`, `147.45.60.252`, `178.130.47.43`, `178.130.47.44`, `178.130.47.50` _(+49 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
