# [HIGH] New XCSSET variant targets macOS devs via compromised Xcode projects

**Source:** BleepingComputer
**Published:** 2026-08-04
**Article:** https://www.bleepingcomputer.com/news/security/new-xcsset-variant-targets-macos-devs-via-compromised-xcode-projects/

## Threat Profile

New XCSSET variant targets macOS devs via compromised Xcode projects 
By Bill Toulas 
August 4, 2026
03:03 PM
0 
A new version of the XCSSET malware is targeting thousands of macOS users through compromised Xcode projects and GitHub repositories.
Xcode is the official software development kit (SDK) for creating, testing, and publishing software for all Apple's platforms.
After months of inactivity, XCSSET has resurfaced with an updated version, v40, that features enhanced evasion techniques and …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `91.108.106.229`
- **IPv4 (defanged):** `95.142.35.34`
- **IPv4 (defanged):** `95.142.35.206`
- **IPv4 (defanged):** `95.142.37.159`
- **IPv4 (defanged):** `151.243.109.188`
- **IPv4 (defanged):** `178.208.92.129`
- **IPv4 (defanged):** `178.208.92.168`
- **Domain (defanged):** `amzndev.in`
- **Domain (defanged):** `amzndev.ru`
- **Domain (defanged):** `googlenets.ru`
- **Domain (defanged):** `netcdndev.in`
- **Domain (defanged):** `whitead.in`
- **Domain (defanged):** `whiteads.ru`
- **Domain (defanged):** `accapple.ru`
- **Domain (defanged):** `adschecks.ru`
- **Domain (defanged):** `adsmobi.ru`
- **Domain (defanged):** `amdcdn.ru`
- **Domain (defanged):** `amznprod.in`
- **Domain (defanged):** `applecdn.ru`
- **Domain (defanged):** `appledisk.ru`
- **Domain (defanged):** `appledns.ru`
- **Domain (defanged):** `applehosts.ru`
- **Domain (defanged):** `bulksec.ru`
- **Domain (defanged):** `cdnamz.in`
- **Domain (defanged):** `cdnamz.ru`
- **Domain (defanged):** `cdnapple.in`
- **Domain (defanged):** `cdnroute.ru`
- **Domain (defanged):** `checkcdn.ru`
- **Domain (defanged):** `chromeads.ru`
- **Domain (defanged):** `devnetaps.ru`
- **Domain (defanged):** `dnsapple.ru`
- **Domain (defanged):** `dnsrelays.ru`
- **Domain (defanged):** `explorecdn.ru`
- **Domain (defanged):** `icloudsnet.ru`
- **Domain (defanged):** `netcdnamz.ru`
- **Domain (defanged):** `networkads.in`
- **Domain (defanged):** `windsecure.ru`
- **SHA1:** `6e480d648fa1b70612f5d198a66875e28847547d`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1027** — Obfuscated Files or Information
- **T1185** — Browser Session Hijacking
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1553.001** — Subvert Trust Controls: Gatekeeper Bypass
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1571** — Non-Standard Port
- **T1554** — Compromise Host Software Binary
- **T1059.002** — Command and Scripting Interpreter: AppleScript
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Chrome launched with DevTools/remote-debugging port by shell launcher (XCSSET v40 browser hijack)

`UC_24_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*--remote-debugging-port*" OR Processes.process="*--remote-debugging-pipe*") AND (Processes.process_name="Google Chrome" OR Processes.process="*Google Chrome.app*") AND (Processes.parent_process_name IN ("bash","zsh","sh","osascript") OR Processes.parent_process="*/tmp/*" OR Processes.parent_process="*/var/folders/*") AND NOT Processes.process="*--headless*" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "Google Chrome" or FolderPath has "Google Chrome.app"
| where ProcessCommandLine has_any ("--remote-debugging-port","--remote-debugging-pipe")
| where ProcessCommandLine !has "--headless"
| where InitiatingProcessFileName in~ ("bash","sh","zsh","osascript") or InitiatingProcessFolderPath has "/tmp/" or InitiatingProcessFolderPath has "/var/folders/"
| where not(InitiatingProcessCommandLine has_any ("puppeteer","playwright","selenium","chromedriver"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### macOS security tooling sabotage: tccutil reset + CloudTelemetryService kill + XProtect/softwareupdate tamper (XCSSET v40)

`UC_24_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*tccutil*reset*" OR Processes.process="*CloudTelemetryService*" OR (Processes.process="*spctl*" AND Processes.process="*disable*") OR (Processes.process="*softwareupdate*" AND Processes.process="*XProtect*") OR (Processes.process="*XProtect*" AND Processes.process="*ignore*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "tccutil" and ProcessCommandLine has "reset")
    or (FileName in~ ("killall","pkill","kill") and ProcessCommandLine has "CloudTelemetryService")
    or (FileName =~ "spctl" and ProcessCommandLine has_any ("--master-disable","--global-disable"))
    or (ProcessCommandLine has "softwareupdate" and ProcessCommandLine has_any ("XProtect","XProtectFramework","MRTConfigData"))
    or ProcessCommandLine has "CloudTelemetryService"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### XCSSET v40 C2 beacon to Unit 42 IOC domains / IPs

`UC_24_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query IN ("amzndev.in","amzndev.ru","googlenets.ru","netcdndev.in","whitead.in","whiteads.ru","accapple.ru","adschecks.ru","adsmobi.ru","adsmorein.in","adsmoreme.in","amdcdn.ru","amznprod.in","applecdn.ru","appledisk.ru","appledns.ru","applehosts.ru","appletime.in","bulksec.ru","cdnamz.in")) by DNS.src DNS.dest DNS.query | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let c2domains = dynamic(["amzndev.in","amzndev.ru","googlenets.ru","netcdndev.in","whitead.in","whiteads.ru","accapple.ru","adschecks.ru","adsmobi.ru","adsmorein.in","adsmoreme.in","amdcdn.ru","amznprod.in","applecdn.ru","appledisk.ru","appledns.ru","applehosts.ru","appletime.in","bulksec.ru","cdnamz.in"]);
let c2ips = dynamic(["91.108.106.229","95.142.35.34","95.142.35.206","95.142.37.159","151.243.109.188","178.208.92.129","178.208.92.168"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (c2ips) or RemoteUrl has_any (c2domains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### XCSSET v40 Telegram trojanizer: /Applications/Telegram.app replacement + ~/.tr config drop

`UC_24_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/Applications/Telegram.app*" OR Filesystem.file_name=".tr" OR Filesystem.file_name=".tr_map") AND (Filesystem.process_name IN ("bash","sh","zsh","osascript","curl","ditto","unzip","tar") OR Filesystem.process="*/tmp/*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.action Filesystem.process_name Filesystem.process | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where (FolderPath has "/Applications/Telegram.app" and ActionType in ("FileDeleted","FileRenamed","FileCreated","FileModified"))
    or FileName in~ (".tr",".tr_map")
| where InitiatingProcessFileName in~ ("bash","sh","zsh","osascript","curl","ditto","unzip","tar") or InitiatingProcessFolderPath has "/tmp/" or InitiatingProcessFolderPath has "/var/folders/"
| where InitiatingProcessFileName !in~ ("Telegram","softwareupdated","installd","Install Telegram")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### XCSSET v40 build-time execution: Xcode-spawned osascript loader / /tmp/r payload

`UC_24_9` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*/tmp/r*" OR Processes.process="*/tmp/p.app*" OR (Processes.process_name="osascript" AND (Processes.parent_process_name="xcodebuild" OR Processes.parent_process="*Xcode.app*"))) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has_any ("/tmp/r","/tmp/p.app")
    or FolderPath in~ ("/tmp/r")
    or (FileName =~ "osascript" and (InitiatingProcessFileName in~ ("xcodebuild","Xcode") or InitiatingProcessFolderPath has "Xcode.app"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `91.108.106.229`, `95.142.35.34`, `95.142.35.206`, `95.142.37.159`, `151.243.109.188`, `178.208.92.129`, `178.208.92.168`, `amzndev.in` _(+29 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `6e480d648fa1b70612f5d198a66875e28847547d`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
