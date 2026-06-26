# [HIGH] Chrome Ad Blocker with 10M+ Installs Found with Dormant Script Injection Capability

**Source:** The Hacker News
**Published:** 2026-06-25
**Article:** https://thehackernews.com/2026/06/chrome-ad-blocker-with-10m-installs.html

## Threat Profile

Chrome Ad Blocker with 10M+ Installs Found with Dormant Script Injection Capability 
 Ravie Lakshmanan  Jun 25, 2026 Browser Security / Malware 
An analysis of a popular Google Chrome ad block extension for YouTube has uncovered the ability to execute arbitrary JavaScript code.
According to Island, the extension, named Adblock for YouTube (ID: cmedhionkhpnakcndndgjdbohmhepckk), has more than 10 million installs and carries a Featured badge on the Chrome Web Store.
The extension description sta…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `api.adblock-for-youtube.com`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1071** — Application Layer Protocol
- **T1185** — Browser Session Hijacking
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Risky/removed Chrome ad-block extension IDs present on endpoint (Island 'Adblock for YouTube' set)

`UC_23_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*cmedhionkhpnakcndndgjdbohmhepckk*" OR Filesystem.file_path="*onomjaelhagjjojbkcafidnepbfkpnee*" OR Filesystem.file_path="*ogcaehilgakehloljjmajoempaflmdci*" OR Filesystem.file_path="*gekoepiplklhniacchbbgbhilidiojmb*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let extIds = dynamic(["cmedhionkhpnakcndndgjdbohmhepckk","onomjaelhagjjojbkcafidnepbfkpnee","ogcaehilgakehloljjmajoempaflmdci","gekoepiplklhniacchbbgbhilidiojmb"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (extIds)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","brave.exe","chrome_proxy.exe","opera.exe")
| extend MatchedExtId = extract(@"(cmedhionkhpnakcndndgjdbohmhepckk|onomjaelhagjjojbkcafidnepbfkpnee|ogcaehilgakehloljjmajoempaflmdci|gekoepiplklhniacchbbgbhilidiojmb)", 1, FolderPath)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), FileWrites=count(), SampleFolder=any(FolderPath) by DeviceName, InitiatingProcessAccountName, MatchedExtId
| order by LastSeen desc
```

### Browser beacon to Adblock for YouTube config/activation backend (api.adblock-for-youtube.com)

`UC_23_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*adblock-for-youtube.com*" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "adblock-for-youtube.com"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","brave.exe","opera.exe")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Connections=count(), Hosts=dcount(DeviceName), RemoteIPs=make_set(RemoteIP, 10) by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RemoteUrl
| order by LastSeen desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `api.adblock-for-youtube.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
