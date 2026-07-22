# [HIGH] Adobe Chrome extension flaw let sites access private WhatsApp chats

**Source:** BleepingComputer
**Published:** 2026-07-22
**Article:** https://www.bleepingcomputer.com/news/security/adobe-chrome-extension-flaw-let-sites-access-private-whatsapp-chats/

## Threat Profile

Adobe Chrome extension flaw let sites access private WhatsApp chats 
By Bill Toulas 
July 22, 2026
09:22 AM
0 
The Adobe Acrobat extension for Chrome could be used to access conversations and data rendered in WhatsApp Web without any form of authentication.
The attack exploits a chain of vulnerabilities,  collectively tracked as CVE-2026-48294 and dubbed HermeticReader by researchers at cybersecurity firm Guardio.
Exploiting them requires only that the target running the Adobe Acrobat extension …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-48294`
- **Domain (defanged):** `www.google.attacker.com`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1189** — Drive-by Compromise
- **T1567** — Exfiltration Over Web Service
- **T1185** — Browser Session Hijacking

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable Adobe Acrobat Chrome extension (CVE-2026-48294 / HermeticReader) exposure

`UC_7_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities where Vulnerabilities.cve="CVE-2026-48294" by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - count
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId =~ "CVE-2026-48294"
| project Timestamp, DeviceId, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| where SoftwareVersion != "26.5.2.3"
| order by DeviceName asc
```

### Browser exfil to rare external host during active WhatsApp Web session (HermeticReader)

`UC_7_5` · phase: **actions** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web where Web.http_method=POST by Web.src Web.dest Web.url _time span=1h
| `drop_dm_object_name(Web)`
| search NOT (url IN ("*whatsapp*","*facebook*","*fbcdn*","*instagram*","*cdninstagram*","*meta.com*","*google*","*gstatic*","*googleapis*","*microsoft*","*office*","*cloudflare*","*akamai*","*fastly*"))
| join type=inner src [
    | tstats `summariesonly` count from datamodel=Web where Web.url IN ("*whatsapp*") by Web.src
    | `drop_dm_object_name(Web)`
    | fields src ]
| stats min(_time) as firstSeen count by src dest url
| sort - firstSeen
```

**Defender KQL:**
```kql
let Lookback = 7d;
let Benign = dynamic(["whatsapp","facebook","fbcdn","fbsbx","instagram","cdninstagram","meta.com","google","gstatic","googleapis","gvt1","gvt2","microsoft","office","windows.net","live.com","bing","mozilla","apple","icloud","cloudflare","akamai","fastly","doubleclick"]);
let WaSessions = DeviceNetworkEvents
    | where Timestamp > ago(Lookback)
    | where InitiatingProcessFileName =~ "chrome.exe"
    | where RemoteUrl has "whatsapp"
    | summarize by DeviceId, WaHour = bin(Timestamp, 1h);
let RareDest = DeviceNetworkEvents
    | where Timestamp between (ago(30d) .. ago(Lookback))
    | where InitiatingProcessFileName =~ "chrome.exe"
    | where RemoteIPType == "Public" and isnotempty(RemoteUrl)
    | summarize BaselineHosts = dcount(DeviceName) by RemoteUrl
    | where BaselineHosts <= 2   // 2 = org-rare threshold; attacker exfil host is unlikely to be broadly visited
    | distinct RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(Lookback)
| where InitiatingProcessFileName =~ "chrome.exe"
| where RemoteIPType == "Public" and isnotempty(RemoteUrl)
| where not(RemoteUrl has_any (Benign))
| join kind=inner RareDest on RemoteUrl
| extend WaHour = bin(Timestamp, 1h)
| join kind=inner WaSessions on DeviceId, WaHour
| summarize FirstSeen = min(Timestamp), Connections = count() by DeviceId, DeviceName, RemoteUrl
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-48294`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `www.google.attacker.com`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
