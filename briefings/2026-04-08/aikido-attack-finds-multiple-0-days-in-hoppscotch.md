# [HIGH] Aikido Attack finds multiple 0-days in Hoppscotch

**Source:** Aikido
**Published:** 2026-04-08
**Article:** https://www.aikido.dev/blog/ai-pentest-hoppscotch-vulnerabilities

## Threat Profile

Blog Vulnerabilities & Threats Aikido Attack finds multiple 0-days in Hoppscotch Aikido Attack finds multiple 0-days in Hoppscotch Written by Robbe Verwilghen Published on: Apr 8, 2026 Introduction Hoppscotch is an open-source API development ecosystem, similar to Postman, with over 100,000 monthly users. Two weeks ago, we set up a self-hosted instance and ran our AI pentest agents against it. They found two high-severity vulnerabilities and one medium-severity vulnerability, all present in vers…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Phishing: Spearphishing Link
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1185** — Browser Session Hijacking

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Hoppscotch device-login open redirect exploitation (GHSA-7fg7-wx5q-6m3v)

`UC_285_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.user) as user values(Web.http_user_agent) as ua values(Web.url) as url from datamodel=Web where (Web.url="*/device-login*") Web.url="*redirect_uri=*" (Web.url="*redirect_uri=http://localhost.*" OR Web.url="*redirect_uri=https://localhost.*" OR Web.url="*redirect_uri=http%3A%2F%2Flocalhost.*" OR Web.url="*redirect_uri=https%3A%2F%2Flocalhost.*" OR Web.url="*redirect_uri=http%3A%2F%2Flocalhost%2E*" OR Web.url="*redirect_uri=https%3A%2F%2Flocalhost%2E*") by Web.dest, Web.url | `drop_dm_object_name(Web)` | rex field=url "(?i)redirect_uri=(?<redirect_target>[^&]+)" | eval redirect_decoded=urldecode(redirect_target) | where match(redirect_decoded, "(?i)^https?://localhost\.[a-zA-Z0-9.\-]+") | convert ctime(firstTime) ctime(lastTime) | table firstTime, lastTime, src, user, ua, dest, url, redirect_decoded
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let UrlPattern = DeviceNetworkEvents
    | where Timestamp > ago(LookbackDays)
    | where RemoteUrl has "device-login"
    | where RemoteUrl has "redirect_uri"
    | extend Decoded = url_decode(RemoteUrl)
    | where Decoded matches regex @"(?i)redirect_uri=https?://localhost\.[a-zA-Z0-9.\-]+"
    | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, Indicator = RemoteUrl, Signal = "device-login URL with localhost.<subdomain> redirect_uri";
let DnsExfil = DeviceEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tolower(tostring(parse_json(AdditionalFields).QueryName))
    | where Q startswith "localhost."
    | where Q !endswith ".localdomain" and Q !endswith ".local" and Q != "localhost."
    | where Q endswith ".sslip.io" or Q endswith ".nip.io" or Q matches regex @"^localhost\.[a-z0-9\-]+\.[a-z]{2,}$"
    | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, Indicator = Q, Signal = "DNS resolution of localhost.<attacker-subdomain> (Hoppscotch token-exfil channel)";
union isfuzzy=true UrlPattern, DnsExfil
| order by Timestamp desc
```

### [LLM] Hoppscotch Mock Server stored XSS via GraphQL response-header injection

`UC_285_4` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.user) as user values(Web.url) as url values(Web.http_user_agent) as ua values(Web.form_data) as body from datamodel=Web where Web.http_method=POST (Web.url="*/graphql*" OR Web.url="*/v1/graphql*") Web.form_data="*updateRESTUserRequest*" Web.form_data="*content-type*" Web.form_data="*text/html*" by Web.dest | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | table firstTime, lastTime, src, user, dest, url, ua, body
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


## Why this matters

Severity classified as **HIGH** based on: 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
