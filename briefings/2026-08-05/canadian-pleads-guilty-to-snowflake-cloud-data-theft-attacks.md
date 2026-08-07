# [HIGH] Canadian pleads guilty to Snowflake cloud data-theft attacks

**Source:** BleepingComputer
**Published:** 2026-08-05
**Article:** https://www.bleepingcomputer.com/news/security/canadian-pleads-guilty-to-snowflake-cloud-data-theft-attacks/

## Threat Profile

Canadian pleads guilty to Snowflake cloud data-theft attacks 
By Ionut Ilascu 
August 5, 2026
05:53 PM
0 
A Canadian man pleaded guilty today to his role in accessing company accounts at cloud storage provider Snowflake and stealing data from at least 165 organizations in a scheme to extort millions of dollars from victims.
​26-year-old Connor Riley Moucka, also known as Alexander Moucka and Waifu, was arrested on October 30, 2024, for stealing data of hundreds of millions of individuals from co…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `45.27.26.205`
- **IPv4 (defanged):** `37.19.210.21`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1071** — Application Layer Protocol
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1078** — Valid Accounts
- **T1567** — Exfiltration Over Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### UNC5537 Snowflake data-theft: sign-in from attacker infrastructure IPs

`UC_26_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Authentication.app) as app values(Authentication.action) as action from datamodel=Authentication where Authentication.src IN ("45.27.26.205","37.19.210.21") by Authentication.user Authentication.src Authentication.dest | `drop_dm_object_name(Authentication)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(90d)
| where IPAddress in ("45.27.26.205","37.19.210.21")
| project Timestamp, AccountUpn, AccountDisplayName, Application, AppDisplayName, IPAddress, Country, City, ErrorCode, ClientAppUsed, UserAgent
| order by Timestamp desc
```

### UNC5537 Snowflake campaign: network connection to attacker IPs

`UC_26_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic where (All_Traffic.dest IN ("45.27.26.205","37.19.210.21") OR All_Traffic.src IN ("45.27.26.205","37.19.210.21")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteIP in ("45.27.26.205","37.19.210.21")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.27.26.205`, `37.19.210.21`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
