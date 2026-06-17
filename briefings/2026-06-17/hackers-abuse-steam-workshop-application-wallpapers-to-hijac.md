# [MED] Hackers Abuse Steam Workshop Application Wallpapers to Hijack Active Steam Sessions

**Source:** Cyber Security News
**Published:** 2026-06-17
**Article:** https://cybersecuritynews.com/steam-workshop-abused/

## Threat Profile

Threat actors have been abusing Valve&#8217;s Steam Workshop since late 2025, embedding malware inside Wallpaper Engine application wallpapers to hijack active Steam sessions and infect victims with backdoors, infostealers, and crypto miners, with 89% of targets located in China, according to a new Kaspersky report. Wallpaper Engine is a hugely popular Steam application that lets [&#8230;] The post Hackers Abuse Steam Workshop Application Wallpapers to Hijack Active Steam Sessions appeared first…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `202.144.192.29`
- **IPv4 (defanged):** `120.48.156.17`
- **Domain (defanged):** `brightly.to`
- **MD5:** `95856f2ce428c728d9781d3296558068`
- **MD5:** `af080780cca2acd1d082ce01e7cc346a`
- **MD5:** `c133c3dd9f7d6934598025047df41abf`
- **MD5:** `d1693bbff456ae8fa3360446706df6da`
- **MD5:** `8c2cc585ad8a13a72a704c0fda0c9854`
- **MD5:** `b9fa763a53da3eea742d0f3c845a8c09`
- **MD5:** `ded08ae5df7f1b12e5fdb767dbbed0b1`
- **MD5:** `20965254e29104986e11939decd39549`
- **MD5:** `18dedc0009f0927cba6425c84cce9883`
- **MD5:** `0f4f01c6d495abb37403072dd017ce8d`
- **MD5:** `5620f01284329f561b1839a36be55355`
- **MD5:** `fe1f6485013cd5e6d5cf718049b0b8d6`
- **MD5:** `74414ed4b63aadec039b603c32762b80`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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
  - IP / domain IOC(s): `202.144.192.29`, `120.48.156.17`, `brightly.to`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `95856f2ce428c728d9781d3296558068`, `af080780cca2acd1d082ce01e7cc346a`, `c133c3dd9f7d6934598025047df41abf`, `d1693bbff456ae8fa3360446706df6da`, `8c2cc585ad8a13a72a704c0fda0c9854`, `b9fa763a53da3eea742d0f3c845a8c09`, `ded08ae5df7f1b12e5fdb767dbbed0b1`, `20965254e29104986e11939decd39549` _(+5 more)_


## Why this matters

Severity classified as **MED** based on: IOCs present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
