# [MED] New Lucid Stealer Targets 18 Browsers, Crypto Wallets, and Discord Tokens With Hidden Remote Access

**Source:** Cyber Security News
**Published:** 2026-06-08
**Article:** https://cybersecuritynews.com/lucid-stealer-targets-18-browsers-crypto-wallets-and-discord-tokens/

## Threat Profile

A newly identified piece of Windows malware is raising serious concerns among cybersecurity professionals for its wide reach and unusually deep set of capabilities. Discovered through underground channels linked to Telegram, the threat known as Lucid Stealer goes far beyond stealing a few stored passwords. It can take full control of an infected machine without [&#8230;] The post New Lucid Stealer Targets 18 Browsers, Crypto Wallets, and Discord Tokens With Hidden Remote Access appeared first on…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `45.138.16.107`
- **IPv4 (defanged):** `85.239.155.68`
- **Domain (defanged):** `lucidstealer.one`
- **Domain (defanged):** `iloveyoulucid.space`
- **Domain (defanged):** `ghdfhfjhfg.webhop.me`
- **Domain (defanged):** `0kt.one`
- **Domain (defanged):** `storedonutsmp.net`
- **SHA256:** `a380e66f381c9f88f4f221906f12b73e1f43517c8e5f6affcaca71fad3340d5f`
- **SHA256:** `101351cff5f971cd39bd6280be02a5e0e8f08d9874cae78b971e3a421a7050f6`
- **SHA256:** `8422c48d6301426a39bf9b3d7f11bdbee7708e8a4e58171f38a5b5e51a8a53b8`
- **SHA256:** `cad3f0dde70a5d37c996abee75f39aff8e7603862f071a8c85cb48ee5482750f`
- **SHA256:** `5e33fe030fb7c3bbe2bca1f70f21a406716961aefdfb1bc030d7c65b7db055e9`
- **SHA256:** `fc52b15848191ad97213d49c7f3c21760e1cc9507d5fb0d77fa75b7620c0deac`
- **SHA256:** `6fb83f431f43d7b13e411676cdaa98d8ce005ffd61eed9d1d117698476acfb44`
- **SHA256:** `18e61b06068a8dd71e19ed3b117e4b0800f6dfbf252f381961dbb15b44ecc481`
- **SHA256:** `f85e5b19198cc4800be76346bb2868abdd45acbb314968cf2fe41cb18b502bfa`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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
  - IP / domain IOC(s): `45.138.16.107`, `85.239.155.68`, `lucidstealer.one`, `iloveyoulucid.space`, `ghdfhfjhfg.webhop.me`, `0kt.one`, `storedonutsmp.net`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `a380e66f381c9f88f4f221906f12b73e1f43517c8e5f6affcaca71fad3340d5f`, `101351cff5f971cd39bd6280be02a5e0e8f08d9874cae78b971e3a421a7050f6`, `8422c48d6301426a39bf9b3d7f11bdbee7708e8a4e58171f38a5b5e51a8a53b8`, `cad3f0dde70a5d37c996abee75f39aff8e7603862f071a8c85cb48ee5482750f`, `5e33fe030fb7c3bbe2bca1f70f21a406716961aefdfb1bc030d7c65b7db055e9`, `fc52b15848191ad97213d49c7f3c21760e1cc9507d5fb0d77fa75b7620c0deac`, `6fb83f431f43d7b13e411676cdaa98d8ce005ffd61eed9d1d117698476acfb44`, `18e61b06068a8dd71e19ed3b117e4b0800f6dfbf252f381961dbb15b44ecc481` _(+1 more)_


## Why this matters

Severity classified as **MED** based on: IOCs present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
