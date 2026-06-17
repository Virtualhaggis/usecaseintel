# [MED] Hackers Use Fake Software Update Prompts to Steal Passwords and Crypto Wallet Data From macOS Users

**Source:** Cyber Security News
**Published:** 2026-06-17
**Article:** https://cybersecuritynews.com/hackers-use-fake-software-update-prompts/

## Threat Profile

A dangerous new cyber campaign is putting macOS users at serious risk, and it does not rely on software bugs to do its damage. Instead, the attackers trick people into handing over their own passwords and sensitive data by making everything look completely normal. What appears to be a routine software update turns out to [&#8230;] The post Hackers Use Fake Software Update Prompts to Steal Passwords and Crypto Wallet Data From macOS Users appeared first on Cyber Security News .

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `83.136.208.246`
- **IPv4 (defanged):** `188.227.196.252`
- **IPv4 (defanged):** `83.136.209.22`
- **IPv4 (defanged):** `83.136.208.48`
- **IPv4 (defanged):** `83.136.210.180`
- **IPv4 (defanged):** `104.145.210.107`
- **IPv4 (defanged):** `188.227.197.136`
- **Domain (defanged):** `uw04webzoom.us`
- **Domain (defanged):** `uw05webzoom.us`
- **Domain (defanged):** `uw03webzoom.us`
- **Domain (defanged):** `ur01webzoom.us`
- **Domain (defanged):** `uv01webzoom.us`
- **Domain (defanged):** `uv03webzoom.us`
- **Domain (defanged):** `uv04webzoom.us`
- **Domain (defanged):** `ux06webzoom.us`
- **Domain (defanged):** `check02id.com`
- **Domain (defanged):** `termsliva.com`
- **SHA256:** `2075fd1a1362d188290910a8c55cf30c11ed5955c04af410c481410f538da419`
- **SHA256:** `980bf65c703edae7b28a752207a84b80332be0dae4ee87f00928f82a011ab0ce`
- **SHA256:** `05e1761b535537287e7b72d103a29c4453742725600f59a34a4831eafc0b8e53`
- **SHA256:** `3e6fcace412827b14d4af9fc7ca1b8867f75f40c589f3fdca50e988466f00279`
- **SHA256:** `5f457c492773b832054d007ba94d2e89c22dac8458dc9dc1b1d91896777c0c9f`
- **SHA256:** `97ccc28808d2c21b83f24835744af754920a992e57216d2cbc8315664905b0e2`
- **SHA256:** `5fbbca2d72840feb86b6ef8a1abb4fe2f225d84228a714391673be2719c73ac7`
- **SHA256:** `5e581f22f56883ee13358f73fabab00fcf9313a053210eb12ac18e66098346e5`
- **SHA256:** `8fd5b8db10458ace7e4ed335eb0c66527e1928ad87a3c688595804f72b205e8c`
- **SHA256:** `a05400000843fbad6b28d2b76fc201c3d415a72d88d8dc548fafd8bae073c640`

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
  - IP / domain IOC(s): `83.136.208.246`, `188.227.196.252`, `83.136.209.22`, `83.136.208.48`, `83.136.210.180`, `104.145.210.107`, `188.227.197.136`, `uw04webzoom.us` _(+9 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `2075fd1a1362d188290910a8c55cf30c11ed5955c04af410c481410f538da419`, `980bf65c703edae7b28a752207a84b80332be0dae4ee87f00928f82a011ab0ce`, `05e1761b535537287e7b72d103a29c4453742725600f59a34a4831eafc0b8e53`, `3e6fcace412827b14d4af9fc7ca1b8867f75f40c589f3fdca50e988466f00279`, `5f457c492773b832054d007ba94d2e89c22dac8458dc9dc1b1d91896777c0c9f`, `97ccc28808d2c21b83f24835744af754920a992e57216d2cbc8315664905b0e2`, `5fbbca2d72840feb86b6ef8a1abb4fe2f225d84228a714391673be2719c73ac7`, `5e581f22f56883ee13358f73fabab00fcf9313a053210eb12ac18e66098346e5` _(+2 more)_


## Why this matters

Severity classified as **MED** based on: IOCs present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
