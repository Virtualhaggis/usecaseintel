# [MED] Hackers Use Weaponized DMG Files to Target macOS Users With Infostealer Malware

**Source:** Cyber Security News
**Published:** 2026-06-11
**Article:** https://cybersecuritynews.com/hackers-use-weaponized-dmg-files/

## Threat Profile

Hackers are using weaponized DMG files to target macOS users with infostealer malware, exploiting the long-standing myth that Apple devices are safe from cyber threats. These attacks rely on fake software installers disguised as legitimate apps, tricking users into handing over access without raising any alarm. The speed of these campaigns has made them one [&#8230;] The post Hackers Use Weaponized DMG Files to Target macOS Users With Infostealer Malware appeared first on Cyber Security News .

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `95.85.251.177`
- **IPv4 (defanged):** `45.94.47.204`
- **IPv4 (defanged):** `138.124.93.32`
- **IPv4 (defanged):** `168.100.9.122`
- **IPv4 (defanged):** `199.217.98.33`
- **IPv4 (defanged):** `38.244.158.103`
- **IPv4 (defanged):** `38.244.158.56`
- **IPv4 (defanged):** `92.246.136.14`
- **Domain (defanged):** `cleanmymacos.org`
- **Domain (defanged):** `domenpozh.net`
- **Domain (defanged):** `rapidfilevault4.sbs`
- **Domain (defanged):** `rapidfilevault5.sbs`
- **Domain (defanged):** `rapidfilevault4.cyou`
- **Domain (defanged):** `coco-fun2.com`
- **Domain (defanged):** `nitlebuf.com`
- **Domain (defanged):** `yablochnisok.com`
- **Domain (defanged):** `mentaorb.com`
- **Domain (defanged):** `seagalnssteavens.com`
- **Domain (defanged):** `filefastdata.com`
- **Domain (defanged):** `metramon.com`
- **Domain (defanged):** `octopixeldate.com`
- **Domain (defanged):** `datasphere.us.com`
- **Domain (defanged):** `cauterizespray.icu`
- **Domain (defanged):** `enslaveculprit.digital`
- **Domain (defanged):** `resilientlimb.icu`
- **Domain (defanged):** `thickentributary.digital`
- **Domain (defanged):** `paralegalmustang.icu`
- **Domain (defanged):** `round5on.digital`
- **Domain (defanged):** `apexharvestor.digital`
- **Domain (defanged):** `0x666.info`
- **Domain (defanged):** `honestly.ink`
- **Domain (defanged):** `pla7ina.cfd`
- **Domain (defanged):** `play67.cc`
- **Domain (defanged):** `rvdownloads.com`
- **Domain (defanged):** `avipstudios.com`
- **Domain (defanged):** `joytion.com`
- **Domain (defanged):** `laislivon.com`
- **Domain (defanged):** `swift-sh.com`
- **SHA256:** `9d2da07aa6e7db3fbc36b36f0cfd74f78d5815f5ba55d0f0405cdd668bd13767`
- **SHA256:** `7ca42f1f23dbdc9427c9f135815bb74708a7494ea78df1fbc0fc348ba2a161ae`
- **SHA256:** `241a50befcf5c1aa6dab79664e2ba9cb373cc351cb9de9c3699fd2ecb2afab05`
- **SHA256:** `522fdfaff44797b9180f36c654f77baf5cdeaab861bbf372ccfc1a5bd920d62e`

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
  - IP / domain IOC(s): `95.85.251.177`, `45.94.47.204`, `138.124.93.32`, `168.100.9.122`, `199.217.98.33`, `38.244.158.103`, `38.244.158.56`, `92.246.136.14` _(+30 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9d2da07aa6e7db3fbc36b36f0cfd74f78d5815f5ba55d0f0405cdd668bd13767`, `7ca42f1f23dbdc9427c9f135815bb74708a7494ea78df1fbc0fc348ba2a161ae`, `241a50befcf5c1aa6dab79664e2ba9cb373cc351cb9de9c3699fd2ecb2afab05`, `522fdfaff44797b9180f36c654f77baf5cdeaab861bbf372ccfc1a5bd920d62e`


## Why this matters

Severity classified as **MED** based on: IOCs present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
