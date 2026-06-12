# [MED] Hackers Use Free Spotify Premium Hacks on TikTok and Instagram to Spread Vidar Infostealer

**Source:** Cyber Security News
**Published:** 2026-06-12
**Article:** https://cybersecuritynews.com/hackers-use-free-spotify-premium-hacks/

## Threat Profile

Hackers are now turning popular social media platforms into malware delivery channels, using the promise of free software to trap unsuspecting users. Short-form video platforms like TikTok and Instagram Reels have become the latest tools in a cybercriminal&#8217;s playbook, with attackers posting polished tutorial videos that promise free Spotify Premium, free Windows activation, or free [&#8230;] The post Hackers Use Free Spotify Premium Hacks on TikTok and Instagram to Spread Vidar Infostealer…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `pluginchad.xyz`
- **Domain (defanged):** `maxapk.xyz`
- **Domain (defanged):** `d4ug.site`
- **Domain (defanged):** `slmgr.sh`
- **Domain (defanged):** `msget.run`
- **SHA256:** `03bbc4fa1fd784276da135ab62fef85aaddea66e6eb176d7e59c3398f818b153`

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
  - IP / domain IOC(s): `pluginchad.xyz`, `maxapk.xyz`, `d4ug.site`, `slmgr.sh`, `msget.run`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `03bbc4fa1fd784276da135ab62fef85aaddea66e6eb176d7e59c3398f818b153`


## Why this matters

Severity classified as **MED** based on: IOCs present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
