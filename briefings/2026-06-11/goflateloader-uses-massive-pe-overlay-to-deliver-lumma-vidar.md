# [LOW] GoFlateLoader Uses Massive PE Overlay to Deliver Lumma, Vidar, and StealC Infostealers

**Source:** Cyber Security News
**Published:** 2026-06-11
**Article:** https://cybersecuritynews.com/goflateloader-uses-massive-pe-overlay/

## Threat Profile

A new malware loader called GoFlateLoader has been quietly spreading across the internet, and what makes it stand out is not how complex it is but how effective a simple trick has made it. Written in the Go programming language, this loader has one job: to decode and drop dangerous information-stealing programs onto a victim&#8217;s [&#8230;] The post GoFlateLoader Uses Massive PE Overlay to Deliver Lumma, Vidar, and StealC Infostealers appeared first on Cyber Security News .

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `b88c5744975d2abb447aecc6c090fee9f8580413f4612eecdc6ed1973e8a1739`
- **SHA256:** `ed5ae7f36453c5a23e9868a5729d67e0549a11f6dea54f5f52d654a8f51d4902`
- **SHA256:** `841c9297cb8a2e0ff89433d13c05bfc760eb2e98e251cb8fa785d2ad7cbac05f`
- **SHA256:** `ece7c48eb411b24f26762ede83badb4a644c41d5777129381ac2541804d64fc2`
- **SHA256:** `421ce2d2f49c23bbe9f60ef3b9cd38d7eb912ce02e56a61837656210069bd9e2`
- **SHA256:** `121c2dc793b3873f75a29ec02241f94136de19c049382a50a50d0d5b99507073`
- **SHA256:** `2415db5081cec9bfd14ad6da1a66169fd96f13a49010c319a73d1ed6fafd4efa`
- **SHA256:** `d9917ade3b4c125a95b5d3e6343cde26145dfbf569bd7e2a843fd0c6fc8ddc28`
- **SHA256:** `4cf6893756f441522b94b36f10e5de0e47aeed4743f95c51650746d1ecf97e3d`
- **SHA256:** `8b89d6c9152d3aab97aadd515ecb69ca72654db2f25425759ba4b646853d737d`
- **SHA256:** `90ce4ff9da23ac150da0a8e17930cab1e369aa349fdc1b65691b70369145664a`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `b88c5744975d2abb447aecc6c090fee9f8580413f4612eecdc6ed1973e8a1739`, `ed5ae7f36453c5a23e9868a5729d67e0549a11f6dea54f5f52d654a8f51d4902`, `841c9297cb8a2e0ff89433d13c05bfc760eb2e98e251cb8fa785d2ad7cbac05f`, `ece7c48eb411b24f26762ede83badb4a644c41d5777129381ac2541804d64fc2`, `421ce2d2f49c23bbe9f60ef3b9cd38d7eb912ce02e56a61837656210069bd9e2`, `121c2dc793b3873f75a29ec02241f94136de19c049382a50a50d0d5b99507073`, `2415db5081cec9bfd14ad6da1a66169fd96f13a49010c319a73d1ed6fafd4efa`, `d9917ade3b4c125a95b5d3e6343cde26145dfbf569bd7e2a843fd0c6fc8ddc28` _(+3 more)_


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
