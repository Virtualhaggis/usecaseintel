# [CRIT] OpenAI Expands Daybreak With GPT-5.5-Cyber to Help Defenders Patch Security Flaws

**Source:** The Hacker News
**Published:** 2026-06-23
**Article:** https://thehackernews.com/2026/06/openai-expands-daybreak-with-gpt-55.html

## Threat Profile

OpenAI Expands Daybreak With GPT-5.5-Cyber to Help Defenders Patch Security Flaws 
 Ravie Lakshmanan  Jun 23, 2026 Artificial Intelligence / Codex Security 
OpenAI on Monday said it's releasing an improved version of its GPT‑5.5‑Cyber model to trusted defenders as part of the Daybreak initiative , the artificial intelligence (AI) company announced last month.
Calling GPT‑5.5‑Cyber its "strongest model yet for finding and helping patch software vulnerabilities," OpenAI said the model can "susta…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-47729`
- **CVE:** `CVE-2026-4890`
- **CVE:** `CVE-2026-4891`
- **CVE:** `CVE-2026-4892`
- **CVE:** `CVE-2026-5172`
- **CVE:** `CVE-2026-8390`
- **CVE:** `CVE-2026-11645`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application

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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-47729`, `CVE-2026-4890`, `CVE-2026-4891`, `CVE-2026-4892`, `CVE-2026-5172`, `CVE-2026-8390`, `CVE-2026-11645`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
