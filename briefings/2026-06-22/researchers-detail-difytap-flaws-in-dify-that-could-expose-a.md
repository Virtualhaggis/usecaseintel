# [HIGH] Researchers Detail DifyTap Flaws in Dify That Could Expose AI Chats Across Tenants

**Source:** The Hacker News
**Published:** 2026-06-22
**Article:** https://thehackernews.com/2026/06/researchers-detail-difytap-flaws-in.html

## Threat Profile

Researchers Detail DifyTap Flaws in Dify That Could Expose AI Chats Across Tenants 
 Ravie Lakshmanan  Jun 22, 2026 AI Security / Vulnerability 
Cybersecurity researchers have disclosed details of four vulnerabilities in Dify , an open-source agentic workflow platform with more than 146,000 GitHub stars , that could allow attackers to stealthily read artificial intelligence (AI) conversions from other customers' applications without requiring authentication.
The vulnerabilities have been colle…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-5846`
- **CVE:** `CVE-2026-41947`
- **CVE:** `CVE-2026-41948`
- **CVE:** `CVE-2026-41949`
- **CVE:** `CVE-2026-41950`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1213** — Data from Information Repositories
- **T1530** — Data from Cloud Storage
- **T1083** — File and Directory Discovery
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Dify cross-tenant file-preview UUID enumeration (CVE-2026-41949)

`UC_78_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as preview_hits, dc(Web.uri_path) as distinct_file_ids, values(Web.uri_path) as paths from datamodel=Web where Web.uri_path="/console/api/files/*/preview" by Web.src, Web.user, _time span=10m
| `drop_dm_object_name(Web)`
| where distinct_file_ids >= 15
| sort - distinct_file_ids
```

### Dify Plugin Daemon path traversal to internal REST API (CVE-2026-41948)

`UC_78_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Web.url) as urls, values(Web.http_method) as methods, values(Web.status) as statuses from datamodel=Web where Web.uri_path="*plugin*" (Web.uri_path="*..*" OR Web.uri_query="*..*" OR Web.url="*%2e%2e*" OR Web.url="*%2f..*") by Web.src, Web.user, Web.uri_path
| `drop_dm_object_name(Web)`
| sort - count
```

### Dify mass trace-config hijack across apps (CVE-2026-41947)

`UC_78_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as trace_posts, dc(Web.uri_path) as distinct_apps, values(Web.uri_path) as app_paths from datamodel=Web where Web.http_method=POST Web.uri_path="/console/api/apps/*/trace*" by Web.src, Web.user, _time span=1h
| `drop_dm_object_name(Web)`
| where distinct_apps >= 5
| sort - distinct_apps
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
  - CVE(s): `CVE-2024-5846`, `CVE-2026-41947`, `CVE-2026-41948`, `CVE-2026-41949`, `CVE-2026-41950`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
