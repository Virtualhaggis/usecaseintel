# [HIGH] F5 Patches Two Critical NGINX Open Source Flaws Enabling Remote Code Execution

**Source:** The Hacker News
**Published:** 2026-06-18
**Article:** https://thehackernews.com/2026/06/f5-patches-two-critical-nginx-open.html

## Threat Profile

F5 Patches Two Critical NGINX Open Source Flaws Enabling Remote Code Execution 
 Ravie Lakshmanan  Jun 18, 2026 Vulnerability / Cloud Security 
F5 has released security updates to address two critical security flaws in NGINX Open Source that could be exploited to achieve code execution on affected systems.
The vulnerabilities are listed below -
CVE-2026-42530 (CVSS v4 score: 9.2) - A use-after-free vulnerability in the ngx_http_v3_module that could be triggered by a remote unauthenticated atta…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-42530`
- **CVE:** `CVE-2026-42055`
- **CVE:** `CVE-2026-42945`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1499.004** — Endpoint Denial of Service: Application or System Exploitation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### NGINX hosts vulnerable to CVE-2026-42530 / CVE-2026-42055 (HTTP/3 UAF & HTTP/2 heap overflow)

`UC_73_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Vulnerabilities.signature) as signature values(Vulnerabilities.severity) as severity from datamodel=Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-42530","CVE-2026-42055") by Vulnerabilities.dest Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| convert ctime(firstTime) ctime(lastTime)
| sort 0 dest
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-42530","CVE-2026-42055")
| where SoftwareName has "nginx"
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing) by DeviceId) on DeviceId
| project DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, IsInternetFacing
| sort by IsInternetFacing desc, DeviceName asc
```

### NGINX worker process crash-loop — memory-corruption exploitation of CVE-2026-42530/42055

`UC_73_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly`
| tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=nginx Processes.parent_process_name=nginx by Processes.dest Processes.process Processes.parent_process span=10m
| `drop_dm_object_name(Processes)`
| search process="*worker*"
| where count>=10
| convert ctime(firstTime) ctime(lastTime)
| sort 0 - count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName == "nginx" and InitiatingProcessFileName == "nginx"
| where ProcessCommandLine has "worker process"
| summarize WorkerSpawns = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleCmd = any(ProcessCommandLine) by DeviceId, DeviceName, bin(Timestamp, 10m)
| where WorkerSpawns >= 10   // healthy nginx rarely recycles workers; >=10 respawns / 10m = crash loop (baseline ~0)
| sort by LastSeen desc
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
  - CVE(s): `CVE-2026-42530`, `CVE-2026-42055`, `CVE-2026-42945`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
