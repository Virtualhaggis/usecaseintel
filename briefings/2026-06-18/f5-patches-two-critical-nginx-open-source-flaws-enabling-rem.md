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
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1505.003** — Server Software Component: Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### NGINX worker process spawning shell, scripting interpreter, or download utility

`UC_33_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="nginx.exe" OR Processes.parent_process_name="nginx") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","dash","zsh","wget","curl","python","python3","perl","ruby","nc","ncat","wscript.exe","cscript.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("nginx.exe", "nginx")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "dash", "zsh", "wget", "curl", "python", "python3", "perl", "ruby", "nc", "ncat", "wscript.exe", "cscript.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Inventory of hosts running NGINX versions vulnerable to CVE-2026-42530 / CVE-2026-42055

`UC_33_3` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-42530","CVE-2026-42055","CVE-2026-42945") by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.cvss | `drop_dm_object_name(Vulnerabilities)` | sort - cvss
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId in ("CVE-2026-42530", "CVE-2026-42055", "CVE-2026-42945")
   or (SoftwareName has_any ("nginx", "nginx plus", "nginx instance manager", "nginx ingress controller", "nginx gateway fabric", "nginx app protect", "f5 waf for nginx", "f5 dos for nginx"))
| join kind=leftouter (DeviceInfo | where Timestamp > ago(1d) | summarize arg_max(Timestamp, IsInternetFacing, PublicIP, OSPlatform) by DeviceId) on DeviceId
| project Timestamp, DeviceName, OSPlatform, IsInternetFacing, PublicIP, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by IsInternetFacing desc, DeviceName asc
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

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
