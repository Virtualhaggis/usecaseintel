# [CRIT] Roundcube XSS chained with cookie tossing for full inbox access

**Source:** Aikido
**Published:** 2026-04-22
**Article:** https://www.aikido.dev/blog/roundcube-xss-cookie-tossing

## Threat Profile

Blog Vulnerabilities & Threats Roundcube XSS chained with cookie tossing for full inbox access Roundcube XSS chained with cookie tossing for full inbox access Written by Jorian Woltjer Published on: Roundcube is the most widely deployed open-source webmail client in the world. We recently found a dangerous vulnerability in the application! It’s a stored XSS that, chained with a cookie tossing technique, gives an attacker full access to a victim's inbox and, from there, any account that uses that…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-35539`
- **CVE:** `CVE-2026-35538`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1592.002** — Gather Victim Host Information: Software

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Roundcube display-attachment XSS exploit URL pattern (CVE-2026-35538/35539)

`UC_309_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_user_agent) as user_agent values(Web.status) as status from datamodel=Web.Web where Web.url="*_action=display-attachment*" Web.url="*_file=rcmfile*" Web.url="*_task=mail*" by Web.src Web.dest Web.http_method | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has "_action=display-attachment" and RemoteUrl has "_file=rcmfile" and RemoteUrl has "_task=mail"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### [LLM] Vulnerable Roundcube installation exposed (CVE-2026-35538 / CVE-2026-35539, fixed in 1.6.14)

`UC_309_4` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Vulnerabilities.signature) as signature values(Vulnerabilities.cve) as cve from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.cve="CVE-2026-35539" OR Vulnerabilities.cve="CVE-2026-35538" OR Vulnerabilities.signature="*Roundcube*") by Vulnerabilities.dest Vulnerabilities.severity | `drop_dm_object_name(Vulnerabilities)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where (SoftwareName has "roundcube") or (CveId in~ ("CVE-2026-35539","CVE-2026-35538"))
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing, PublicIP) by DeviceId) on DeviceId
| project Timestamp, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, IsInternetFacing, PublicIP, RecommendedSecurityUpdate
| order by IsInternetFacing desc, VulnerabilitySeverityLevel asc
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

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-35539`, `CVE-2026-35538`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
