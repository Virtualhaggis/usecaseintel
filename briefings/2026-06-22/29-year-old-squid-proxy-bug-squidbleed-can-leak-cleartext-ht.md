# [HIGH] 29-Year-Old Squid Proxy Bug 'Squidbleed' Can Leak Cleartext HTTP Requests

**Source:** The Hacker News
**Published:** 2026-06-22
**Article:** https://thehackernews.com/2026/06/29-year-old-squid-proxy-bug-squidbleed.html

## Threat Profile

29-Year-Old Squid Proxy Bug 'Squidbleed' Can Leak Cleartext HTTP Requests 
 Swati Khandelwal  Jun 22, 2026 Vulnerability / Server Security 
A heap over-read in the Squid web proxy can leak another user's cleartext HTTP request, including any credentials or session tokens it carries, to anyone already allowed to send traffic through the same proxy.
The bug traces to a 1997 FTP-parsing change and is still live in Squid's default configuration. Researchers at Calif.io  disclosed it in June  and n…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-47729`
- **CVE:** `CVE-2026-50012`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1071.002** — Application Layer Protocol: File Transfer Protocols
- **T1212** — Exploitation for Credential Access

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Squid proxy initiating outbound FTP control-channel (TCP/21) to external host (Squidbleed precondition)

`UC_59_2` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=21 (All_Traffic.app=squid OR All_Traffic.process=squid) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "squid"
| where RemotePort == 21
| where RemoteIPType == "Public"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ConnCount=count() by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| order by FirstSeen desc
```

### High-volume ftp:// listing requests through Squid proxy to single host (Squidbleed memory harvest)

`UC_59_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Web.dest) as dest_count values(Web.url) as urls from datamodel=Web.Web where Web.url="ftp://*" by Web.src Web.user _time span=10m | `drop_dm_object_name(Web)` | where count > 20 AND dest_count <= 2 | sort - count
```

### Squid hosts exposed to Squidbleed (CVE-2026-47729) with FTP attack surface

`UC_59_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2026-47729" by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity | `drop_dm_object_name(Vulnerabilities)` | sort - count
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId == "CVE-2026-47729"
| project Timestamp, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by Timestamp desc
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
  - CVE(s): `CVE-2026-47729`, `CVE-2026-50012`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 5 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
