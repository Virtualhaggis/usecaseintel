# [HIGH] Rails patches critical Active Storage flaw with RCE potential

**Source:** BleepingComputer
**Published:** 2026-08-01
**Article:** https://www.bleepingcomputer.com/news/security/rails-patches-critical-active-storage-flaw-with-rce-potential/

## Threat Profile

Rails patches critical Active Storage flaw with RCE potential 
By Bill Toulas 
August 1, 2026
10:20 AM
0 
A critical vulnerability in the Active Storage framework can allow an unauthenticated attacker to read arbitrary files from a Rails application, and potentially escalate to remote code execution (RCE).
Rails is a popular open-source web application framework written in Ruby for building websites and web apps. It uses the built-in Rails component Active Storage for handling file uploads and a…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-66066`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1552.001** — Credentials In Files
- **T1552** — Unsecured Credentials
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Active Storage crafted image upload to libvips variant endpoints (CVE-2026-66066)

`UC_47_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url IN ("*/rails/active_storage/representations/*","*/rails/active_storage/blobs/*","*/rails/active_storage/direct_uploads*","*/rails/active_storage/disk/*") by Web.src, Web.dest, Web.http_method, Web.status, Web.url
| `drop_dm_object_name(Web)`
| stats sum(count) as hits values(url) as urls values(http_method) as methods values(status) as statuses min(firstTime) as firstTime max(lastTime) as lastTime by src, dest
| where hits > 0
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### Rails/Ruby worker reading secret_key_base and credential files post-upload (CVE-2026-66066)

`UC_47_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.file_path IN ("*/config/credentials.yml.enc","*/config/master.key","*/config/credentials/*.key","*/.env","/proc/self/environ") by Endpoint.Filesystem.dest, Endpoint.Filesystem.file_path, Endpoint.Filesystem.file_name, Endpoint.Filesystem.process_id, Endpoint.Filesystem.action
| `drop_dm_object_name(Endpoint.Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("ruby", "puma", "unicorn", "passenger", "bundle", "rails")
| where FileName in~ ("credentials.yml.enc", "master.key", "environ", ".env")
    or FolderPath has_any ("/config/credentials", "/proc/self/environ")
| where FolderPath !startswith "/tmp/" and FolderPath !has "/active_storage/"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, FileName, FolderPath
| order by Timestamp desc
```

### Rails app worker spawning shell or network child (KindaRails2Shell RCE)

`UC_47_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Endpoint.Processes.parent_process_name IN ("ruby","puma","unicorn","passenger","rails","bundle")) AND (Endpoint.Processes.process_name IN ("sh","bash","dash","curl","wget","nc","ncat","python","python3","perl")) by Endpoint.Processes.dest, Endpoint.Processes.user, Endpoint.Processes.parent_process_name, Endpoint.Processes.process_name, Endpoint.Processes.process
| `drop_dm_object_name(Endpoint.Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("ruby", "puma", "unicorn", "passenger", "rails", "bundle")
| where FileName in~ ("sh", "bash", "dash", "curl", "wget", "nc", "ncat", "python", "python3", "perl")
    or (FileName in~ ("ruby") and ProcessCommandLine has "-e ")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Exposure hunt: hosts with vulnerable libvips / Rails Active Storage (CVE-2026-66066)

`UC_47_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities where Vulnerabilities.cve="CVE-2026-66066" by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2026-66066"
| join kind=leftouter (DeviceInfo | where Timestamp > ago(1d) | summarize arg_max(Timestamp, IsInternetFacing, OSPlatform) by DeviceId) on DeviceId
| project DeviceName, OSPlatform, IsInternetFacing, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-66066`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 6 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
