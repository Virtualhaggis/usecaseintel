# [HIGH] Malicious JPEG Images Could Trigger PHP Memory Safety Vulnerabilities

**Source:** Cyber Security News
**Published:** 2026-05-16
**Article:** https://cybersecuritynews.com/malicious-jpeg-images-php-memory-safety-vulnerabilities/

## Threat Profile

Home Cyber Security News 
Malicious JPEG Images Could Trigger PHP Memory Safety Vulnerabilities 
By Dhivya 
May 16, 2026 
Two critical memory-safety vulnerabilities in PHP’s image-processing functions could allow attackers to leak sensitive heap memory or to execute denial-of-service attacks via specially crafted JPEG files. 
The flaws, discovered in PHP’s ext/standard extension by Positive Technologies researcher Nikita Sveshnikov , affect the widely-used getimagesize and iptcembed functions th…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-14177`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1212** — Exploitation for Credential Access
- **T1592.002** — Gather Victim Host Information: Software
- **T1499.004** — Endpoint Denial of Service: Application or System Exploitation
- **T1203** — Exploitation for Client Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PHP php:// wrapper abuse in HTTP requests targeting getimagesize endpoints (CVE-2025-14177)

`UC_3_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Web.url) as urls, values(Web.http_method) as methods, values(Web.status) as statuses, values(Web.bytes_out) as bytes_out from datamodel=Web where (Web.url="*php://filter*" OR Web.url="*php%3A%2F%2Ffilter*" OR Web.url="*php%3a%2f%2ffilter*" OR Web.uri_query="*php://filter*" OR Web.uri_query="*php%3A%2F%2Ffilter*") by Web.src, Web.dest, Web.user, _time span=1m | `drop_dm_object_name(Web)` | where count >= 1 | sort - _time
```

**Defender KQL:**
```kql
// Defender lacks server-side inbound HTTP body/URL telemetry for PHP web servers.
// Best-effort: catch PHP CLI/CGI processes invoked with php://filter on the command line
// (e.g. attacker pivoted onto host and is testing locally) — narrow but valid.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("php.exe","php-cgi.exe","php-fpm","php") or FileName in~ ("php.exe","php-cgi.exe","php-fpm","php")
| where ProcessCommandLine has_any ("php://filter","php%3A%2F%2Ffilter")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] Estate exposure: PHP versions vulnerable to CVE-2025-14177 / iptcembed overflow

`UC_3_6` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Vulnerabilities.severity) as severity, values(Vulnerabilities.signature) as signature, values(Vulnerabilities.vendor_product) as product, values(Vulnerabilities.url) as references, latest(_time) as last_seen from datamodel=Vulnerabilities where Vulnerabilities.cve="CVE-2025-14177" by Vulnerabilities.dest | `drop_dm_object_name(Vulnerabilities)` | eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S") | sort - count
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2025-14177"
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform, IsInternetFacing, MachineGroup) by DeviceId, DeviceName
) on DeviceId
| extend Priority = case(IsInternetFacing == true, "CRITICAL-internet-facing", "high")
| project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, IsInternetFacing, MachineGroup, Priority
| order by Priority asc, DeviceName asc
```

### [LLM] PHP-FPM/php-cgi worker SIGSEGV or abort coincident with image-processing endpoint traffic

`UC_3_7` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Processes.process) as process, values(Processes.parent_process_name) as parent, values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name IN ("php-fpm","php-cgi.exe","php.exe","php","httpd","apache2","nginx") AND (Processes.process="*SIGSEGV*" OR Processes.process="*segfault*" OR Processes.process="*AddressSanitizer*" OR Processes.process="*core dumped*" OR Processes.process="*signal 11*")) by Processes.dest, Processes.process_name, _time span=5m | `drop_dm_object_name(Processes)` | where count >= 2 | sort - _time
```

**Defender KQL:**
```kql
// Linux/Windows PHP worker crash signatures via Defender Linux/Windows agents
let PhpHosts = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("php-fpm","php-cgi.exe","php.exe","php")
    | summarize by DeviceId, DeviceName;
DeviceEvents
| where Timestamp > ago(7d)
| where DeviceId in ((PhpHosts | project DeviceId))
| where ActionType in ("ProcessTerminated","ProcessCrashed","AddressSanitizerError") or AdditionalFields has_any ("SIGSEGV","segfault","AddressSanitizer","signal 11","core dumped")
| where InitiatingProcessFileName in~ ("php-fpm","php-cgi.exe","php.exe","php","httpd","apache2","nginx")
   or FileName in~ ("php-fpm","php-cgi.exe","php.exe","php")
| summarize CrashCount = count(), FirstCrash = min(Timestamp), LastCrash = max(Timestamp), SampleFields = any(AdditionalFields) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 10m)
| where CrashCount >= 2
| order by LastCrash desc
```

### Office app spawning script/LOLBin child process

`UC_OFFICE_CHILD` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-14177`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 8 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
