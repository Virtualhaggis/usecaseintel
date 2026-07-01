# [HIGH] Over 900 Oracle E-Business instances exposed to ongoing attacks

**Source:** BleepingComputer
**Published:** 2026-07-01
**Article:** https://www.bleepingcomputer.com/news/security/over-900-oracle-e-business-instances-exposed-to-ongoing-attacks/

## Threat Profile

Over 900 Oracle E-Business instances exposed to ongoing attacks 
By Sergiu Gatlan 
July 1, 2026
08:30 AM
0 
Over 900 Oracle E-Business Suite (EBS) instances have been found exposed online amid ongoing attacks exploiting a critical security flaw.
The vulnerability (tracked as CVE-2026-46817 ) was found in the File Transmission component of EBS's Oracle Payments product and allows malicious actors without privileges and with HTTP network access to take over vulnerable systems through low-complexit…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-46817`
- **CVE:** `CVE-2025-61882`
- **CVE:** `CVE-2026-35273`
- **CVE:** `CVE-2024-21182`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.004** — Unix Shell
- **T1083** — File and Directory Discovery
- **T1595.002** — Vulnerability Scanning

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Oracle EBS CVE-2026-46817 exploitation — POST to /OA_HTML/ibytransmit File Transmission endpoint

`UC_9_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method="POST" (Web.url="*/OA_HTML/ibytransmit*" OR Web.uri_path="*/OA_HTML/ibytransmit*") by Web.src, Web.dest, Web.dest_port, Web.http_method, Web.url, Web.status, Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

### Oracle EBS web/app tier (java/OHS) spawning shell or recon binary — post-exploit RCE

`UC_9_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("java","httpd","oracle","tnslsnr")) AND (Processes.process_name IN ("sh","bash","dash","cat","id","whoami","uname","curl","wget","python","python3","perl","nc","ncat")) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java","httpd","oracle","tnslsnr")
| where FileName in~ ("sh","bash","dash","cat","id","whoami","uname","curl","wget","python","python3","perl","nc","ncat")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Exposed & unpatched Oracle E-Business Suite instances vulnerable to CVE-2026-46817

`UC_9_6` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities where Vulnerabilities.cve="CVE-2026-46817" by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve | `drop_dm_object_name(Vulnerabilities)` | sort - severity
```

**Defender KQL:**
```kql
let vuln = DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2026-46817"
| summarize arg_max(Timestamp, *) by DeviceId;
vuln
| join kind=leftouter (DeviceInfo | where Timestamp > ago(1d) | summarize arg_max(Timestamp, IsInternetFacing, PublicIP, OSPlatform) by DeviceId) on DeviceId
| project DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, IsInternetFacing, PublicIP, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by IsInternetFacing desc
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
  - CVE(s): `CVE-2026-46817`, `CVE-2025-61882`, `CVE-2026-35273`, `CVE-2024-21182`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 7 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
