# [CRIT] cPanel, WHM Release Fixes for Three New Vulnerabilities — Patch Now

**Source:** The Hacker News
**Published:** 2026-05-09
**Article:** https://thehackernews.com/2026/05/cpanel-whm-patch-3-new-vulnerabilities.html

## Threat Profile

cPanel, WHM Release Fixes for Three New Vulnerabilities — Patch Now 
 Ravie Lakshmanan  May 09, 2026 Vulnerability / Web Hosting 
cPanel has released updates to address three vulnerabilities in cPanel and Web Host Manager (WHM) that could be exploited to achieve privilege escalation, code execution, and denial-of-service.
The list of vulnerabilities is as follows -
CVE-2026-29201 (CVSS score: 4.3) - An insufficient input validation of the feature file name in the "feature::LOADFEATUREFILE" adm…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-29201`
- **CVE:** `CVE-2026-29202`
- **CVE:** `CVE-2026-29203`
- **CVE:** `CVE-2026-41940`
- **CVE:** `CVE-2026-33626`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-3854`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1068** — Exploitation for Privilege Escalation
- **T1059.006** — Command and Scripting Interpreter: Perl
- **T1083** — File and Directory Discovery
- **T1006** — Direct Volume Access

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Unpatched cPanel / WHM servers exposed to CVE-2026-29201/29202/29203

`UC_102_5` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Vulnerabilities.signature) as signature values(Vulnerabilities.severity) as severity from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.cve="CVE-2026-29201" OR Vulnerabilities.cve="CVE-2026-29202" OR Vulnerabilities.cve="CVE-2026-29203") by Vulnerabilities.dest Vulnerabilities.cve | `drop_dm_object_name(Vulnerabilities)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-29201","CVE-2026-29202","CVE-2026-29203")
| where SoftwareVendor has "cpanel" or SoftwareName has_any ("cpanel","whm","wp squared")
| join kind=leftouter (
    DeviceTvmSoftwareVulnerabilitiesKB
    | where CveId in ("CVE-2026-29201","CVE-2026-29202","CVE-2026-29203")
    | project CveId, CvssScore, IsExploitAvailable
  ) on CveId
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform, IsInternetFacing, PublicIP) by DeviceId
  ) on DeviceId
| project Timestamp, DeviceName, DeviceId, OSPlatform, PublicIP, IsInternetFacing,
          SoftwareVendor, SoftwareName, SoftwareVersion, CveId, CvssScore,
          IsExploitAvailable, RecommendedSecurityUpdate
| order by IsInternetFacing desc, CvssScore desc
```

### [LLM] cPanel create_user UAPI call with Perl-injection markers in 'plugin' parameter (CVE-2026-29202)

`UC_102_6` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_user_agent) as ua values(Web.status) as status from datamodel=Web.Web where (Web.url="*create_user*" OR Web.url="*Plugins/create_user*") AND (Web.url="*plugin=*" OR Web.http_method=POST) AND (Web.url="*%60*" OR Web.url="*system(*" OR Web.url="*exec(*" OR Web.url="*eval(*" OR Web.url="*qx{*" OR Web.url="*%7c*" OR Web.url="*%3b*" OR Web.url="*%0a*") by Web.src Web.dest Web.user Web.url | `drop_dm_object_name(Web)` | where dest_match="*cpanel*" OR url="*:2083*" OR url="*:2087*" OR url="*/cpsess*" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// cPanel typically runs on Linux servers; this query covers the case where MDE-Linux is deployed and cpsrvd writes to syslog visible via DeviceProcessEvents shell-fork pattern, or a managed reverse-proxy is in front.
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (2082, 2083, 2086, 2087, 2095, 2096)  // cPanel/WHM ports
| where ActionType == "InboundConnectionAccepted"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName has_any ("cpsrvd","cpanel","whostmgrd")
    | where ProcessCommandLine has "create_user"
       and ProcessCommandLine has_any ("plugin=","--plugin","plugin:")
       and ProcessCommandLine matches regex @"(?i)(`|system\s*\(|exec\s*\(|eval\s*\(|qx\s*[{\(]|\|\s*sh|;\s*(perl|sh|bash))"
    | project Timestamp, DeviceId, DeviceName, AccountName,
              ProcessCommandLine, InitiatingProcessFileName,
              InitiatingProcessCommandLine
  ) on DeviceId
| project Timestamp, DeviceName, AccountName, RemoteIP, RemotePort,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### [LLM] cPanel feature::LOADFEATUREFILE adminbin call with path traversal (CVE-2026-29201)

`UC_102_7` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name="adminbin" OR Processes.parent_process_name="adminbin" OR Processes.process="*adminbin*feature*" OR Processes.process="*LOADFEATUREFILE*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | where match(cmdline, "(?i)LOADFEATUREFILE") AND (match(cmdline, "\.\./") OR match(cmdline, "(?i)/etc/(passwd|shadow|cpanel)") OR match(cmdline, "(?i)/root/") OR match(cmdline, "(?i)/home/[^/]+/\.my\.cnf")) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "adminbin"
   or InitiatingProcessFileName =~ "adminbin"
   or ProcessCommandLine has "adminbin"
| where ProcessCommandLine has "LOADFEATUREFILE"
   or ProcessCommandLine has "feature::LOADFEATUREFILE"
| where ProcessCommandLine matches regex @"(?i)(\.\./|%2e%2e%2f|/etc/(passwd|shadow|cpanel)|/root/|\.my\.cnf|/var/cpanel/users/|/home/[^/\s]+/\.[a-z])"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
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
  - CVE(s): `CVE-2026-29201`, `CVE-2026-29202`, `CVE-2026-29203`, `CVE-2026-41940`, `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
