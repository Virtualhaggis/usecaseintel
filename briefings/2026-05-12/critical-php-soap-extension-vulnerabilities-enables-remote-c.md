# [CRIT] Critical PHP SOAP Extension Vulnerabilities Enables Remote Code Execution Attacks

**Source:** Cyber Security News
**Published:** 2026-05-12
**Article:** https://cybersecuritynews.com/php-soap-extension-vulnerabilities/

## Threat Profile

Home Cyber Security News 
Critical PHP SOAP Extension Vulnerabilities Enables Remote Code Execution Attacks 
By Abinaya 
May 12, 2026 
A serious cluster of vulnerabilities has been uncovered in PHP’s core string processing and ext-soap components, putting numerous web servers at immediate risk of total takeover.
While the SOAP extension has a notorious history of memory corruption flaws, this latest discovery crosses the red line into unauthenticated Remote Code Execution (RCE).
GitHub security …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-6722`
- **CVE:** `CVE-2026-7261`
- **CVE:** `CVE-2026-7262`
- **CVE:** `CVE-2026-7258`
- **CVE:** `CVE-2026-6104`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1203** — Exploitation for Client Execution
- **T1499.004** — Endpoint Denial of Service: Application or System Exploitation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable PHP SOAP / mbstring runtime on managed host (CVE-2026-6722, -7261, -7262, -7258, -6104)

`UC_26_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-6722","CVE-2026-7261","CVE-2026-7262","CVE-2026-7258","CVE-2026-6104") by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| eval is_internet_facing=if(match(dest,"(?i)(web|www|api|dmz|edge|public)"),"yes","unknown")
| convert ctime(firstTime), ctime(lastTime)
| sort - severity, dest
```

**Defender KQL:**
```kql
// CVE-driven inventory hunt — PHP <8.2.31 / <8.3.31 / <8.4.21 / <8.5.6
let PhpSoapCves = dynamic(["CVE-2026-6722","CVE-2026-7261","CVE-2026-7262","CVE-2026-7258","CVE-2026-6104"]);
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId in (PhpSoapCves)
| where SoftwareVendor has "php" or SoftwareName has "php"
| extend MajorMinor = extract(@"^(\d+\.\d+)", 1, SoftwareVersion)
| extend PatchedFloor = case(
    MajorMinor == "8.2", "8.2.31",
    MajorMinor == "8.3", "8.3.31",
    MajorMinor == "8.4", "8.4.21",
    MajorMinor == "8.5", "8.5.6",
    "unsupported-branch")
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing, OSPlatform) by DeviceId) on DeviceId
| project Timestamp, DeviceName, OSPlatform, IsInternetFacing, SoftwareVendor, SoftwareName, SoftwareVersion, PatchedFloor, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by VulnerabilitySeverityLevel desc, IsInternetFacing desc, DeviceName asc
```

### [LLM] PHP / php-fpm worker segfault cluster on Linux web tier — possible CVE-2026-6722 / 7258 / 7262 exploit attempt

`UC_26_6` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`linux_syslog`
| where match(_raw, "(?i)(php-?fpm|php-cgi|php\d|libphp)")
   AND match(_raw, "(?i)(segfault|sigsegv|sigabrt|core dumped|general protection)")
| rex field=_raw "(?i)(?<phpProc>php[-\w\.]+)"
| rex field=_raw "(?i)error\s+(?<err>\d+)\s+in\s+(?<faultModule>[^\s]+)"
| stats count as crash_count, min(_time) as firstSeen, max(_time) as lastSeen, values(phpProc) as phpProcs, values(faultModule) as faultModules, values(_raw) as sample by host
| where crash_count >= 3
| convert ctime(firstSeen), ctime(lastSeen)
| sort - crash_count
```

**Defender KQL:**
```kql
// MDE for Linux — surface clustered php-fpm crashes (DeviceEvents ProcessTerminated / Defender for Linux unexpected exits)
DeviceEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("php","php-fpm","php-cgi","php7","php8")
| where ActionType has_any ("ProcessCrash","ProcessAbnormalExit","ProcessTerminated")
   or (isnotempty(AdditionalFields) and tostring(AdditionalFields) has_any ("SIGSEGV","SIGABRT","segfault","core dumped"))
| summarize CrashCount = count(),
            FirstSeen  = min(Timestamp),
            LastSeen   = max(Timestamp),
            SampleAdditional = any(tostring(AdditionalFields)),
            SampleCmd  = any(InitiatingProcessCommandLine)
            by DeviceName, InitiatingProcessFileName
| where CrashCount >= 3
| order by CrashCount desc
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
  - CVE(s): `CVE-2026-6722`, `CVE-2026-7261`, `CVE-2026-7262`, `CVE-2026-7258`, `CVE-2026-6104`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
