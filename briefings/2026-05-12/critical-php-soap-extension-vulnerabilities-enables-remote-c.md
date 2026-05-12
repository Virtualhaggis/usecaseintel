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
GitHub s…

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
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1505.003** — Server Software Component: Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PHP servers vulnerable to CVE-2026-6722 SOAP UAF + companion ext-soap/mbstring/urldecode CVEs

`UC_0_5` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-6722","CVE-2026-7261","CVE-2026-7262","CVE-2026-7258","CVE-2026-6104") by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.cvss 
| `drop_dm_object_name(Vulnerabilities)`
| eval recommended_fix=case(cve=="CVE-2026-6722","Upgrade to PHP 8.2.31 / 8.3.31 / 8.4.21 / 8.5.6", cve=="CVE-2026-7261","Upgrade to PHP 8.2.31 / 8.3.31 / 8.4.21 / 8.5.6", cve=="CVE-2026-7262","Upgrade to PHP 8.2.31 / 8.3.31 / 8.4.21 / 8.5.6", cve=="CVE-2026-7258","Upgrade to PHP 8.2.31 / 8.3.31 / 8.4.21 / 8.5.6", cve=="CVE-2026-6104","Upgrade to PHP 8.4.21 / 8.5.6 (mbstring; older branches unaffected)")
| sort 0 - severity dest
```

**Defender KQL:**
```kql
// CVE-2026-6722 + 4 companion ext-soap / urldecode / mbstring CVEs patched in PHP 8.2.31/8.3.31/8.4.21/8.5.6
let _php_cves = dynamic(["CVE-2026-6722","CVE-2026-7261","CVE-2026-7262","CVE-2026-7258","CVE-2026-6104"]);
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId in (_php_cves)
| where SoftwareVendor =~ "php" or SoftwareName has "php" or SoftwareName has "php-fpm" or SoftwareName has "php-cgi" or SoftwareName has "php-soap" or SoftwareName has "php-mbstring"
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing, OSPlatform, OSVersion, MachineGroup) by DeviceId) on DeviceId
| project DeviceName, IsInternetFacing, OSPlatform=OSPlatform1, OSVersion=OSVersion1, MachineGroup, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by IsInternetFacing desc, CveId asc, DeviceName asc
```

### [LLM] PHP web worker (php-fpm / php-cgi / mod_php / w3wp) spawns shell or networking LOLBin — post-CVE-2026-6722 RCE

`UC_0_6` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("php-fpm","php-cgi","php","php8.2","php8.3","php8.4","php8.5","php-fpm8.2","php-fpm8.3","php-fpm8.4","php-fpm8.5","httpd","apache2","nginx","w3wp.exe")) AND (Processes.process_name IN ("sh","bash","dash","zsh","ash","cmd.exe","powershell.exe","pwsh.exe","curl","curl.exe","wget","wget.exe","nc","nc.exe","ncat","ncat.exe","socat","python","python3","perl","ruby","whoami","whoami.exe","id","uname","hostname")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name 
| `drop_dm_object_name(Processes)` 
| where NOT match(parent_cmd, "(?i)(image[-_]?magick|imagick|convert|gs |ghostscript|phpunit|composer|artisan|wp[- ]cli|drush|cron)") 
| sort 0 - firstSeen
```

**Defender KQL:**
```kql
// PHP runtime worker spawning shell / scripting / netutil — typical post-RCE tail of CVE-2026-6722 ext-soap UAF
let _php_parents = dynamic(["php-fpm","php-cgi","php","php8.2","php8.3","php8.4","php8.5","php-fpm8.2","php-fpm8.3","php-fpm8.4","php-fpm8.5","php.exe","php-cgi.exe","httpd","httpd.exe","apache2","nginx","nginx.exe","w3wp.exe"]);
let _suspicious_children = dynamic(["sh","bash","dash","zsh","ash","cmd.exe","powershell.exe","pwsh.exe","curl","curl.exe","wget","wget.exe","nc","nc.exe","ncat","ncat.exe","socat","python","python3","python.exe","perl","perl.exe","ruby","whoami","whoami.exe","id","uname","hostname"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (_php_parents)
| where FileName in~ (_suspicious_children)
| where AccountName !endswith "$"
// Drop the most common legit PHP shell-outs; tune per app as needed
| where not(ProcessCommandLine has_any ("ImageMagick","imagick","convert -","gs -","ghostscript","phpunit","composer","artisan","wp-cli","wp-cron","drush"))
| project Timestamp, DeviceName, AccountName, IsInitiatingProcessRemoteSession,
          Parent = InitiatingProcessFileName, ParentPath = InitiatingProcessFolderPath, ParentCmd = InitiatingProcessCommandLine,
          Child = FileName, ChildPath = FolderPath, ChildCmd = ProcessCommandLine, SHA256
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
  - CVE(s): `CVE-2026-6722`, `CVE-2026-7261`, `CVE-2026-7262`, `CVE-2026-7258`, `CVE-2026-6104`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
