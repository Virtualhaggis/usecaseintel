# [CRIT] 79 Chrome Vulnerabilities Patched, Including 14 Critical One’s – Update Now!

**Source:** Cyber Security News
**Published:** 2026-05-15
**Article:** https://cybersecuritynews.com/79-chrome-vulnerabilities-patched/

## Threat Profile

Home Cyber Security News 
79 Chrome Vulnerabilities Patched, Including 14 Critical One’s – Update Now! 
By Abinaya 
May 15, 2026 
Google has rolled out a massive security update for its Chrome browser , sealing a staggering 79 vulnerabilities before threat actors can exploit them.
With 14 of these flaws rated as critical, browsing the web on an outdated version leaves your entire system wide open to devastating cyberattacks.
The newest stable release bumps Chrome to 148.0.7778.167/168 on Windows…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-8509`
- **CVE:** `CVE-2026-8510`
- **CVE:** `CVE-2026-8511`
- **CVE:** `CVE-2026-8512`
- **CVE:** `CVE-2026-8513`
- **CVE:** `CVE-2026-8514`
- **CVE:** `CVE-2026-8515`
- **CVE:** `CVE-2026-8516`
- **CVE:** `CVE-2026-8517`
- **CVE:** `CVE-2026-8518`
- **CVE:** `CVE-2026-8519`
- **CVE:** `CVE-2026-8520`
- **CVE:** `CVE-2026-8521`
- **CVE:** `CVE-2026-8522`
- **CVE:** `CVE-2026-41940`
- **MD5:** `c6eed09fc8b174b0f3eebedcceb1e792`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1189** — Drive-by Compromise
- **T1203** — Exploitation for Client Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Endpoints exposed to May 2026 critical Chrome CVEs (CVE-2026-8509…8522 — fixed in 148.0.7778.167)

`UC_8_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.signature_id IN ("CVE-2026-8509","CVE-2026-8510","CVE-2026-8511","CVE-2026-8512","CVE-2026-8513","CVE-2026-8514","CVE-2026-8515","CVE-2026-8516","CVE-2026-8517","CVE-2026-8518","CVE-2026-8519","CVE-2026-8520","CVE-2026-8521","CVE-2026-8522") by Vulnerabilities.dest Vulnerabilities.signature_id Vulnerabilities.severity Vulnerabilities.vendor_product
| `drop_dm_object_name(Vulnerabilities)`
| stats values(signature_id) as exposed_cves dc(signature_id) as cve_count values(vendor_product) as product values(severity) as severity by dest
| where cve_count >= 1
| sort - cve_count
```

**Defender KQL:**
```kql
let chrome_cves = dynamic(["CVE-2026-8509","CVE-2026-8510","CVE-2026-8511","CVE-2026-8512","CVE-2026-8513","CVE-2026-8514","CVE-2026-8515","CVE-2026-8516","CVE-2026-8517","CVE-2026-8518","CVE-2026-8519","CVE-2026-8520","CVE-2026-8521","CVE-2026-8522"]);
let patched_win_mac = "148.0.7778.167";
DeviceTvmSoftwareVulnerabilities
| where CveId in (chrome_cves)
| where SoftwareVendor =~ "google" and SoftwareName has "chrome"
| summarize ExposedCVEs = make_set(CveId),
            ExposedCveCount = dcount(CveId),
            InstalledVersion = any(SoftwareVersion),
            RecommendedUpdate = any(RecommendedSecurityUpdate),
            Severity = max(VulnerabilitySeverityLevel)
            by DeviceId, DeviceName, OSPlatform
| extend NeedsPatch = InstalledVersion != patched_win_mac and InstalledVersion !startswith "148.0.7778.168"
| where NeedsPatch == true
| order by ExposedCveCount desc, DeviceName asc
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

### Article-specific behavioural hunt — 79 Chrome Vulnerabilities Patched, Including 14 Critical One’s – Update Now!

`UC_8_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — 79 Chrome Vulnerabilities Patched, Including 14 Critical One’s – Update Now! ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — 79 Chrome Vulnerabilities Patched, Including 14 Critical One’s – Update Now!
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-8509`, `CVE-2026-8510`, `CVE-2026-8511`, `CVE-2026-8512`, `CVE-2026-8513`, `CVE-2026-8514`, `CVE-2026-8515`, `CVE-2026-8516` _(+7 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c6eed09fc8b174b0f3eebedcceb1e792`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
