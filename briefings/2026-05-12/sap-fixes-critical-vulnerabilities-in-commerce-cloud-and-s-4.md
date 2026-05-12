# [HIGH] SAP fixes critical vulnerabilities in Commerce Cloud and S/4HANA

**Source:** BleepingComputer
**Published:** 2026-05-12
**Article:** https://www.bleepingcomputer.com/news/security/sap-fixes-critical-vulnerabilities-in-commerce-cloud-and-s-4hana/

## Threat Profile

SAP fixes critical vulnerabilities in Commerce Cloud and S/4HANA 
By Sergiu Gatlan 
May 12, 2026
07:04 AM
0 
SAP has released the May 2026 security updates addressing 15 vulnerabilities across multiple products, including two critical flaws in Commerce Cloud and S/4HANA.
Commerce Cloud is an enterprise-grade e-commerce platform used by online stores owned by large retailers and global brands, while S/4HANA is a cloud-based Enterprise Resource Planning (ERP) suite that will replace the company's …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-34263`
- **CVE:** `CVE-2026-34260`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1059** — Command and Scripting Interpreter
- **T1190.001** — SQL Injection (via T1190)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Hunt SAP Commerce Cloud & S/4HANA hosts vulnerable to CVE-2026-34263 / CVE-2026-34260

`UC_2_5` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities where (Vulnerabilities.cve="CVE-2026-34263" OR Vulnerabilities.cve="CVE-2026-34260") by Vulnerabilities.dest Vulnerabilities.dest_category Vulnerabilities.signature Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.vendor_product Vulnerabilities.cvss | `drop_dm_object_name(Vulnerabilities)` | eval product_hint=case(match(vendor_product,"(?i)commerce|hybris"),"SAP Commerce Cloud (Hybris)",match(vendor_product,"(?i)s.?4.?hana|netweaver|abap"),"SAP S/4HANA",1==1,vendor_product) | convert ctime(firstTime) ctime(lastTime) | sort - cvss, dest
```

**Defender KQL:**
```kql
// CVE-2026-34263 (SAP Commerce Cloud RCE) + CVE-2026-34260 (SAP S/4HANA SQLi)
let SapCves = dynamic(["CVE-2026-34263","CVE-2026-34260"]);
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(7d)
| where CveId in (SapCves)
| where SoftwareVendor =~ "sap"
   or SoftwareName has_any ("commerce","hybris","s/4hana","s4hana","netweaver","abap")
| join kind=leftouter (
    DeviceTvmSoftwareVulnerabilitiesKB
    | project CveId, CvssScore, IsExploitAvailable, PublishedDate, VulnerabilityDescription
  ) on CveId
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago(1d)
    | summarize arg_max(Timestamp, IsInternetFacing, PublicIP, OSPlatform, MachineGroup) by DeviceId, DeviceName
  ) on DeviceId
| project Timestamp, DeviceName, DeviceId, OSPlatform, IsInternetFacing, PublicIP, MachineGroup,
          CveId, VulnerabilitySeverityLevel, CvssScore, IsExploitAvailable,
          SoftwareVendor, SoftwareName, SoftwareVersion,
          RecommendedSecurityUpdate, RecommendedSecurityUpdateId
| order by IsInternetFacing desc, CvssScore desc, DeviceName asc
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
  - CVE(s): `CVE-2026-34263`, `CVE-2026-34260`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
