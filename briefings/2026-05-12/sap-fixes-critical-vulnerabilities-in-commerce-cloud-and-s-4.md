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

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SAP May 2026 Patch Tuesday CVE exposure hunt (Commerce Cloud / S/4HANA criticals)

`UC_45_5` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstFound max(_time) as lastFound values(Vulnerabilities.signature) as signature values(Vulnerabilities.severity) as severity values(Vulnerabilities.vendor_product) as vendor_product from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.cve IN ("CVE-2026-34263","CVE-2026-34260")) by Vulnerabilities.dest Vulnerabilities.cve | `drop_dm_object_name(Vulnerabilities)` | eval priority=case(cve="CVE-2026-34263","P1 - unauth RCE (Commerce Cloud, Spring Security)", cve="CVE-2026-34260","P2 - authenticated SQLi (S/4HANA)", 1=1,"P3") | convert ctime(firstFound) ctime(lastFound) | sort 0 priority dest
```

**Defender KQL:**
```kql
// SAP May 2026 Patch Tuesday — devices still vulnerable to either critical CVE
let SapMay2026Criticals = dynamic(["CVE-2026-34263","CVE-2026-34260"]);
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)            // TVM snapshot — daily refresh is enough
| where CveId in (SapMay2026Criticals)
| where SoftwareVendor has "sap"        // belt-and-braces — confirms this is the SAP CVE, not a collision
| extend Priority = case(
    CveId == "CVE-2026-34263", "P1 - unauth RCE (Commerce Cloud, Spring Security misconfig)",
    CveId == "CVE-2026-34260", "P2 - authenticated SQLi (S/4HANA)",
    "P3")
| project Timestamp, DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion,
          CveId, VulnerabilitySeverityLevel, Priority, RecommendedSecurityUpdate, RecommendedSecurityUpdateId
| order by Priority asc, DeviceName asc
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

Severity classified as **HIGH** based on: CVE present, 6 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
