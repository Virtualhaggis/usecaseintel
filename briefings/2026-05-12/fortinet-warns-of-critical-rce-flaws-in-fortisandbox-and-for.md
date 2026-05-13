# [HIGH] Fortinet warns of critical RCE flaws in FortiSandbox and FortiAuthenticator

**Source:** BleepingComputer
**Published:** 2026-05-12
**Article:** https://www.bleepingcomputer.com/news/security/fortinet-warns-of-critical-rce-flaws-in-fortisandbox-and-fortiauthenticator/

## Threat Profile

Fortinet warns of critical RCE flaws in FortiSandbox and FortiAuthenticator 
By Sergiu Gatlan 
May 12, 2026
02:23 PM
0 
Fortinet has released security updates to address two critical vulnerabilities in FortiSandbox and FortiAuthenticator that could enable attackers to run commands or arbitrary code on unpatched systems.
The first one, tracked as CVE-2026-44277, impacts the company's FortiAuthenticator Identity and Access Management (IAM) solution and was patched in FortiAuthenticator versions 6.…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-44277`
- **CVE:** `CVE-2026-26083`
- **CVE:** `CVE-2026-21643`
- **CVE:** `CVE-2026-35616`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1592.002** — Gather Victim Host Information: Software

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Asset exposure: FortiAuthenticator CVE-2026-44277 / FortiSandbox CVE-2026-26083 vulnerable versions

`UC_36_4` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstSeen, max(_time) as lastSeen from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-44277","CVE-2026-26083") by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.cve, Vulnerabilities.severity, Vulnerabilities.cvss | `drop_dm_object_name(Vulnerabilities)` | eval product=case(cve=="CVE-2026-44277","FortiAuthenticator",cve=="CVE-2026-26083","FortiSandbox",true(),"unknown"), fix=case(cve=="CVE-2026-44277","Upgrade to FortiAuthenticator 6.5.7 / 6.6.9 / 8.0.3",cve=="CVE-2026-26083","Upgrade to FortiSandbox 4.4.9 / 5.0.2 (Cloud/PaaS 5.0.6+)",true(),"") | sort - cvss, dest
```

**Defender KQL:**
```kql
// Catches Fortinet appliances only if TVM enumerates them via Network Device Discovery; pair with the inventory query below for hosts that have FortiClient/Forti agents installed.
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-44277", "CVE-2026-26083")
| extend FixGuidance = case(CveId == "CVE-2026-44277", "Upgrade FortiAuthenticator to 6.5.7 / 6.6.9 / 8.0.3",
                            CveId == "CVE-2026-26083", "Upgrade FortiSandbox to 4.4.9 / 5.0.2 (Cloud/PaaS 5.0.6+)",
                            "")
| project DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, FixGuidance
| union (
    // Fallback: hit on Fortinet inventory string + affected-version regex, in case CVE feed lag
    DeviceTvmSoftwareInventory
    | where SoftwareVendor =~ "fortinet"
    | where (SoftwareName has "fortiauthenticator" and (SoftwareVersion startswith "6.5." and SoftwareVersion matches regex @"^6\.5\.[0-6]($|[^0-9])"
             or SoftwareVersion startswith "6.6." and SoftwareVersion matches regex @"^6\.6\.[0-8]($|[^0-9])"
             or SoftwareVersion startswith "8.0." and SoftwareVersion matches regex @"^8\.0\.[0-2]($|[^0-9])"))
       or (SoftwareName has "fortisandbox" and (SoftwareVersion startswith "4.4." and SoftwareVersion matches regex @"^4\.4\.[0-8]($|[^0-9])"
             or SoftwareVersion startswith "5.0." and SoftwareVersion matches regex @"^5\.0\.[0-1]($|[^0-9])"))
    | extend CveId = iff(SoftwareName has "fortiauthenticator", "CVE-2026-44277", "CVE-2026-26083"),
             VulnerabilitySeverityLevel = "Critical",
             RecommendedSecurityUpdate = iff(SoftwareName has "fortiauthenticator", "6.5.7 / 6.6.9 / 8.0.3", "4.4.9 / 5.0.2"),
             FixGuidance = "See Fortinet PSIRT (May 12 2026)"
    | project DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, FixGuidance
  )
| summarize arg_max(Timestamp, *) by DeviceName, SoftwareName, CveId
| order by VulnerabilitySeverityLevel asc, DeviceName asc
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
  - CVE(s): `CVE-2026-44277`, `CVE-2026-26083`, `CVE-2026-21643`, `CVE-2026-35616`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
