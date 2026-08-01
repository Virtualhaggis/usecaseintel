# [CRIT] VMware fixes three critical flaws allowing auth bypass, VM escapes

**Source:** BleepingComputer
**Published:** 2026-07-30
**Article:** https://www.bleepingcomputer.com/news/security/vmware-fixes-three-critical-flaws-allowing-auth-bypass-vm-escapes/

## Threat Profile

VMware fixes three critical flaws allowing auth bypass, VM escapes 
By Lawrence Abrams 
July 30, 2026
02:00 PM
0 
Broadcom has released security updates to fix five vulnerabilities in VMware vCenter, ESX, Workstation, and Fusion, including three critical flaws that allow attackers to bypass authentication, execute arbitrary code, or escape from a virtual machine to the host.
The vulnerabilities also affect products containing vCenter or ESX, including VMware Cloud Foundation, VMware vSphere Foun…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-59309`
- **CVE:** `CVE-2026-59310`
- **CVE:** `CVE-2026-47876`
- **CVE:** `CVE-2026-41703`
- **CVE:** `CVE-2026-41709`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1564.006** — Hide Artifacts: Run Virtual Instance
- **T1673** — Virtual Machine Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### VMware ESX/vCenter hosts exposed to VMSA-2026-0006 critical CVEs (59309/59310/47876)

`UC_39_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-59309","CVE-2026-59310","CVE-2026-47876","CVE-2026-41703","CVE-2026-41709") by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.cvss
| `drop_dm_object_name(Vulnerabilities)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - cvss
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-59309","CVE-2026-59310","CVE-2026-47876","CVE-2026-41703","CVE-2026-41709")
| where SoftwareVendor has_any ("vmware","broadcom")
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing) by DeviceId) on DeviceId
| project DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, IsInternetFacing
| sort by IsInternetFacing desc, CveId asc
```

### ESXi rogue/'ghost' VM instantiated from the shell (VirtualGHOST persistence)

`UC_39_5` · phase: **install** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=vmware (sourcetype="vmware:esxilog" OR sourcetype="vmw-syslog" OR sourcetype="esxi:syslog") (source="*shell.log" OR source="*hostd.log")
("vim-cmd solo/registervm" OR "vim-cmd vmsvc/power.on" OR "vim-cmd vmsvc/reload" OR "esxcli vm process list")
| rex field=_raw "(?<esxi_cmd>vim-cmd\s+\S+|esxcli\s+vm\s+process\s+\S+)"
| stats count min(_time) as firstTime max(_time) as lastTime values(esxi_cmd) as commands values(source) as logfile by host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - count
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
  - CVE(s): `CVE-2026-59309`, `CVE-2026-59310`, `CVE-2026-47876`, `CVE-2026-41703`, `CVE-2026-41709`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
