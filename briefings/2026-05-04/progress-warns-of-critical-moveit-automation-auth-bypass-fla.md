# [HIGH] Progress warns of critical MOVEit Automation auth bypass flaw

**Source:** BleepingComputer
**Published:** 2026-05-04
**Article:** https://www.bleepingcomputer.com/news/security/moveit-automation-customers-warned-to-patch-critical-auth-bypass-flaw/

## Threat Profile

Progress warns of critical MOVEit Automation auth bypass flaw 
By Sergiu Gatlan 
May 4, 2026
08:18 AM
0 
Progress Software warned customers to patch a critical authentication bypass vulnerability in its MOVEit Automation enterprise-grade managed file transfer (MFT) application.
MOVEit Automation automates complex data workflows without requiring manual scripting and serves as a central automation orchestrator to schedule and manage file transfers between different systems, including local server…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-4670`
- **CVE:** `CVE-2026-5174`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1068** — Exploitation for Privilege Escalation
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable MOVEit Automation instance exposed to CVE-2026-4670 / CVE-2026-5174

`UC_39_4` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Vulnerabilities.signature) as signature values(Vulnerabilities.severity) as severity from datamodel=Vulnerabilities where (Vulnerabilities.cve IN ("CVE-2026-4670","CVE-2026-5174")) OR (Vulnerabilities.signature="*MOVEit Automation*") by Vulnerabilities.dest Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| eval firstSeen=strftime(firstSeen,"%Y-%m-%d %H:%M:%S"), lastSeen=strftime(lastSeen,"%Y-%m-%d %H:%M:%S")
| sort - severity
```

**Defender KQL:**
```kql
// Hunt for hosts vulnerable to the May-2026 MOVEit Automation advisories
let vuln_cves = dynamic(["CVE-2026-4670","CVE-2026-5174"]);
DeviceTvmSoftwareVulnerabilities
| where CveId in (vuln_cves)
   or (SoftwareVendor =~ "progress" and SoftwareName has "moveit" and SoftwareName has "automation")
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform, PublicIP, IsInternetFacing, MachineGroup) by DeviceId
  ) on DeviceId
| project Timestamp, DeviceName, DeviceId, OSPlatform, IsInternetFacing, PublicIP,
          SoftwareVendor, SoftwareName, SoftwareVersion,
          CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by IsInternetFacing desc, VulnerabilitySeverityLevel asc
```

### [LLM] MOVEit Automation service spawning interactive shell or LOLBin (post-exploit hunt)

`UC_39_5` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_path="*\\Progress\\MOVEit Automation\\*" OR Processes.parent_process_path="*\\Ipswitch\\MOVEit Central\\*" OR Processes.parent_process_path="*\\Ipswitch\\MOVEit Automation\\*") (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="mshta.exe" OR Processes.process_name="certutil.exe" OR Processes.process_name="bitsadmin.exe" OR Processes.process_name="rundll32.exe" OR Processes.process_name="regsvr32.exe" OR Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe" OR Processes.process_name="curl.exe" OR Processes.process_name="wget.exe" OR Processes.process_name="whoami.exe" OR Processes.process_name="net.exe" OR Processes.process_name="net1.exe" OR Processes.process_name="nltest.exe" OR Processes.process_name="systeminfo.exe" OR Processes.process_name="tasklist.exe" OR Processes.process_name="quser.exe" OR Processes.process_name="hostname.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process_path Processes.parent_process Processes.process_name Processes.process_path Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Post-exploitation child of MOVEit Automation service binary
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFolderPath has_any (@"\Progress\MOVEit Automation\", @"\Ipswitch\MOVEit Central\", @"\Ipswitch\MOVEit Automation\")
| where FileName in~ (
    "cmd.exe","powershell.exe","pwsh.exe","mshta.exe","certutil.exe",
    "bitsadmin.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe",
    "curl.exe","wget.exe","whoami.exe","net.exe","net1.exe","nltest.exe",
    "systeminfo.exe","tasklist.exe","quser.exe","hostname.exe","reg.exe")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentBinary = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildBinary = FileName,
          ChildCmd = ProcessCommandLine,
          SHA256
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-4670`, `CVE-2026-5174`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
