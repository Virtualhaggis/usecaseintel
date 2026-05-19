# [CRIT] Ivanti, Fortinet, SAP, VMware, n8n Patch RCE, SQL Injection, Privilege Escalation Flaws

**Source:** The Hacker News
**Published:** 2026-05-18
**Article:** https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html

## Threat Profile

Ivanti, Fortinet, SAP, VMware, n8n Patch RCE, SQL Injection, Privilege Escalation Flaws 
 Ravie Lakshmanan  May 18, 2026 Vulnerability / Software Security 
Ivanti, Fortinet, n8n, SAP, and VMware have released security fixes for various vulnerabilities that could be exploited by bad actors to bypass authentication and execute arbitrary code.
Topping the list is a critical flaw impacting Ivanti Xtraction (CVE-2026-8043, CVSS score: 9.6) that could be exploited to achieve information disclosure o…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-8043`
- **CVE:** `CVE-2026-44277`
- **CVE:** `CVE-2026-26083`
- **CVE:** `CVE-2026-34260`
- **CVE:** `CVE-2026-34263`
- **CVE:** `CVE-2026-41702`
- **CVE:** `CVE-2026-42231`
- **CVE:** `CVE-2026-42232`
- **CVE:** `CVE-2026-44791`
- **CVE:** `CVE-2026-44789`
- **CVE:** `CVE-2026-44790`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1592** — Gather Victim Host Information
- **T1059** — Command and Scripting Interpreter
- **T1068** — Exploitation for Privilege Escalation
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1005** — Data from Local System
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable inventory hunt: May 2026 Ivanti/Fortinet/SAP/VMware/n8n patch bundle

`UC_18_5` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen values(Vulnerabilities.signature) as signature values(Vulnerabilities.severity) as severity from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-8043","CVE-2026-44277","CVE-2026-26083","CVE-2026-34260","CVE-2026-34263","CVE-2026-41702","CVE-2026-42231","CVE-2026-42232","CVE-2026-44789","CVE-2026-44790","CVE-2026-44791") by Vulnerabilities.dest Vulnerabilities.cve | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstSeen) ctime(lastSeen) | sort -lastSeen
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-8043","CVE-2026-44277","CVE-2026-26083","CVE-2026-34260","CVE-2026-34263","CVE-2026-41702","CVE-2026-42231","CVE-2026-42232","CVE-2026-44789","CVE-2026-44790","CVE-2026-44791")
| join kind=leftouter (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, CvssScore, IsExploitAvailable, PublishedDate) on CveId
| summarize DeviceCount = dcount(DeviceName),
            Devices    = make_set(DeviceName, 50),
            FirstSeen  = min(Timestamp),
            LastSeen   = max(Timestamp)
            by CveId, SoftwareVendor, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate, VulnerabilitySeverityLevel, CvssScore, IsExploitAvailable
| order by CvssScore desc, DeviceCount desc
```

### [LLM] n8n (Node.js) host spawning unexpected shell or script interpreter — likely CVE-2026-42231/42232/44789/44791 post-exploit

`UC_18_6` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as child_cmdlines values(Processes.parent_process) as parent_cmdline from datamodel=Endpoint.Processes where (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node") AND (Processes.parent_process="*n8n*") AND (Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","sh","bash","zsh","dash","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe")) by host Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | sort -lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where InitiatingProcessCommandLine contains "n8n"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","sh","bash","zsh","dash","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          NodeCmd  = InitiatingProcessCommandLine,
          NodePath = InitiatingProcessFolderPath,
          ChildBinary = FileName,
          ChildCmd    = ProcessCommandLine,
          ChildSHA256 = SHA256,
          NodeSHA256  = InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] n8n Git node Push CLI flag injection — CVE-2026-44790 arbitrary file read

`UC_18_7` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as git_cmdlines from datamodel=Endpoint.Processes where (Processes.process_name="git.exe" OR Processes.process_name="git") AND (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node") AND (Processes.parent_process="*n8n*") AND (Processes.process="*--upload-pack*" OR Processes.process="*--receive-pack*" OR Processes.process="*--exec=*" OR Processes.process="*--exec-path*" OR Processes.process="*core.sshCommand*" OR Processes.process="*--config-env*" OR Processes.process="*protocol.ext.allow*" OR Processes.process="*core.gitProxy*" OR Processes.process="*core.fsmonitor*" OR Processes.process="*core.editor*") by host Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | sort -lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("git.exe","git")
| where InitiatingProcessFileName in~ ("node.exe","node")
| where InitiatingProcessCommandLine contains "n8n"
| where ProcessCommandLine has_any (
    "--upload-pack",
    "--receive-pack",
    "--exec=",
    "--exec-path",
    "core.sshCommand",
    "--config-env",
    "protocol.ext.allow",
    "core.gitProxy",
    "core.fsmonitor",
    "core.editor",
    "core.hooksPath",
    "--no-verify"
  )
| project Timestamp, DeviceName, AccountName,
          NodeCmd = InitiatingProcessCommandLine,
          GitCmd  = ProcessCommandLine,
          GitPath = FolderPath,
          InitiatingProcessSHA256
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

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-8043`, `CVE-2026-44277`, `CVE-2026-26083`, `CVE-2026-34260`, `CVE-2026-34263`, `CVE-2026-41702`, `CVE-2026-42231`, `CVE-2026-42232` _(+3 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
