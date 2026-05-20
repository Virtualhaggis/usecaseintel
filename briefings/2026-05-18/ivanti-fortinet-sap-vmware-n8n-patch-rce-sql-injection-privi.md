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
- **T1059** — Command and Scripting Interpreter
- **T1068** — Exploitation for Privilege Escalation
- **T1059.004** — Unix Shell
- **T1059.001** — PowerShell
- **T1505.003** — Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] n8n Git node CLI argument injection (CVE-2026-44790) — git child of node with --upload-pack/--receive-pack/-c core.sshCommand

`UC_25_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node","node.exe","n8n","n8n.exe") (Processes.process_name="git" OR Processes.process_name="git.exe") (Processes.process="*--upload-pack=*" OR Processes.process="*--receive-pack=*" OR Processes.process="*-c core.sshCommand=*" OR Processes.process="*--exec=*" OR Processes.process="*-u *" OR Processes.process="*core.sshCommand*") by host Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | rename firstTime as firstTime, lastTime as lastTime | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node","node.exe","n8n","n8n.exe")
| where FileName in~ ("git","git.exe")
| where ProcessCommandLine has_any ("--upload-pack=", "--receive-pack=", "core.sshCommand", "--exec=")
   or ProcessCommandLine matches regex @"(?i)-c\s+core\.sshCommand"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] n8n Node.js worker spawning interactive shell — RCE chained from prototype-pollution CVEs (42231/42232/44789/44791)

`UC_25_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node","node.exe","n8n","n8n.exe") (Processes.process_name IN ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh","pwsh.exe","nc","ncat","socat") OR Processes.process="*/dev/tcp/*" OR Processes.process="*bash -i*" OR Processes.process="*IEX*" OR Processes.process="*Invoke-Expression*" OR Processes.process="*FromBase64String*" OR Processes.process="*-EncodedCommand*") by host Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node","node.exe","n8n","n8n.exe")
| where FileName in~ ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh","pwsh.exe","nc","ncat","socat","python","python3","perl","ruby")
   or ProcessCommandLine has_any ("/dev/tcp/","bash -i","sh -i","IEX","Invoke-Expression","FromBase64String","-EncodedCommand","socket.socket")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] Vulnerable n8n / Ivanti Xtraction / FortiAuthenticator / FortiSandbox / SAP / VMware Fusion inventory — exposure surface map

`UC_25_7` · phase: **recon** · confidence: **High**

**Defender KQL:**
```kql
let TargetCves = dynamic([
    "CVE-2026-8043",   // Ivanti Xtraction
    "CVE-2026-44277",  // FortiAuthenticator
    "CVE-2026-26083",  // FortiSandbox
    "CVE-2026-34260",  // SAP S/4HANA
    "CVE-2026-34263",  // SAP Commerce Cloud
    "CVE-2026-41702",  // VMware Fusion
    "CVE-2026-42231","CVE-2026-42232","CVE-2026-44789","CVE-2026-44790","CVE-2026-44791" // n8n
]);
DeviceTvmSoftwareVulnerabilities
| where CveId in (TargetCves)
| join kind=leftouter DeviceTvmSoftwareVulnerabilitiesKB on CveId
| project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion,
          CveId, VulnerabilitySeverityLevel, CvssScore, IsExploitAvailable,
          RecommendedSecurityUpdate, PublishedDate
| order by CvssScore desc, DeviceName asc
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

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
