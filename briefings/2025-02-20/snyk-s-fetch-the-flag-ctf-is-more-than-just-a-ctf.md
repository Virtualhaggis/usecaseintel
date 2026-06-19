# [CRIT] Snyk’s Fetch the Flag CTF is More Than Just a CTF

**Source:** Snyk
**Published:** 2025-02-20
**Article:** https://snyk.io/blog/snyks-fetch-the-flag-ctf/

## Threat Profile

Snyk Blog In this article
Written by John Hammond 
February 20, 2025
0 mins read Since 2023, Snyk has partnered with John Hammond to host ‘Fetch the Flag,’ a 12-hour CTF event for thousands of security professionals, practitioners, and members of the DevOps community!
Register for Fetch the Flag Snyk’s Annual Fetch the Flag CTF competition is on February 27 at 9 a.m. EST!
Register here But Capture the Flag sometimes gets a bad rap… with the occasional scrutiny that these exercises aren’t “real w…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-33891`
- **CVE:** `CVE-2022-24439`
- **CVE:** `CVE-2023-40267`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Apache Spark JVM spawning shell — CVE-2022-33891 doAs command injection

`UC_1002_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("java","java.exe") AND (Processes.parent_process="*org.apache.spark*" OR Processes.parent_process="*SparkSubmit*" OR Processes.parent_process="*spark.deploy.master*" OR Processes.parent_process="*spark.deploy.worker*" OR Processes.parent_process="*HistoryServer*") AND Processes.process_name IN ("sh","bash","dash","ksh","zsh","cmd.exe","powershell.exe","pwsh.exe","busybox") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java","java.exe")
| where InitiatingProcessCommandLine has_any ("org.apache.spark","SparkSubmit","spark.deploy.master","spark.deploy.worker","HistoryServer")
| where FileName in~ ("sh","bash","dash","ksh","zsh","cmd.exe","powershell.exe","pwsh","pwsh.exe","busybox")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### GitPython ext::sh URL command injection — CVE-2022-24439

`UC_1002_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python","python.exe","python3","python3.exe","pip","pip.exe","pip3","pip3.exe") OR Processes.parent_process IN ("*GitPython*","*git.Repo*","*clone_from*")) AND (Processes.process="*ext::sh*" OR Processes.process="*ext::*-c*" OR Processes.process="*protocol.ext.allow=always*") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python","python3","python3.exe","pip","pip.exe","pip3","pip3.exe")
   or InitiatingProcessCommandLine has_any ("GitPython","git.Repo","clone_from","Repo.clone")
| where ProcessCommandLine has "ext::"
   or ProcessCommandLine has "protocol.ext.allow=always"
   or ProcessCommandLine matches regex @"(?i)ext::\s*sh\s+-c"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
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
  - CVE(s): `CVE-2022-33891`, `CVE-2022-24439`, `CVE-2023-40267`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
