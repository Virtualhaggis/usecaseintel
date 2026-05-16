# [HIGH] reviewdog GitHub Actions are compromised

**Source:** StepSecurity
**Published:** 2025-07-08
**Article:** https://www.stepsecurity.io/blog/reviewdog-github-actions-are-compromised

## Threat Profile

Back to Blog Threat Intel reviewdog GitHub Actions are compromised The supply chain compromise of reviewdog GitHub Actions has been resolved. This post summarizes the incident, how it was discovered, and what you should do to protect your workflows Varun Sharma View LinkedIn March 18, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Introduction We have concluded our investigation into the supply chain attack affecting several …

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `f0d342d24037bb11d26b9bd8496e0808ba32e9ec`
- **SHA1:** `fab6de28ae8bc2a032c9e655d990afa450edb995`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1554** — Compromise Host Software Binary
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1003.007** — OS Credential Dumping: Proc Filesystem
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.006** — Command and Scripting Interpreter: Python

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Compromised reviewdog/action-setup commit SHA referenced in GitHub Actions workflow (CVE-2025-30154)

`UC_697_2` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Change.command) as command values(Change.object_attrs) as object_attrs values(Change.user) as user from datamodel=Change where (Change.object="reviewdog/action-setup" OR Change.command="*reviewdog/action-setup*" OR Change.object_attrs="*reviewdog/action-setup*") by Change.object Change.action _time span=1h | `drop_dm_object_name(Change)` | eval malicious_sha=if(match(object_attrs,"f0d342d24037bb11d26b9bd8496e0808ba32e9ec"),1,0) | eval v1_tag_in_window=if((match(object_attrs,"reviewdog/action-setup@v1($|[^a-f0-9])") OR match(command,"reviewdog/action-setup@v1($|[^a-f0-9])")) AND _time>=strptime("2025-03-11 18:42:00","%Y-%m-%d %H:%M:%S") AND _time<=strptime("2025-03-11 20:31:00","%Y-%m-%d %H:%M:%S"),1,0) | where malicious_sha=1 OR v1_tag_in_window=1 | convert ctime(firstTime) ctime(lastTime)
```

### [LLM] GitHub Actions Runner.Worker memory dumped via /proc on Linux runner (reviewdog payload)

`UC_697_3` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_name) as process_name values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.os="Linux" Processes.process_name IN ("python","python2","python3") (Processes.process="*Runner.Worker*" OR (Processes.process="*/proc/*" AND Processes.process IN ("*/maps*","*/mem*")) OR Processes.parent_process_name="Runner.Worker" OR Processes.parent_process="*Runner.Worker*") by host Processes.dest Processes.process_id Processes.parent_process_id | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Defender for Endpoint Linux on a self-hosted GitHub runner
let RunnerWorkerCue = dynamic(["Runner.Worker","/proc/","/maps","/mem","cmdline_f","map_path","mem_path"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessVersionInfoProductName has "Linux" or FolderPath startswith "/usr/" or FolderPath startswith "/opt/" or FolderPath startswith "/home/"
| where FileName in~ ("python","python2","python3") or InitiatingProcessFileName in~ ("python","python2","python3")
| where ProcessCommandLine has "Runner.Worker"
   or (ProcessCommandLine has "/proc/" and (ProcessCommandLine has "/maps" or ProcessCommandLine has "/mem"))
   or InitiatingProcessParentFileName =~ "Runner.Worker"
   or InitiatingProcessFileName =~ "Runner.Worker"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine,
          Parent = InitiatingProcessFileName,
          GrandParent = InitiatingProcessParentFileName,
          ParentCmd = InitiatingProcessCommandLine, SHA256
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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `f0d342d24037bb11d26b9bd8496e0808ba32e9ec`, `fab6de28ae8bc2a032c9e655d990afa450edb995`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
