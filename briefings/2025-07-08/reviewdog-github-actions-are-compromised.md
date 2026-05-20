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

- **CVE:** `CVE-2025-30154`
- **CVE:** `CVE-2025-30066`
- **SHA1:** `f0d342d24037bb11d26b9bd8496e0808ba32e9ec`
- **SHA1:** `b833eecdf13c615cd60d5dede6f6593a4b3b4376`
- **SHA1:** `0e58ed8671d6b60d0890c21b07f8835ace038e67`
- **SHA1:** `6e6023c01918b353229af0881232f601a4cc8365`
- **SHA1:** `f5434e31b6259b4e08684618a305bae127b6d784`
- **SHA1:** `0f176b316e1d41a945e574fc2ba76b0dc752d585`
- **SHA1:** `96be5a72d8adac89200e08658f69273912fe4783`
- **SHA1:** `61902a2b3c982d3551ad219bb0ff22f3663e44de`
- **SHA1:** `f966d8d897bc8033657b8e77da56a988029ce8c7`
- **SHA1:** `909ace6b17fc4045030e55f5ac27ca99f276ae80`
- **SHA1:** `454c8a19a12cde77505464d7e4549500c8ac68d0`
- **SHA1:** `04d5b6d4c18c06d7df6edabf914d0ded986c3a87`
- **SHA1:** `81796e43b6348d628e3e739a910d50704a5292c1`
- **SHA1:** `8d73381aa1c2ccd12c8ddcfefa47aeb1443e67e3`
- **SHA1:** `c27af8180030e1f3d0434473731f030dc1849edf`
- **SHA1:** `efa6ce46bcaa8751ad223e44be7977798c909304`
- **SHA1:** `143a52c0d919c1a69bdeafeab564650f6939a2b3`
- **SHA1:** `31b1df0e735ad8511fd7df3be8cf9351d8cb4de7`
- **SHA1:** `26f36301be817815fbcb896d2c85e89f04b17df4`
- **SHA1:** `9bb460e92befdbb6506d2e643ae06c8b50205f97`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
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

`UC_697_3` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Change.command) as command values(Change.object_attrs) as object_attrs values(Change.user) as user from datamodel=Change where (Change.object="reviewdog/action-setup" OR Change.command="*reviewdog/action-setup*" OR Change.object_attrs="*reviewdog/action-setup*") by Change.object Change.action _time span=1h | `drop_dm_object_name(Change)` | eval malicious_sha=if(match(object_attrs,"f0d342d24037bb11d26b9bd8496e0808ba32e9ec"),1,0) | eval v1_tag_in_window=if((match(object_attrs,"reviewdog/action-setup@v1($|[^a-f0-9])") OR match(command,"reviewdog/action-setup@v1($|[^a-f0-9])")) AND _time>=strptime("2025-03-11 18:42:00","%Y-%m-%d %H:%M:%S") AND _time<=strptime("2025-03-11 20:31:00","%Y-%m-%d %H:%M:%S"),1,0) | where malicious_sha=1 OR v1_tag_in_window=1 | convert ctime(firstTime) ctime(lastTime)
```

### [LLM] GitHub Actions Runner.Worker memory dumped via /proc on Linux runner (reviewdog payload)

`UC_697_4` · phase: **actions** · confidence: **High**

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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-30154`, `CVE-2025-30066`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `f0d342d24037bb11d26b9bd8496e0808ba32e9ec`, `b833eecdf13c615cd60d5dede6f6593a4b3b4376`, `0e58ed8671d6b60d0890c21b07f8835ace038e67`, `6e6023c01918b353229af0881232f601a4cc8365`, `f5434e31b6259b4e08684618a305bae127b6d784`, `0f176b316e1d41a945e574fc2ba76b0dc752d585`, `96be5a72d8adac89200e08658f69273912fe4783`, `61902a2b3c982d3551ad219bb0ff22f3663e44de` _(+12 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
