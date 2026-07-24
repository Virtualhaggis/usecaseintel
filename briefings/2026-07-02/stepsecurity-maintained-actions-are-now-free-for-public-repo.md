# [HIGH] StepSecurity Maintained Actions Are Now Free for Public Repos

**Source:** StepSecurity
**Published:** 2026-07-02
**Article:** https://www.stepsecurity.io/blog/stepsecurity-maintained-actions-are-now-free-for-public-repos

## Threat Profile

Back to Blog Product StepSecurity Maintained Actions Are Now Free for Public Repos StepSecurity Maintained Actions are now free for public repos. Secure, drop-in replacements for risky third-party GitHub Actions, reviewed and actively maintained. Varun Sharma View LinkedIn June 29, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Today we are excited to announce that StepSecurity Maintained Actions are now free for public repos…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-30066`
- **SHA1:** `0e58ed8671d6b60d0890c21b07f8835ace038e67`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1105** — Ingress Tool Transfer
- **T1195.001** — Compromise Software Supply Chain: Software Dependencies and Development Tools
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GitHub Actions runner outbound to gist.githubusercontent.com (tj-actions/changed-files CVE-2025-30066)

`UC_233_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*gist.githubusercontent.com*" OR Web.url="*gist.github.com*") by Web.src Web.dest Web.url Web.http_user_agent Web.app
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "gist.githubusercontent.com" or RemoteUrl has "gist.github.com"
| where InitiatingProcessFileName in~ ("node.exe","node","python.exe","python3","python","curl.exe","curl","wget","Runner.Worker.exe","Runner.Worker")
     or InitiatingProcessParentFileName in~ ("Runner.Worker.exe","Runner.Worker","node.exe","node")
     or InitiatingProcessFolderPath has_any ("actions-runner","_work","_actions")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### tj-actions/changed-files malicious commit 0e58ed86 referenced on host (CVE-2025-30066)

`UC_233_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*0e58ed8671d6b60d0890c21b07f8835ace038e67*" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
let ioc = "0e58ed8671d6b60d0890c21b07f8835ace038e67";
union
 (DeviceProcessEvents
  | where Timestamp > ago(90d)
  | where ProcessCommandLine has ioc or InitiatingProcessCommandLine has ioc
  | project Timestamp, DeviceName, Source="ProcessEvent", Account=AccountName, Evidence=ProcessCommandLine, Context=InitiatingProcessCommandLine),
 (DeviceFileEvents
  | where Timestamp > ago(90d)
  | where FolderPath has ioc or FileName has ioc or FolderPath has "tj-actions/changed-files"
  | project Timestamp, DeviceName, Source="FileEvent", Account=InitiatingProcessAccountName, Evidence=FolderPath, Context=InitiatingProcessCommandLine)
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
  - CVE(s): `CVE-2025-30066`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `0e58ed8671d6b60d0890c21b07f8835ace038e67`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 5 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
