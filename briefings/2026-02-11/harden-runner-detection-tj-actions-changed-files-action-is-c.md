# [HIGH] Harden-Runner detection: tj-actions/changed-files action is compromised

**Source:** StepSecurity
**Published:** 2026-02-11
**Article:** https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised

## Threat Profile

Back to Blog Threat Intel Harden-Runner detection: tj-actions/changed-files action is compromised We have concluded our investigation into the tj-actions/changed-files compromise. This post explains how the attack worked, how we detected it, and what steps you should take to secure your CI/CD environment. Varun Sharma View LinkedIn March 14, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Introduction We have concluded our inv…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-30066`
- **SHA1:** `0e58ed8671d6b60d0890c21b07f8835ace038e67`
- **SHA1:** `3dbe17c78367e7d60f00d78ae6781a35be47b4a1`
- **MD5:** `30e525b776c409e03c2d6f328f254965`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1567.001** — Exfiltration to Code Repository
- **T1105** — Ingress Tool Transfer
- **T1552.001** — Credentials in Files
- **T1059.004** — Unix Shell
- **T1003** — OS Credential Dumping
- **T1554** — Compromise Host Software Binary

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] tj-actions/changed-files compromise: self-hosted runner egress to nikitastupin memdump gist (CVE-2025-30066)

`UC_384_3` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.http_user_agent) as user_agents values(Web.http_method) as methods from datamodel=Web where Web.url="*gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965*" by Web.src Web.dest Web.user Web.url | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "nikitastupin/30e525b776c409e03c2d6f328f254965"
    or (RemoteUrl has "gist.githubusercontent.com" and RemoteUrl has "nikitastupin")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### [LLM] tj-actions/changed-files compromise: memdump.py secret-exfiltration shell pattern on runner (CVE-2025-30066)

`UC_384_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Endpoint.Processes.parent_process) as parent_processes from datamodel=Endpoint.Processes where (Endpoint.Processes.process="*nikitastupin/30e525b776c409e03c2d6f328f254965*" OR Endpoint.Processes.process="*memdump.py*" OR Endpoint.Processes.process="*Runner.Worker*" OR Endpoint.Processes.process="*\"isSecret\":true*" OR Endpoint.Processes.process="*base64 -w 0 | base64 -w 0*") by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.parent_process_name Endpoint.Processes.process_name Endpoint.Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any (
        "nikitastupin/30e525b776c409e03c2d6f328f254965",
        "memdump.py",
        "Runner.Worker",
        @"""isSecret"":true",
        "base64 -w 0 | base64 -w 0"
    )
   or InitiatingProcessCommandLine has_any (
        "nikitastupin/30e525b776c409e03c2d6f328f254965",
        "memdump.py",
        @"""isSecret"":true"
    )
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] tj-actions/changed-files compromise: malicious commit SHA 0e58ed86... referenced on host (CVE-2025-30066)

`UC_384_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.Processes.process="*0e58ed8671d6b60d0890c21b07f8835ace038e67*" by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.parent_process_name Endpoint.Processes.process_name Endpoint.Processes.process | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*0e58ed8671d6b60d0890c21b07f8835ace038e67*" by Web.src Web.dest Web.url Web.user | `drop_dm_object_name(Web)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union isfuzzy=true
    (DeviceProcessEvents
     | where Timestamp > ago(30d)
     | where ProcessCommandLine has "0e58ed8671d6b60d0890c21b07f8835ace038e67"
          or InitiatingProcessCommandLine has "0e58ed8671d6b60d0890c21b07f8835ace038e67"
     | project Timestamp, DeviceName, Source="Process", Account=AccountName,
               Image=FileName, Details=ProcessCommandLine, Parent=InitiatingProcessFileName),
    (DeviceNetworkEvents
     | where Timestamp > ago(30d)
     | where RemoteUrl has "0e58ed8671d6b60d0890c21b07f8835ace038e67"
          or InitiatingProcessCommandLine has "0e58ed8671d6b60d0890c21b07f8835ace038e67"
     | project Timestamp, DeviceName, Source="Network", Account=InitiatingProcessAccountName,
               Image=InitiatingProcessFileName, Details=RemoteUrl, Parent=InitiatingProcessParentFileName),
    (DeviceFileEvents
     | where Timestamp > ago(30d)
     | where InitiatingProcessCommandLine has "0e58ed8671d6b60d0890c21b07f8835ace038e67"
          or FolderPath has "0e58ed8671d6b60d0890c21b07f8835ace038e67"
     | project Timestamp, DeviceName, Source="File", Account=InitiatingProcessAccountName,
               Image=InitiatingProcessFileName, Details=strcat(FolderPath, "\\", FileName), Parent="")
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
  - file hash IOC(s): `0e58ed8671d6b60d0890c21b07f8835ace038e67`, `3dbe17c78367e7d60f00d78ae6781a35be47b4a1`, `30e525b776c409e03c2d6f328f254965`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
