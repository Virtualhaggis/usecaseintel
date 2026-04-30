# [HIGH] GitHub fixes RCE flaw that gave access to millions of private repos

**Source:** BleepingComputer
**Published:** 2026-04-29
**Article:** https://www.bleepingcomputer.com/news/security/github-fixes-rce-flaw-that-gave-access-to-millions-of-private-repos/

## Threat Profile

GitHub fixes RCE flaw that gave access to millions of private repos 
By Sergiu Gatlan 
April 29, 2026
08:41 AM
0 
In early March, GitHub patched a critical remote code execution vulnerability ( CVE-2026-3854 ) that could have allowed attackers to access millions of private repositories.
The flaw was reported on March 4, 2026, by researchers at cybersecurity firm Wiz through GitHub's bug bounty program. GitHub Chief Information Security Officer Alexis Wales said the company's security team reprod…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-3854`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1505.005** — Server Software Component: Terminal Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Client-side git push -o payload matching CVE-2026-3854 X-Stat injection

`UC_10_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where Processes.process_name IN ("git","git.exe") AND Processes.process="*push*" AND Processes.process="*-o*" AND (Processes.process="*;rails_env=*" OR Processes.process="*;custom_hooks_dir=*" OR Processes.process="*;repo_pre_receive_hooks=*" OR Processes.process="*large_blob_rejection_enabled=bool:false*" OR Processes.process="*;user_operator_mode=bool:true*" OR Processes.process="*push_option_0=*;*") by host Processes.user Processes.dest Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where FileName in~ ("git","git.exe") or InitiatingProcessFileName in~ ("git","git.exe")
| where ProcessCommandLine has "push" and ProcessCommandLine has "-o"
| where ProcessCommandLine has_any (";rails_env=",";custom_hooks_dir=",";repo_pre_receive_hooks=","large_blob_rejection_enabled=bool:false",";user_operator_mode=bool:true") or ProcessCommandLine matches regex @"push_option_\d+=[^\s'\"]*;"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### [LLM] GHES babeld/gitrpcd spawning interactive shell or interpreter (CVE-2026-3854 hook traversal)

`UC_10_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as exec_path from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("gitrpcd","babeld","git-receive-pack","git-upload-pack") AND Processes.process_name IN ("sh","bash","dash","zsh","python","python3","ruby","perl","nc","ncat","curl","wget") AND NOT (Processes.process_path="/data/repositories/*" OR Processes.process_path="/data/user/repositories/*" OR Processes.process_path="/usr/lib/git-core/*") by host Processes.user Processes.parent_process Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where DeviceName has_any ("ghes","github") or InitiatingProcessFileName in~ ("babeld","gitrpcd","git-receive-pack","git-upload-pack")
| where InitiatingProcessFileName in~ ("babeld","gitrpcd","git-receive-pack","git-upload-pack")
| where FileName in~ ("sh","bash","dash","zsh","python","python3","ruby","perl","nc","ncat","curl","wget")
| where not(FolderPath startswith "/data/repositories/" or FolderPath startswith "/data/user/repositories/" or FolderPath startswith "/usr/lib/git-core/")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-3854`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
