# [HIGH] New Gogs zero-day flaw lets hackers get remote code execution

**Source:** BleepingComputer
**Published:** 2026-05-28
**Article:** https://www.bleepingcomputer.com/news/security/new-gogs-zero-day-flaw-lets-hackers-get-remote-code-execution/

## Threat Profile

New Gogs zero-day flaw lets hackers get remote code execution 
By Sergiu Gatlan 
May 28, 2026
10:25 AM
0 


An unpatched zero-day vulnerability in the Gogs self-hosted Git service can allow attackers to gain remote code execution (RCE) on Internet-facing instances.


Designed as an alternative to GitHub Enterprise or GitLab and written in Go, Gogs is often exposed online for remote collaboration.


This critical severity argument injection security flaw has yet to be assigned a CVE ID, aff…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-39933`
- **CVE:** `CVE-2024-39932`
- **CVE:** `CVE-2026-26194`
- **CVE:** `CVE-2024-39930`
- **CVE:** `CVE-2025-8110`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1068** — Exploitation for Privilege Escalation
- **T1505.003** — Server Software Component: Web Shell
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Gogs RCE: git rebase invoked with --exec flag (argument injection)

`UC_5_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.user) as user values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where Processes.parent_process_name="gogs" Processes.process_name="git" Processes.process="*rebase*" (Processes.process="*--exec*" OR Processes.process="* -x *" OR Processes.process="*-x=*") by host Processes.process_name Processes.parent_process_name Processes.user | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "gogs"
| where FileName =~ "git"
| where ProcessCommandLine has "rebase"
| where ProcessCommandLine has_any ("--exec", "-x=", "--exec=")
| project Timestamp, DeviceName, AccountName,
          GogsCmd = InitiatingProcessCommandLine,
          GitCmd  = ProcessCommandLine,
          GitPath = FolderPath,
          ProcessId
| order by Timestamp desc
```

### [LLM] Post-exploit shell or LOLBin spawned by git invoked from Gogs server

`UC_5_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as child_cmd values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where Processes.parent_process_name="git" Processes.process_name IN ("sh","bash","dash","zsh","curl","wget","nc","ncat","python","python3","perl","socat","base64","chmod","id","whoami","uname","cat") by host Processes.process_name Processes.parent_process_name Processes.user | `drop_dm_object_name(Processes)` | join type=inner host [| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name="git" Processes.parent_process_name="gogs" by host | fields host] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let GogsHosts = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "gogs" and FileName =~ "git"
    | distinct DeviceId;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId in (GogsHosts)
| where InitiatingProcessFileName =~ "git"
| where InitiatingProcessParentFileName =~ "gogs"
| where FileName in~ ("sh","bash","dash","zsh","curl","wget","nc","ncat","python","python3","perl","socat","base64","chmod","id","whoami","uname","cat","openssl")
| project Timestamp, DeviceName, AccountName,
          ChildProc = FileName,
          ChildCmd  = ProcessCommandLine,
          GitCmd    = InitiatingProcessCommandLine,
          GogsCmd   = InitiatingProcessParentFileName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-39933`, `CVE-2024-39932`, `CVE-2026-26194`, `CVE-2024-39930`, `CVE-2025-8110`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
