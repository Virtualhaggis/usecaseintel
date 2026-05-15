# [HIGH] Evolving Harden-Runner’s disable-sudo Policy for Improved Runner Security

**Source:** StepSecurity
**Published:** 2025-07-08
**Article:** https://www.stepsecurity.io/blog/evolving-harden-runners-disable-sudo-policy-for-improved-runner-security

## Threat Profile

Back to Blog Threat Intel Evolving Harden-Runner’s disable-sudo Policy for Improved Runner Security This post details a vulnerability to bypass Harden-Runner’s disable-sudo policy, the assigned CVE, and the steps we’ve taken to mitigate and detect it. Varun Sharma View LinkedIn April 21, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Summary Harden-Runner secures CI/CD workflows by controlling network access and monitoring ac…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-30066`
- **CVE:** `CVE-2025-32955`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1611** — Escape to Host
- **T1610** — Deploy Container
- **T1068** — Exploitation for Privilege Escalation
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Privileged or host-mounting container launch by GitHub Actions runner user (CVE-2025-32955)

`UC_700_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("docker","ctr","nerdctl","podman","runc")) AND (Processes.process="*--privileged*" OR Processes.process="* -v /:*" OR Processes.process="*--volume /:*" OR Processes.process="*--volume=/:*" OR Processes.process="*-v /var/run/docker.sock*" OR Processes.process="*-v /run/containerd/containerd.sock*" OR Processes.process="*--pid=host*" OR Processes.process="*--userns=host*" OR Processes.process="*--ipc=host*" OR Processes.process="*--net=host*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | where (user="runner" OR like(parent_process,"%/Runner.Worker%") OR like(parent_process,"%/actions-runner%") OR like(process_path,"%/home/runner/_work%") OR like(process,"%/home/runner/_work%")) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// CVE-2025-32955 — Harden-Runner disable-sudo bypass via Docker
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("docker","ctr","nerdctl","podman","runc")
| where ProcessCommandLine has_any (
    "--privileged",
    " -v /:", "--volume /:", "--volume=/:",
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "--pid=host", "--userns=host", "--ipc=host", "--net=host"
  )
| where AccountName =~ "runner"
    or InitiatingProcessFolderPath has_any ("/home/runner/_work","/actions-runner","/runner/_work","/_work")
    or InitiatingProcessFileName in~ ("Runner.Worker","Runner.Listener","run-docker.sh")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessParentFileName,
          FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] Direct Docker/containerd socket abuse by runner workflow (CLI-less CVE-2025-32955 exploitation)

`UC_700_3` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("curl","wget","socat","nc","ncat","python","python3","perl","ruby","node")) AND (Processes.process="*/var/run/docker.sock*" OR Processes.process="*/run/containerd/containerd.sock*" OR Processes.process="*--unix-socket*docker.sock*" OR Processes.process="*--unix-socket*containerd.sock*" OR Processes.process="*UNIX-CONNECT:/var/run/docker.sock*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where (user="runner" OR like(parent_process,"%/Runner.Worker%") OR like(parent_process,"%/actions-runner%") OR like(process,"%/home/runner/_work%")) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// CVE-2025-32955 — direct docker.sock / containerd.sock abuse (no docker CLI)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("curl","wget","socat","nc","ncat","python","python3","perl","ruby","node")
| where ProcessCommandLine has_any (
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "--unix-socket",
    "UNIX-CONNECT:/var/run/docker.sock",
    "UNIX-CONNECT:/run/containerd"
  )
| where AccountName =~ "runner"
    or InitiatingProcessFolderPath has_any ("/home/runner/_work","/actions-runner","/_work")
    or InitiatingProcessFileName in~ ("Runner.Worker","Runner.Listener","bash","sh","node")
    or ProcessCommandLine has "/home/runner/_work"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessParentFileName
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
  - CVE(s): `CVE-2025-30066`, `CVE-2025-32955`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
