# [CRIT] A serious security flaw in runC can result in root privilege escalation in Docker and Kubernetes

**Source:** Snyk
**Published:** 2019-02-13
**Article:** https://snyk.io/blog/a-serious-security-flaw-in-runc-can-result-in-root-privilege-escalation-in-docker-and-kubernetes/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
February 13, 2019
0 mins read A security flaw discovered by Adam Iwaniuk and Borys Popławski and found in open source software  runC  was disclosed on February 11th, 2019 and described in  CVE-2019-5736 .
The vulnerability, affecting several container engines such as Docker and Kubernetes, is found in a key component of container engines and allows containers to break out of their isolated context and gain access to the host server which they run o…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2019-5736`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1611** — Escape to Host
- **T1610** — Deploy Container
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Host runc binary overwrite from container (CVE-2019-5736 escape-to-host)

`UC_3548_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/usr/bin/runc","/usr/sbin/runc","/usr/bin/docker-runc","/usr/sbin/docker-runc","/usr/local/bin/runc","/usr/bin/containerd-shim-runc-v2") OR Filesystem.file_name IN ("runc","docker-runc","containerd-shim-runc-v2")) (Filesystem.action IN ("modified","created","write","rename")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.action Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("runc","docker-runc","runc.amd64","containerd-shim-runc-v2")
| where FolderPath has_any ("/usr/bin","/usr/sbin","/usr/local/bin","/usr/local/sbin")
| where ActionType in ("FileModified","FileCreated","FileRenamed")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","apt","apt-get","yum","dnf","zypper","tar","dockerd","containerd")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### runc /proc/self/exe re-exec abuse (CVE-2019-5736 exploit primitive)

`UC_3548_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*/proc/self/exe*" OR Processes.process_path="*/proc/self/exe*" OR Processes.parent_process="*/proc/self/exe*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "/proc/self/exe" or InitiatingProcessCommandLine has "/proc/self/exe" or FolderPath has "/proc/self/exe"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
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
  - CVE(s): `CVE-2019-5736`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
