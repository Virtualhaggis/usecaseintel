# [HIGH] New Linux 'Dirty Frag' zero-day gives root on all major distros

**Source:** BleepingComputer
**Published:** 2026-05-08
**Article:** https://www.bleepingcomputer.com/news/security/new-linux-dirty-frag-zero-day-with-poc-exploit-gives-root-privileges/

## Threat Profile

New Linux 'Dirty Frag' zero-day gives root on all major distros 
By Sergiu Gatlan 
May 8, 2026
03:45 AM
0 
A new Linux zero-day vulnerability, named Dirty Frag, allows local attackers to gain root privileges on most major Linux distributions with a single command.
Security researcher Hyunwoo Kim, who disclosed the flaw earlier today and published a proof-of-concept (PoC) exploit, says this privilege escalation flaw was introduced roughly nine years ago in the Linux kernel's algif_aead cryptograp…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1068** — Exploitation for Privilege Escalation
- **T1547.006** — Boot or Logon Autostart Execution: Kernel Modules and Extensions

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Tampering with Dirty Frag kernel module mitigation file (/etc/modprobe.d/dirtyfrag.conf)

`UC_29_1` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.action) as action values(Filesystem.process_id) as process_id values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_path="/etc/modprobe.d/dirtyfrag.conf" Filesystem.action IN ("deleted","modified","renamed","overwritten") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | where NOT (process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","zypper","puppet","chef-client","ansible-playbook","salt-minion")) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has @"/etc/modprobe.d"
| where FileName =~ "dirtyfrag.conf"
| where ActionType in ("FileDeleted","FileModified","FileRenamed","FileCreated")
| where InitiatingProcessFileName !in~ ("dpkg","apt","apt-get","yum","dnf","rpm","zypper","puppet","chef-client","ansible-playbook","salt-minion","unattended-upgrade")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Manual load of Dirty Frag vulnerable kernel modules (esp4/esp6/rxrpc) outside of init/IPsec/AFS

`UC_29_2` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where Processes.process_name IN ("modprobe","insmod","kmod") (Processes.process="*esp4*" OR Processes.process="*esp6*" OR Processes.process="*rxrpc*") NOT Processes.parent_process_name IN ("systemd","systemd-modules-load","systemd-udevd","networkd-dispatcher","NetworkManager","charon","pluto","libreswan","strongswan","openafs","afsd","kmod") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("modprobe","insmod","kmod")
| where ProcessCommandLine matches regex @"(?i)(^|[\s/])(esp4|esp6|rxrpc)([\s/.]|$)"
| where InitiatingProcessFileName !in~ ("systemd","systemd-modules-load","systemd-udevd","networkd-dispatcher","NetworkManager","charon","pluto","libreswan","strongswan","openafs","afsd","kmod")
| where AccountName != ""
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Article-specific behavioural hunt — New Linux 'Dirty Frag' zero-day gives root on all major distros

`UC_29_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New Linux 'Dirty Frag' zero-day gives root on all major distros ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/modprobe.d/dirtyfrag.conf*" OR Filesystem.file_path="*/dev/null*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New Linux 'Dirty Frag' zero-day gives root on all major distros
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/modprobe.d/dirtyfrag.conf", "/dev/null"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
