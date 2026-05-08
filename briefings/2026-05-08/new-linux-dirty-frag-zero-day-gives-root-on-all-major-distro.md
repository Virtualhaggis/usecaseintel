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


Security researcher Hyunwoo Kim, who disclosed the flaw earlier today and published a proof-of-concept (PoC) exploit, says this privilege escalation flaw was introduced roughly nine years ago in the Linux kernel's algif_aead cr…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1068** — Exploitation for Privilege Escalation
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1548.003** — Abuse Elevation Control Mechanism: Sudo and Sudo Caching

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Dirty Frag Linux LPE — modprobe blacklist mitigation deployment tracking

`UC_3_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="rmmod" AND Processes.process="*esp4*" AND Processes.process="*esp6*" AND Processes.process="*rxrpc*" by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="/etc/modprobe.d/dirtyfrag.conf" by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
( DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FolderPath has "/etc/modprobe.d/" and FileName =~ "dirtyfrag.conf"
  | where ActionType in ("FileCreated","FileModified","FileRenamed")
  | project Timestamp, DeviceName, Source="file:dirtyfrag.conf", FolderPath, FileName,
            InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName ),
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName =~ "rmmod"
  | where ProcessCommandLine has "esp4" and ProcessCommandLine has "esp6" and ProcessCommandLine has "rxrpc"
  | project Timestamp, DeviceName, Source="proc:rmmod-esp-rxrpc", FolderPath, FileName,
            InitiatingProcessFileName=InitiatingProcessFileName,
            InitiatingProcessCommandLine=ProcessCommandLine,
            InitiatingProcessAccountName=AccountName )
| order by Timestamp desc
```

### [LLM] Dirty Frag post-exploitation — non-root Linux process modifies /etc/shadow|/etc/passwd|/etc/sudoers

`UC_3_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/shadow" OR Filesystem.file_path="/etc/passwd" OR Filesystem.file_path="/etc/sudoers" OR Filesystem.file_path="/etc/sudoers.d/*" OR Filesystem.file_path="/root/.ssh/authorized_keys") AND Filesystem.action IN ("modified","created","write","renamed") AND Filesystem.user!="root" AND Filesystem.user!="0" AND Filesystem.user!="unknown" AND Filesystem.user!="" by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _linux_hosts = DeviceInfo
    | where OSPlatform =~ "Linux"
    | summarize arg_max(Timestamp, *) by DeviceId
    | project DeviceId;
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceId in (_linux_hosts)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath in ("/etc/shadow","/etc/passwd","/etc/sudoers"))
     or (FolderPath startswith "/etc/sudoers.d/")
     or (FolderPath endswith "/.ssh/authorized_keys" and FolderPath has "/root/")
| where InitiatingProcessAccountName != "root"
     and isnotempty(InitiatingProcessAccountName)
     and InitiatingProcessAccountSid !in ("S-1-5-18","0")
| where InitiatingProcessFileName !in~ ("passwd","chpasswd","useradd","usermod","userdel","groupadd","visudo","pwck","vipw","sudo")  // exclude legitimate setuid helpers that already enforce policy
| project Timestamp, DeviceName, FolderPath, FileName, ActionType,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — New Linux 'Dirty Frag' zero-day gives root on all major distros

`UC_3_0` · phase: **install** · confidence: **High**

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

Severity classified as **HIGH** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
