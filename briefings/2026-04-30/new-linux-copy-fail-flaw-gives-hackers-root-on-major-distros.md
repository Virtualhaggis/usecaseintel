# [HIGH] New Linux ‘Copy Fail’ flaw gives hackers root on major distros

**Source:** BleepingComputer
**Published:** 2026-04-30
**Article:** https://www.bleepingcomputer.com/news/security/new-linux-copy-fail-flaw-gives-hackers-root-on-major-distros/

## Threat Profile

New Linux ‘Copy Fail’ flaw gives hackers root on major distros 
By Bill Toulas 
April 30, 2026
09:54 AM
0 
An exploit has been published for a local privilege escalation vulnerability dubbed “Copy Fail” that impacts Linux kernels released since 2017, allowing an unprivileged local attacker to gain root permissions.
The vulnerability is tracked as CVE-2026-31431 and was discovered by the offensive security company Theori, using its AI-driven pentesting platform Xint Code after scaning the Linux c…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-31431`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1068** — Exploitation for Privilege Escalation
- **T1548.001** — Setuid and Setgid
- **T1547.006** — Boot or Logon Autostart Execution: Kernel Modules and Extensions

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Copy Fail: setuid-root binary modified by non-package-manager process

`UC_10_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path values(Filesystem.process_exec) as process_exec from datamodel=Endpoint.Filesystem where Filesystem.action=modified Filesystem.file_path IN ("/usr/bin/su","/usr/bin/sudo","/usr/bin/passwd","/usr/bin/chsh","/usr/bin/chfn","/usr/bin/mount","/usr/bin/umount","/usr/bin/newgrp","/usr/bin/gpasswd","/usr/bin/pkexec","/usr/bin/crontab","/bin/su","/bin/mount","/bin/ping","/usr/sbin/pppd","/usr/sbin/unix_chkpwd","/usr/lib/dbus-1.0/dbus-daemon-launch-helper") by Filesystem.dest Filesystem.file_path Filesystem.user Filesystem.process_id | `drop_dm_object_name(Filesystem)` | where NOT match(process_name,"(?i)^(dpkg|rpm|yum|dnf|zypper|apt|apt-get|unattended-upgrade|snapd|snap|update-alternatives|pacman|tar|cp|install|chmod|setcap)$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where ActionType in ("FileModified","FileCreated")
| where FolderPath in ("/usr/bin","/bin","/usr/sbin","/sbin")
| where FileName in ("su","sudo","passwd","chsh","chfn","mount","umount","newgrp","gpasswd","pkexec","crontab","ping","pppd","unix_chkpwd")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","dnf","zypper","apt","apt-get","unattended-upgrade","snapd","snap","update-alternatives","pacman","tar","cp","install","chmod","setcap")
| where InitiatingProcessAccountName != "root" or InitiatingProcessParentFileName !in~ ("systemd","init","cron")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName
```

### [LLM] Copy Fail: algif_aead kernel module load by unprivileged or unexpected process

`UC_10_3` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where Processes.process_name IN ("modprobe","insmod","kmod") (Processes.process="*algif_aead*" OR Processes.process="*algif_skcipher*" OR Processes.process="*algif_hash*") by Processes.dest Processes.user Processes.process_name Processes.process_id | `drop_dm_object_name(Processes)` | where (user!="root") OR NOT match(parent_process_name,"(?i)^(systemd|systemd-modules-load|cryptsetup|init|kmod|udevadm|dracut)$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where FileName in~ ("modprobe","insmod","kmod")
| where ProcessCommandLine has_any ("algif_aead","algif_skcipher","algif_hash")
| where AccountName != "root" or InitiatingProcessFileName !in~ ("systemd","systemd-modules-load","cryptsetup","init","kmod","udevadm","dracut")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

### [LLM] Copy Fail: setuid binary executed within minutes of an out-of-band modification

`UC_10_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as mod_time values(Filesystem.process_name) as modifying_process values(Filesystem.user) as modifying_user from datamodel=Endpoint.Filesystem where Filesystem.action=modified Filesystem.file_path IN ("/usr/bin/su","/usr/bin/sudo","/usr/bin/passwd","/usr/bin/pkexec","/usr/bin/chsh","/usr/bin/chfn","/usr/bin/mount","/usr/bin/newgrp","/usr/bin/gpasswd","/bin/su","/bin/mount") by Filesystem.dest Filesystem.file_path | `drop_dm_object_name(Filesystem)` | rename file_path as suid_path | join type=inner dest suid_path [ | tstats `summariesonly` min(_time) as exec_time values(Processes.user) as exec_user values(Processes.parent_process_name) as parent_process_name from datamodel=Endpoint.Processes where Processes.process_path IN ("/usr/bin/su","/usr/bin/sudo","/usr/bin/passwd","/usr/bin/pkexec","/usr/bin/chsh","/usr/bin/chfn","/usr/bin/mount","/usr/bin/newgrp","/usr/bin/gpasswd","/bin/su","/bin/mount") by Processes.dest Processes.process_path | `drop_dm_object_name(Processes)` | rename process_path as suid_path ] | eval delta_seconds=exec_time-mod_time | where delta_seconds>=0 AND delta_seconds<=300 | where NOT match(modifying_process,"(?i)^(dpkg|rpm|yum|dnf|zypper|apt|apt-get|snapd|snap|update-alternatives|pacman)$") | table dest suid_path mod_time exec_time delta_seconds modifying_user modifying_process exec_user parent_process_name
```

**Defender KQL:**
```kql
let Window = 5m;
let Targets = dynamic(["su","sudo","passwd","pkexec","chsh","chfn","mount","newgrp","gpasswd"]);
let Modified = DeviceFileEvents
| where ActionType in ("FileModified","FileCreated")
| where FolderPath in ("/usr/bin","/bin")
| where FileName in (Targets)
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","dnf","zypper","apt","apt-get","snapd","snap","update-alternatives","pacman")
| project ModTime=Timestamp, DeviceId, DeviceName, SuidPath=strcat(FolderPath,"/",FileName), ModifyingProcess=InitiatingProcessFileName, ModifyingUser=InitiatingProcessAccountName;
let Executed = DeviceProcessEvents
| where FolderPath in ("/usr/bin","/bin") and FileName in (Targets)
| project ExecTime=Timestamp, DeviceId, SuidPath=strcat(FolderPath,"/",FileName), ExecUser=AccountName, ExecParent=InitiatingProcessFileName, ExecCmd=ProcessCommandLine;
Modified
| join kind=inner Executed on DeviceId, SuidPath
| where ExecTime between (ModTime .. ModTime + Window)
| extend DeltaSeconds = datetime_diff('second', ExecTime, ModTime)
| project ModTime, ExecTime, DeltaSeconds, DeviceName, SuidPath, ModifyingProcess, ModifyingUser, ExecUser, ExecParent, ExecCmd
```

### Article-specific behavioural hunt — New Linux ‘Copy Fail’ flaw gives hackers root on major distros

`UC_10_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New Linux ‘Copy Fail’ flaw gives hackers root on major distros ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/modprobe.d/disable-algif.conf*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New Linux ‘Copy Fail’ flaw gives hackers root on major distros
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/modprobe.d/disable-algif.conf"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-31431`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 5 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
