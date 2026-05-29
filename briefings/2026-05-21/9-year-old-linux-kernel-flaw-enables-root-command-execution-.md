# [CRIT] 9-Year-Old Linux Kernel Flaw Enables Root Command Execution on Major Distros

**Source:** The Hacker News
**Published:** 2026-05-21
**Article:** https://thehackernews.com/2026/05/9-year-old-linux-kernel-flaw-enables.html

## Threat Profile

9-Year-Old Linux Kernel Flaw Enables Root Command Execution on Major Distros 
 Ravie Lakshmanan  May 21, 2026 Linux / Vulnerability 
Cybersecurity researchers have disclosed details of a vulnerability in the Linux kernel that remained undetected for nine years.
The vulnerability, tracked as CVE-2026-46333 (CVSS score: 5.5), is a case of improper privilege management that could permit an unprivileged local user to disclose sensitive files and execute arbitrary commands as root on default instal…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-46333`
- **SHA1:** `31e62c2ebbfd`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1068** — Exploitation for Privilege Escalation
- **T1548.001** — Abuse Elevation Control Mechanism: Setuid and Setgid
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1548** — Abuse Elevation Control Mechanism
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1547.006** — Boot or Logon Autostart Execution: Kernel Modules and Extensions

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Repeated SUID helper invocation (ssh-keysign/chage) by unprivileged user — ssh-keysign-pwn race

`UC_92_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where (Processes.process_name="ssh-keysign" OR Processes.process_name="chage") AND NOT (Processes.user IN ("root","SYSTEM")) AND NOT (Processes.parent_process_name IN ("sshd","ssh","passwd","useradd","usermod","chage")) by _time span=1m Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | where count >= 5 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("ssh-keysign","chage")
| where InitiatingProcessAccountName !in~ ("root","system")
| where InitiatingProcessFileName !in~ ("sshd","ssh","passwd","useradd","usermod","chage","systemd")
| summarize ExecCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            SampleParent = any(InitiatingProcessFileName),
            SampleCmd = any(ProcessCommandLine)
            by DeviceName, InitiatingProcessAccountName, FileName, bin(Timestamp, 1m)
| where ExecCount >= 5
| order by LastSeen desc
```

### [LLM] kernel.yama.ptrace_scope lowered or disabled — ssh-keysign-pwn mitigation tampering

`UC_92_7` · phase: **weapon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where (Processes.process_name IN ("sysctl","sh","bash","dash","zsh","tee","sed") OR Processes.parent_process_name IN ("sysctl")) AND (Processes.process="*kernel.yama.ptrace_scope*" OR Processes.process="*/proc/sys/kernel/yama/ptrace_scope*") AND (Processes.process="*=0*" OR Processes.process="*=1*" OR Processes.process="* 0*" OR Processes.process="* 1*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("kernel.yama.ptrace_scope","/proc/sys/kernel/yama/ptrace_scope")
| where ProcessCommandLine matches regex @"(=|\s)[01]\b"
| where InitiatingProcessAccountName !in~ ("_apt","unattended-upgrades")
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Read of /etc/shadow or /etc/ssh/*_key by non-root, non-canonical process — ssh-keysign-pwn post-exploit

`UC_92_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as procs values(Filesystem.process) as cmdlines from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/shadow" OR Filesystem.file_path="/etc/gshadow" OR Filesystem.file_path="/etc/ssh/ssh_host_*_key" OR Filesystem.file_path="/etc/ssh/*_key") AND NOT (Filesystem.user IN ("root","SYSTEM","_apt")) AND NOT (Filesystem.process_name IN ("sshd","ssh-keysign","login","su","sudo","passwd","chage","useradd","usermod","systemd","accounts-daemon","polkitd","unix_chkpwd","cron","crond")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where (FolderPath in ("/etc/shadow","/etc/gshadow"))
     or (FolderPath startswith "/etc/ssh/" and FolderPath endswith "_key")
| where InitiatingProcessAccountName !in~ ("root","system","_apt","sshd")
| where InitiatingProcessFileName !in~ ("sshd","ssh-keysign","login","su","sudo","passwd","chage","useradd","usermod","systemd","accounts-daemon","polkitd","unix_chkpwd","cron","crond","vipw")
| project Timestamp, DeviceName, FolderPath, FileName,
          ActionType,
          InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] RDS kernel module loaded — PinTheft LPE exploit prerequisite

`UC_92_9` · phase: **weapon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where (Processes.process_name="modprobe" OR Processes.process_name="insmod") AND (Processes.process="*rds*" OR Processes.process="*rds_rdma*" OR Processes.process="*rds_tcp*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | rex field=process "\b(?<module>rds(_rdma|_tcp)?)\b" | where isnotnull(module) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("modprobe","insmod")
| where ProcessCommandLine matches regex @"(?i)\brds(_rdma|_tcp)?\b"
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### Article-specific behavioural hunt — 9-Year-Old Linux Kernel Flaw Enables Root Command Execution on Major Distros

`UC_92_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — 9-Year-Old Linux Kernel Flaw Enables Root Command Execution on Major Distros ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/shadow*" OR Filesystem.file_path="*/etc/ssh/*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — 9-Year-Old Linux Kernel Flaw Enables Root Command Execution on Major Distros
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/shadow", "/etc/ssh/"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-46333`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `31e62c2ebbfd`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
