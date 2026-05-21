# [HIGH] 9-Year-Old Linux Kernel Flaw Enables Root Command Execution on Major Distros

**Source:** The Hacker News, BleepingComputer, Cyber Security News, Aikido, StepSecurity
**Published:** 2026-05-21
**Article:** https://thehackernews.com/2026/05/9-year-old-linux-kernel-flaw-enables.html

## Threat Profile

Back to Blog Product Dev Machine Guard Now Scans Extensions Across Every Modern IDE Dev Machine Guard now scans IDE extensions across VS Code, Cursor, Windsurf, JetBrains IDEs, Android Studio, Eclipse, and Xcode on macOS, Windows, and Linux. Get a unified inventory, extension risk scoring, typosquat detection, and compromised extension visibility across your entire developer fleet. Swarit Pandey View LinkedIn April 17, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
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

`UC_4_1` · phase: **exploit** · confidence: **High**

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

`UC_4_2` · phase: **weapon** · confidence: **Medium**

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

`UC_4_3` · phase: **actions** · confidence: **High**

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

`UC_4_4` · phase: **weapon** · confidence: **High**

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


## Why this matters

Severity classified as **HIGH** based on: 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
