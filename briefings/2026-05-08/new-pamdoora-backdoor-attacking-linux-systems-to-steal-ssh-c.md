# [HIGH] New PamDOORa Backdoor Attacking Linux Systems to Steal SSH Credentials

**Source:** Cyber Security News
**Published:** 2026-05-08
**Article:** https://cybersecuritynews.com/new-pamdoora-backdoor-attacking-linux-systems/

## Threat Profile

Home Cyber Security News 
New PamDOORa Backdoor Attacking Linux Systems to Steal SSH Credentials 
By Tushar Subhra Dutta 
May 8, 2026 




A new backdoor called PamDOORa has emerged as a serious and growing threat to Linux systems, targeting one of the most trusted components of the operating system to silently steal SSH credentials. 
The malware was advertised for sale on a Russian-speaking cybercrime forum called Rehub, with its complete source code initially listed at $1,600 before the se…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1204.002** — User Execution: Malicious File
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1543** — Create or Modify System Process
- **T1070.002** — Indicator Removal: Clear Linux or Mac System Logs
- **T1070.006** — Indicator Removal: Timestomp
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PamDOORa PAM hijack: pam_linux.so drop or /etc/pam.d/sshd modification on Linux

`UC_0_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified","renamed") AND ((Filesystem.file_path="/etc/pam.d/sshd") OR (Filesystem.file_name="pam_linux.so" AND Filesystem.file_path IN ("/lib/security/*","/lib64/security/*","/usr/lib/security/*","/lib/x86_64-linux-gnu/security/*"))) AND NOT Filesystem.process_name IN ("apt","apt-get","dpkg","yum","dnf","rpm","zypper","pacman","unattended-upgr") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath =~ "/etc/pam.d/" and FileName =~ "sshd")
   or (FileName =~ "pam_linux.so"
       and FolderPath has_any ("/lib/security","/lib64/security","/usr/lib/security","/lib/x86_64-linux-gnu/security"))
| where InitiatingProcessFileName !in~ ("apt","apt-get","dpkg","yum","dnf","rpm","zypper","pacman","unattended-upgr","systemd","snapd")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] PamDOORa anti-forensics: tampering with lastlog / btmp / utmp / wtmp

`UC_0_5` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where Processes.process_name IN ("dd","truncate","shred","sed","bash","sh","zsh","dash","python","python3","perl") AND (Processes.process="*/var/log/wtmp*" OR Processes.process="*/var/log/btmp*" OR Processes.process="*/var/log/lastlog*" OR Processes.process="*/var/run/utmp*") AND NOT Processes.parent_process_name IN ("logrotate","systemd","systemd-logind") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let AuthLogs = dynamic(["/var/log/wtmp","/var/log/btmp","/var/log/lastlog","/var/run/utmp"]);
let FileTamper = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("FileDeleted","FileRenamed","FileModified")
    | where strcat(FolderPath, FileName) in~ (AuthLogs)
       or (FolderPath has_any ("/var/log","/var/run") and FileName in~ ("wtmp","btmp","lastlog","utmp"))
    | where InitiatingProcessFileName !in~ ("sshd","login","systemd","systemd-logind","logrotate","cron","crond","init","agetty")
    | project Timestamp, DeviceName, Source="FileEvent", Action=ActionType,
              Path=strcat(FolderPath, FileName),
              Actor=InitiatingProcessAccountName,
              ProcName=InitiatingProcessFileName,
              CmdLine=InitiatingProcessCommandLine;
let ProcRedir = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has_any ("/var/log/wtmp","/var/log/btmp","/var/log/lastlog","/var/run/utmp")
    | where ProcessCommandLine matches regex @"(?i)(>\s*/var/(log|run)/(wtmp|btmp|utmp|lastlog)|truncate\s+-s\s*0|shred\s+-[uvfz]+\s+/var/(log|run)/(wtmp|btmp|utmp|lastlog)|:\s*>\s*/var/(log|run)/(wtmp|btmp|utmp|lastlog))"
    | project Timestamp, DeviceName, Source="ProcEvent", Action="CmdLineRedirect",
              Path=ProcessCommandLine,
              Actor=AccountName,
              ProcName=FileName,
              CmdLine=ProcessCommandLine;
union FileTamper, ProcRedir
| order by Timestamp desc
```

### [LLM] PamDOORa credential exfil: pam_exec spawning tn.sh and netcat to TCP/1234

`UC_0_6` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name="sshd" OR Processes.parent_process_name="pam_exec" OR Processes.process="*pam_exec*") AND ( Processes.process="*tn.sh*" OR (Processes.process_name IN ("nc","ncat","netcat","netcat.openbsd","netcat.traditional") AND Processes.process="*1234*") OR (Processes.process_name IN ("sh","bash","dash","zsh") AND Processes.process="*/tmp/*") ) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let AuthSpawn = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("sshd","pam_exec")
         or InitiatingProcessParentFileName in~ ("sshd","pam_exec")
         or InitiatingProcessCommandLine has "pam_exec";
let ScriptOrNc = AuthSpawn
    | where (FileName =~ "tn.sh" or ProcessCommandLine has "tn.sh")
         or (FileName in~ ("nc","ncat","netcat","netcat.openbsd","netcat.traditional")
             and ProcessCommandLine has "1234")
         or (FileName in~ ("sh","bash","dash","zsh")
             and ProcessCommandLine matches regex @"(?i)/tmp/[a-z0-9._-]+\.sh");
let NcEgress = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemotePort == 1234
    | where InitiatingProcessFileName in~ ("nc","ncat","netcat","netcat.openbsd","netcat.traditional")
         or InitiatingProcessParentFileName in~ ("sshd","pam_exec","sh","bash","dash")
    | project Timestamp, DeviceName, Source="Network",
              Process=InitiatingProcessFileName,
              Parent=InitiatingProcessParentFileName,
              CmdLine=InitiatingProcessCommandLine,
              RemoteIP, RemotePort;
ScriptOrNc
| project Timestamp, DeviceName, Source="Process",
          Process=FileName, Parent=InitiatingProcessFileName,
          CmdLine=ProcessCommandLine,
          RemoteIP=tostring(""), RemotePort=toint(0)
| union NcEgress
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
```

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Article-specific behavioural hunt — New PamDOORa Backdoor Attacking Linux Systems to Steal SSH Credentials

`UC_0_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New PamDOORa Backdoor Attacking Linux Systems to Steal SSH Credentials ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/pam.d/sshd*" OR Filesystem.file_name IN ("next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New PamDOORa Backdoor Attacking Linux Systems to Steal SSH Credentials
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/pam.d/sshd") or FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
