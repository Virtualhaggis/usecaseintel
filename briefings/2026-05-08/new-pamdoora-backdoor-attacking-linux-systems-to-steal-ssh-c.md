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
The malware was advertised for sale on a Russian-speaking cybercrime forum called Rehub, with its complete source code initially listed at $1,600 before the seller sla…

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
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1070.002** — Indicator Removal: Clear Linux or Mac System Logs

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PamDOORa — /etc/pam.d/sshd tamper or drop of malicious pam_linux.so PAM module

`UC_0_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/pam.d/sshd" OR Filesystem.file_path="/etc/pam.d/*" OR Filesystem.file_name="pam_linux.so") AND Filesystem.action IN ("created","modified","write","renamed") NOT Filesystem.process_name IN ("apt","apt-get","dpkg","rpm","yum","dnf","zypper","authselect","pam-auth-update","puppet","ansible","cfengine-execd","chef-client","salt-minion") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_name Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath startswith "/etc/pam.d/" or FileName =~ "pam_linux.so")
| where InitiatingProcessFileName !in~ ("apt","apt-get","dpkg","rpm","yum","dnf","zypper","authselect","pam-auth-update","puppet","ansible","cfengine-execd","chef-client","salt-minion")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### [LLM] PamDOORa — sshd-spawned netcat exfil to TCP 1234 (PAM credential drop)

`UC_0_5` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="sshd" AND Processes.process_name IN ("nc","ncat","netcat","nc.openbsd","nc.traditional","ncat.openbsd") AND Processes.process="*1234*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
// PamDOORa exfil — netcat to port 1234 spawned under sshd
let SshdDescendants = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "sshd" or InitiatingProcessParentFileName =~ "sshd";
SshdDescendants
| where FileName in~ ("nc","ncat","netcat","nc.openbsd","nc.traditional","ncat.openbsd")
| where ProcessCommandLine has "1234"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| union (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemotePort == 1234
    | where InitiatingProcessFileName in~ ("nc","ncat","netcat","nc.openbsd","nc.traditional")
         or InitiatingProcessParentFileName =~ "sshd"
         or InitiatingProcessCommandLine has "tn.sh"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              FileName=InitiatingProcessFileName,
              ProcessCommandLine=InitiatingProcessCommandLine,
              InitiatingProcessFileName=InitiatingProcessParentFileName,
              InitiatingProcessCommandLine=tostring(parse_json(AdditionalFields)),
              InitiatingProcessParentFileName, SHA256=InitiatingProcessSHA256
)
| order by Timestamp desc
```

### [LLM] PamDOORa — Anti-forensic wipe of utmp / wtmp / btmp / lastlog

`UC_0_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/var/log/wtmp","/var/log/btmp","/var/log/lastlog","/var/run/utmp","/run/utmp") AND Filesystem.action IN ("deleted","truncated","modified","renamed") NOT Filesystem.process_name IN ("logrotate","systemd-logind","login","sshd","systemd","systemd-tmpfiles","savelog","init") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| extend FullPath = strcat(FolderPath, iif(FolderPath endswith "/", "", "/"), FileName)
| where FullPath in ("/var/log/wtmp","/var/log/btmp","/var/log/lastlog","/var/run/utmp","/run/utmp")
| where ActionType in ("FileDeleted","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("logrotate","systemd-logind","login","sshd","systemd","systemd-tmpfiles","savelog","init")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FullPath
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

Severity classified as **HIGH** based on: 7 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
