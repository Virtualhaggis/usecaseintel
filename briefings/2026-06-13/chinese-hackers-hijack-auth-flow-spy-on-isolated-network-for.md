# [CRIT] Chinese hackers hijack auth flow, spy on isolated network for a decade

**Source:** BleepingComputer
**Published:** 2026-06-13
**Article:** https://www.bleepingcomputer.com/news/security/chinese-hackers-hijack-auth-flow-spy-on-isolated-network-for-a-decade/

## Threat Profile

Chinese hackers hijack auth flow, spy on isolated network for a decade 
By Bill Toulas 
June 13, 2026
10:06 AM
0 
Chinese hackers took control of a target organization's authentication stack and maintained persistence for 10 years, with full visibility into the administrative activity.
Dubbed "Operation Highland," the intrusion is attributed to the Velvet Ant cyberespionage threat group, which targeted vulnerable internet-facing systems before pivoting to a network with no direct external path.
…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-20399`
- **Domain (defanged):** `gs.thc.org`

## MITRE ATT&CK Techniques

- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1572** — Protocol Tunneling
- **T1090** — Proxy
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1556** — Modify Authentication Process
- **T1554** — Compromise Host Software Binary
- **T1040** — Network Sniffing
- **T1555** — Credentials from Password Stores
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1021.004** — Remote Services: SSH
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1037** — Boot or Logon Initialization Scripts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Velvet Ant GS-Netcat reverse shell beacon to gs.thc.org relay

`UC_7_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where (DNS.query="gs.thc.org" OR DNS.query="*.gs.thc.org" OR DNS.query="*.thc.org") by DNS.src DNS.query DNS.dest host
| `drop_dm_object_name("DNS")`
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
| append [| tstats summariesonly=t count from datamodel=Network_Traffic where All_Traffic.dest_port IN (443,7350,22,80) AND (All_Traffic.dest="gs.thc.org" OR All_Traffic.app="*thc.org*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app host | `drop_dm_object_name("All_Traffic")`]
```

**Defender KQL:**
```kql
union
(DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "gs.thc.org" or RemoteUrl endswith ".thc.org"
| project Timestamp, DeviceName, EventType="NetworkConnection", InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName),
(DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| where AdditionalFields has "gs.thc.org" or RemoteUrl has "gs.thc.org"
| project Timestamp, DeviceName, EventType="DNS", InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, AdditionalFields, InitiatingProcessAccountName)
| order by Timestamp desc
```

### Velvet Ant pam_unix.so backdoor module replacement in /lib(64)/security/

`UC_7_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_hash) as file_hash values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/lib/security/*" OR Filesystem.file_path="*/lib64/security/*" OR Filesystem.file_path="*/usr/lib/security/*" OR Filesystem.file_path="*/usr/lib64/security/*") AND Filesystem.action IN ("created","modified","renamed","replaced") by host Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name("Filesystem")`
| search NOT process_name IN ("dpkg","rpm","apt","apt-get","yum","dnf","zypper","snap","pacman")
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any ("/lib/security/", "/lib64/security/", "/usr/lib/security/", "/usr/lib64/security/", "/usr/lib/x86_64-linux-gnu/security/")
| where ActionType in ("FileCreated", "FileModified", "FileRenamed", "FileReplaced")
| where InitiatingProcessFileName !in~ ("dpkg", "rpm", "apt", "apt-get", "yum", "dnf", "zypper", "snap", "pacman", "unattended-upgrade", "PackageKit")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5, FileSize, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Velvet Ant trojanized OpenSSH binary replacement (sshd/ssh/scp)

`UC_7_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_hash) as file_hash values(Filesystem.process_name) as initiating_process values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/scp","/usr/bin/sftp","/usr/local/sbin/sshd","/usr/local/bin/ssh","/usr/local/bin/scp") AND Filesystem.action IN ("created","modified","renamed","replaced") by host Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name("Filesystem")`
| search NOT initiating_process IN ("dpkg","rpm","apt","apt-get","yum","dnf","zypper","snap","unattended-upgrade")
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed","FileReplaced")
| where FolderPath in~ ("/usr/sbin/","/usr/bin/","/usr/local/sbin/","/usr/local/bin/","/bin/","/sbin/")
     and FileName in~ ("sshd","ssh","scp","sftp","sftp-server","ssh-agent")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","apt","apt-get","yum","dnf","zypper","snap","unattended-upgrade","PackageKit")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5, FileSize, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Velvet Ant SOCKS5 proxy masquerading as 'smbd -D' daemon

`UC_7_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process_hash) as hash values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="smbd" OR Processes.process="*smbd -D*" OR Processes.process="*smbd*\\ -D*") by host Processes.process_path Processes.process_name Processes.process
| `drop_dm_object_name("Processes")`
| eval suspicious=if(match(process_path,"^/(usr/sbin|usr/local/sbin|usr/bin)/smbd$"),0,1)
| eval bad_parent=if(match(parent,"systemd|init|smbd|samba"),0,1)
| where suspicious=1 OR bad_parent=1
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "smbd" and (ProcessCommandLine has " -D" or ProcessCommandLine endswith "-D")
   or FileName =~ "smbd"
| extend CanonicalPath = FolderPath in~ ("/usr/sbin/","/usr/sbin","/usr/local/sbin/","/usr/local/sbin","/usr/bin/","/usr/bin")
| extend CanonicalParent = InitiatingProcessFileName in~ ("systemd","init","smbd","samba","systemctl")
| where not(CanonicalPath and CanonicalParent and FileName =~ "smbd")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, SHA256, MD5, FileSize, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, CanonicalPath, CanonicalParent
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | summarize ListenPorts=make_set(LocalPort), RemoteIPs=make_set(RemoteIP) by DeviceName, InitiatingProcessId
  ) on DeviceName
| order by Timestamp desc
```

### Velvet Ant FastCGI fcgiwrap spawning ssh/uptime as bridge to air-gapped network

`UC_7_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.process_path) as child_path values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("fcgiwrap","nginx") OR Processes.parent_process="*fcgiwrap*" OR Processes.parent_process="*nginx*") AND (Processes.process_name IN ("ssh","scp","sftp","nc","ncat","socat","bash","sh","uptime") OR Processes.process="*uptime*") by host Processes.parent_process_name Processes.process_name
| `drop_dm_object_name("Processes")`
| where NOT (process_name="uptime" AND match(child_path,"^/(usr/bin|bin)/uptime$") AND NOT match(cmd,"-[a-z].*[A-Z]"))
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("fcgiwrap","nginx","php-fpm")
     or InitiatingProcessParentFileName in~ ("fcgiwrap","nginx")
| where FileName in~ ("ssh","scp","sftp","nc","ncat","socat","bash","sh","dash","uptime")
| extend SuspiciousUptime = FileName =~ "uptime" and (FolderPath !in~ ("/usr/bin/","/bin/") or ProcessCommandLine has_any ("--","@","-p ","-i ","ssh","connect"))
| where FileName != "uptime" or SuspiciousUptime
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, SHA256, FileSize, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SuspiciousUptime
| order by Timestamp desc
```

### Systemd unit file dropped with ExecStart to unusual paths — Velvet Ant persistence

`UC_7_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as initiating_process values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/etc/systemd/system/*" OR Filesystem.file_path="*/usr/lib/systemd/system/*" OR Filesystem.file_path="*/lib/systemd/system/*" OR Filesystem.file_path="*/run/systemd/system/*" OR Filesystem.file_path="*/etc/rc.local" OR Filesystem.file_path="*/etc/profile.d/*" OR Filesystem.file_path="*/etc/init.d/*") AND (Filesystem.file_name="*.service" OR Filesystem.file_path="*/rc.local" OR Filesystem.file_path="*/profile.d/*") AND Filesystem.action IN ("created","modified") by host Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name("Filesystem")`
| search NOT initiating_process IN ("dpkg","rpm","apt","apt-get","yum","dnf","systemctl","systemd","snap")
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has_any ("/etc/systemd/system/","/usr/lib/systemd/system/","/lib/systemd/system/","/run/systemd/system/") and FileName endswith ".service")
     or FolderPath has_any ("/etc/init.d/","/etc/profile.d/","/etc/rc.d/")
     or FileName in~ ("rc.local",".bashrc",".bash_profile",".profile")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","apt","apt-get","yum","dnf","zypper","snap","systemctl","systemd","systemd-sysv-install","PackageKit","unattended-upgrade")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-20399`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `gs.thc.org`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 9 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
