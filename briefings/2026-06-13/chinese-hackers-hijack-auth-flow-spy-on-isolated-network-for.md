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
- **T1090.002** — Proxy: External Proxy
- **T1571** — Non-Standard Port
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1556** — Modify Authentication Process
- **T1554** — Compromise Host Software Binary
- **T1056.001** — Input Capture: Keylogging
- **T1040** — Network Sniffing
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1090** — Proxy
- **T1572** — Protocol Tunneling
- **T1021.004** — Remote Services: SSH
- **T1090.001** — Internal Proxy
- **T1505.003** — Server Software Component: Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Velvet Ant GS-Netcat C2 relay lookup to gs.thc.org

`UC_36_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="gs.thc.org" OR DNS.query="*.gs.thc.org" OR DNS.query="*.thc.org") by DNS.src, DNS.query, DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | appendcols [| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_category="thc.org" OR All_Traffic.dest="*.thc.org" by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)`]
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "gs.thc.org" or RemoteUrl endswith ".thc.org"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### Velvet Ant backdoored PAM module write (pam_unix.so outside package manager)

`UC_36_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/lib/security/*" OR Filesystem.file_path="/lib64/security/*" OR Filesystem.file_path="/lib/x86_64-linux-gnu/security/*" OR Filesystem.file_path="/usr/lib64/security/*" OR Filesystem.file_path="/usr/lib/x86_64-linux-gnu/security/*") AND Filesystem.file_name="pam_*.so" AND Filesystem.action IN ("created","modified","renamed") AND NOT Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","tdnf","unattended-upgrade","packagekitd") by Filesystem.dest, Filesystem.file_path, Filesystem.file_name, Filesystem.file_hash, Filesystem.process_name, Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any (@"/lib/security/", @"/lib64/security/", @"/lib/x86_64-linux-gnu/security/", @"/usr/lib64/security/", @"/usr/lib/x86_64-linux-gnu/security/")
| where FileName startswith "pam_" and FileName endswith ".so"
| where InitiatingProcessFileName !in~ ("dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "zypper", "tdnf", "unattended-upgr", "packagekitd", "rpmbuild")
| where InitiatingProcessFolderPath !startswith "/usr/lib/apt/methods/"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5, FileSize, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Trojanized OpenSSH binary write (ssh/sshd/scp replaced outside package manager)

`UC_36_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/usr/bin/ssh","/usr/sbin/sshd","/usr/bin/scp","/usr/bin/sftp","/usr/libexec/openssh/sftp-server","/usr/bin/ssh-keygen","/usr/bin/ssh-agent","/usr/bin/ssh-add","/usr/local/bin/ssh","/usr/local/sbin/sshd","/usr/local/bin/scp") AND Filesystem.action IN ("created","modified","renamed") AND NOT Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","tdnf","unattended-upgrade","packagekitd") by Filesystem.dest, Filesystem.file_path, Filesystem.file_name, Filesystem.file_hash, Filesystem.process_name, Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath in~ ("/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/", "/bin/", "/sbin/", "/usr/libexec/openssh/")
| where FileName in~ ("ssh", "sshd", "scp", "sftp", "sftp-server", "ssh-keygen", "ssh-agent", "ssh-add", "ssh-keyscan")
| where InitiatingProcessFileName !in~ ("dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "zypper", "tdnf", "unattended-upgr", "packagekitd", "rpmbuild")
| where InitiatingProcessFolderPath !startswith "/usr/lib/apt/methods/"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5, FileSize, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Velvet Ant SOCKS5 proxy masquerading as 'smbd -D'

`UC_36_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*smbd*-D*" OR Processes.process_name="smbd") AND (Processes.process_path!="/usr/sbin/smbd" AND Processes.process_path!="/usr/local/sbin/smbd" OR Processes.parent_process_name NOT IN ("systemd","init","smbd","samba")) by Processes.dest, Processes.process_path, Processes.process_name, Processes.process, Processes.parent_process_name, Processes.parent_process, Processes.user, Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | join type=left dest [| tstats summariesonly=true count as outbound_conns, dc(All_Traffic.dest) as unique_dests from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="smbd" AND All_Traffic.dest_category="public" by All_Traffic.src | rename All_Traffic.src as dest | `drop_dm_object_name(All_Traffic)`]
```

**Defender KQL:**
```kql
let MasqueradeProc = DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where ProcessCommandLine has "smbd" and ProcessCommandLine has "-D"
  | where FolderPath !in~ ("/usr/sbin/", "/usr/local/sbin/")
     or InitiatingProcessFileName !in~ ("systemd", "init", "smbd", "samba", "sh")
  | project Timestamp, DeviceName, DeviceId, FolderPath, FileName, ProcessCommandLine, SHA256, ProcessId, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, AccountName;
let SmbdEgress = DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where InitiatingProcessFileName =~ "smbd"
  | where RemoteIPType == "Public"
  | project NetTime=Timestamp, DeviceId, RemoteIP, RemotePort, Protocol, InitiatingProcessId, InitiatingProcessFolderPath, InitiatingProcessCommandLine;
MasqueradeProc
| union SmbdEgress
| order by Timestamp asc
```

### Velvet Ant fcgiwrap → SSH/uptime pivot to air-gapped network

`UC_36_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("fcgiwrap","nginx","php-fpm","php-fpm7.4","php-fpm8.0","php-fpm8.1","php-fpm8.2") AND (Processes.process_name IN ("ssh","scp","sshpass","ncat","nc","socat","uptime") OR Processes.process="*ssh *" OR Processes.process="*ssh -i *" OR Processes.process="*ssh -o *") by Processes.dest, Processes.process_path, Processes.process_name, Processes.process, Processes.parent_process_name, Processes.parent_process, Processes.user, Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("fcgiwrap", "nginx", "php-fpm", "php-fpm7.4", "php-fpm8.0", "php-fpm8.1", "php-fpm8.2")
     or InitiatingProcessParentFileName =~ "fcgiwrap"
| where FileName in~ ("ssh", "scp", "sshpass", "ncat", "nc", "socat", "uptime")
     or ProcessCommandLine has_any ("ssh -i", "ssh -o", "ssh -p", "scp -i", "sshpass ")
| where not (FileName =~ "uptime" and FolderPath =~ "/usr/bin/" and ProcessCommandLine !has "ssh" and ProcessCommandLine !has "@")
| project Timestamp, DeviceName, FolderPath, FileName, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
