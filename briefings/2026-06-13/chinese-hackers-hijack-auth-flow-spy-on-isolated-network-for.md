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
- **T1071.004** — Application Layer Protocol: DNS
- **T1572** — Protocol Tunneling
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1090** — Proxy
- **T1021.004** — Remote Services: SSH
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1556** — Modify Authentication Process
- **T1027** — Obfuscated Files or Information
- **T1554** — Compromise Host Software Binary
- **T1056.002** — Input Capture: GUI Input Capture
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1547.014** — Boot or Logon Autostart Execution: Active Setup
- **T1036** — Masquerading

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Velvet Ant GS-Netcat C2 relay domain contact (gs.thc.org)

`UC_4_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.dest) as dest from datamodel=Network_Resolution where DNS.query="gs.thc.org" OR DNS.query="*.thc.org" by DNS.query DNS.src | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "gs.thc.org" or RemoteUrl endswith ".thc.org"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### Process masquerading as 'smbd -D' from non-Samba install path (Velvet Ant SOCKS5 proxy)

`UC_4_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as paths from datamodel=Endpoint.Processes where (Processes.process_name="smbd" OR Processes.process="*smbd -D*") AND NOT Processes.process_path IN ("/usr/sbin/smbd","/usr/local/sbin/smbd","/usr/lib/smbd") AND NOT Processes.parent_process_name IN ("systemd","init","smbd") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "smbd" or ProcessCommandLine has "smbd -D"
| where not(FolderPath startswith "/usr/sbin/") and not(FolderPath startswith "/usr/local/sbin/") and not(FolderPath startswith "/usr/lib/")
| where not(InitiatingProcessFileName in~ ("systemd", "init", "smbd", "samba"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### fcgiwrap spawning ssh/scp/'uptime' (Velvet Ant HTTP-to-air-gap bridge)

`UC_4_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.parent_process_name="fcgiwrap" AND (Processes.process_name IN ("ssh","scp","uptime","nc","ncat","sshpass") OR Processes.process="*ssh *" OR Processes.process="*scp *") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "fcgiwrap"
| where FileName in~ ("ssh", "scp", "uptime", "nc", "ncat", "sshpass") or ProcessCommandLine has_any ("ssh ", "scp ", "/uptime")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Backdoored pam_unix.so or PAM module write outside package manager (Velvet Ant)

`UC_4_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_hash) as hashes from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/lib/security/*" OR Filesystem.file_path="/lib64/security/*" OR Filesystem.file_path="/usr/lib/security/*" OR Filesystem.file_path="/usr/lib64/security/*") AND Filesystem.file_name="pam_*.so" AND Filesystem.action IN ("created","modified","write") AND NOT Filesystem.process_name IN ("dpkg","rpm","apt","apt-get","yum","dnf","unattended-upgrade") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any ("/lib/security/", "/lib64/security/", "/usr/lib/security/", "/usr/lib64/security/")
| where FileName startswith "pam_" and FileName endswith ".so"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where not(InitiatingProcessFileName in~ ("dpkg", "rpm", "apt", "yum", "dnf", "apt-get", "unattended-upgrade"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### OpenSSH binary replacement outside package manager (Velvet Ant ssh/sshd/scp trojanization)

`UC_4_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_hash) as hashes from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/scp","/usr/bin/sftp","/usr/bin/ssh-keyscan") AND Filesystem.action IN ("created","modified","write","replaced") AND NOT Filesystem.process_name IN ("dpkg","rpm","apt","apt-get","yum","dnf","unattended-upgrade") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FolderPath =~ "/usr/sbin/" and FileName =~ "sshd") or (FolderPath =~ "/usr/bin/" and FileName in~ ("ssh", "scp", "sftp", "ssh-keyscan", "ssh-agent"))
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where not(InitiatingProcessFileName in~ ("dpkg", "rpm", "apt", "yum", "dnf", "apt-get", "unattended-upgrade"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### Unmanaged systemd unit file drop pointing to non-standard ExecStart (Velvet Ant GS-Netcat persistence)

`UC_4_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process) as writer_cmd from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/systemd/system/*" OR Filesystem.file_path="/usr/lib/systemd/system/*" OR Filesystem.file_path="/lib/systemd/system/*") AND Filesystem.file_name="*.service" AND Filesystem.action IN ("created","modified","write") AND NOT Filesystem.process_name IN ("dpkg","rpm","apt","apt-get","yum","dnf","systemctl","systemd","unattended-upgrade","puppet","chef-client","ansible","salt-minion") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any ("/etc/systemd/system/", "/usr/lib/systemd/system/", "/lib/systemd/system/")
| where FileName endswith ".service"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where not(InitiatingProcessFileName in~ ("dpkg", "rpm", "apt", "yum", "dnf", "apt-get", "systemctl", "systemd", "unattended-upgrade", "puppet", "chef-client", "ansible", "salt-minion"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
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
