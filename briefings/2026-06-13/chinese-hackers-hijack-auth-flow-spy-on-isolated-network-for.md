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
- **T1556** — Modify Authentication Process
- **T1556.002** — Password Filter DLL
- **T1027** — Obfuscated Files or Information
- **T1040** — Network Sniffing
- **T1555** — Credentials from Password Stores
- **T1572** — Protocol Tunneling
- **T1571** — Non-Standard Port
- **T1021.004** — SSH
- **T1036** — Masquerading
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1543.002** — Systemd Service
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Velvet Ant pam_unix.so backdoor — PAM module replacement outside package manager

`UC_6_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/lib/security/*" OR Filesystem.file_path="*/lib64/security/*" OR Filesystem.file_path="*/usr/lib/security/*" OR Filesystem.file_path="*/usr/lib64/security/*") AND Filesystem.file_name="pam_*.so" AND (Filesystem.action="created" OR Filesystem.action="modified" OR Filesystem.action="renamed") by Filesystem.dest, Filesystem.user, Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| search NOT process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","unattended-upgrade","packagekitd")
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("/lib/security/", "/lib64/security/", "/usr/lib/security/", "/usr/lib64/security/")
| where FileName startswith "pam_" and FileName endswith ".so"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| extend IsPackageManager = InitiatingProcessFileName in~ ("dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "zypper", "unattended-upgrade", "packagekitd")
| where IsPackageManager == false
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Velvet Ant trojanized OpenSSH binary replacement (ssh, sshd, scp)

`UC_6_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/scp","/usr/libexec/openssh/sftp-server","/usr/bin/ssh-keygen")) AND (Filesystem.action="created" OR Filesystem.action="modified" OR Filesystem.action="renamed") by Filesystem.dest, Filesystem.file_name, Filesystem.user, Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| search NOT process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","unattended-upgrade")
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath in~ ("/usr/sbin/", "/usr/bin/", "/bin/", "/sbin/", "/usr/libexec/openssh/")
| where FileName in~ ("sshd", "ssh", "scp", "sftp-server", "ssh-keygen", "ssh-agent")
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| extend IsPackageManager = InitiatingProcessFileName in~ ("dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "zypper", "unattended-upgrade")
| where IsPackageManager == false
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Velvet Ant Nginx → fcgiwrap → SSH execution bridge into air-gapped network

`UC_6_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.process_path) as path values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.parent_process_name="fcgiwrap" OR Processes.parent_process_name="nginx") AND (Processes.process_name IN ("ssh","uptime","bash","sh","dash","nc","ncat","socat")) by Processes.dest, Processes.user, Processes.process_name, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("fcgiwrap", "nginx")
| where FileName in~ ("ssh", "uptime", "bash", "sh", "dash", "nc", "ncat", "socat")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256, InitiatingProcessSHA256
| order by Timestamp desc
```

### smbd masquerading SOCKS5 proxy — wrong path or wrong parent

`UC_6_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process_path) as path values(Processes.parent_process_name) as parent values(Processes.process) as cmd from datamodel=Endpoint.Processes where Processes.process_name="smbd" AND Processes.process="*-D*" by Processes.dest, Processes.user, Processes.process_path, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| eval standard_path=if(match(path, "^/(usr/sbin|usr/local/sbin|usr/lib/x86_64-linux-gnu/samba|usr/lib64/samba)/smbd$"), 1, 0)
| eval standard_parent=if(parent IN ("systemd","init","samba","smbd"), 1, 0)
| where standard_path=0 OR standard_parent=0
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "smbd"
| where ProcessCommandLine has "-D"
| extend StandardPath = FolderPath in~ ("/usr/sbin/", "/usr/local/sbin/", "/usr/lib/x86_64-linux-gnu/samba/", "/usr/lib64/samba/")
| extend StandardParent = InitiatingProcessFileName in~ ("systemd", "init", "samba", "smbd")
| where StandardPath == false or StandardParent == false
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### GS-Netcat C2 — gs.thc.org / GSRN relay contact + suspicious systemd persistence

`UC_6_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as query values(DNS.src) as src from datamodel=Network_Resolution.DNS where (DNS.query="gs.thc.org" OR DNS.query="*.gsocket.io" OR DNS.query="gsocket.io") by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let GsNetcatRelays = dynamic(["gs.thc.org", "gsocket.io"]);
let NetworkHits = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (GsNetcatRelays) or RemoteUrl endswith ".gsocket.io"
    | project Timestamp, DeviceName,
              AccountName = InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessFolderPath,
              InitiatingProcessCommandLine,
              RemoteIP, RemoteUrl, RemotePort, Protocol;
let SystemdWrites = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has_any ("/etc/systemd/system/", "/usr/lib/systemd/system/", "/lib/systemd/system/", "/etc/rc.d/", "/etc/init.d/")
    | where ActionType in ("FileCreated", "FileModified")
    | extend IsPackageManager = InitiatingProcessFileName in~ ("dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "zypper", "systemctl", "systemd")
    | where IsPackageManager == false
    | project Timestamp, DeviceName, FolderPath, FileName,
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName;
union NetworkHits, SystemdWrites
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
