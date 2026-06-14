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
- **T1219** — Remote Access Software
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1556** — Modify Authentication Process
- **T1027** — Obfuscated Files or Information
- **T1554** — Compromise Host Software Binary
- **T1056.001** — Input Capture: Keylogging
- **T1090.001** — Proxy: Internal Proxy
- **T1021.004** — Remote Services: SSH
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1090** — Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Velvet Ant GS-Netcat C2: outbound traffic to gs.thc.org relay

`UC_5_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.query) as query values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where DNS.query="gs.thc.org" OR DNS.query="*.thc.org" OR DNS.query="*.gsocket.io" by DNS.src DNS.query | `drop_dm_object_name(DNS)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="gs.thc.org" by All_Traffic.src All_Traffic.dest | `drop_dm_object_name(All_Traffic)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let lookback = 30d;
let GsocketIndicators = dynamic(["gs.thc.org",".gsocket.io","gs-netcat"]);
union
(DeviceNetworkEvents
  | where Timestamp > ago(lookback)
  | where RemoteUrl has_any (GsocketIndicators)
  | project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort,
            InitiatingProcessFileName, InitiatingProcessFolderPath,
            InitiatingProcessCommandLine, InitiatingProcessAccountName, Source="NetworkEvent"),
(DeviceEvents
  | where Timestamp > ago(lookback)
  | where ActionType == "DnsQueryResponse" or ActionType has "Dns"
  | where AdditionalFields has_any (GsocketIndicators) or RemoteUrl has_any (GsocketIndicators)
  | project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort=int(null),
            InitiatingProcessFileName, InitiatingProcessFolderPath,
            InitiatingProcessCommandLine, InitiatingProcessAccountName=AccountName, Source="DnsEvent")
| order by Timestamp desc
```

### Backdoored PAM module replacement (pam_unix.so) outside package manager context

`UC_5_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/lib/security/pam_*.so" OR Filesystem.file_path="/lib64/security/pam_*.so" OR Filesystem.file_path="/lib/x86_64-linux-gnu/security/pam_*.so" OR Filesystem.file_path="/usr/lib64/security/pam_*.so" OR Filesystem.file_path="/usr/lib/security/pam_*.so") (Filesystem.action=created OR Filesystem.action=modified OR Filesystem.action=renamed) by Filesystem.dest Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | search NOT process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","update-alternatives","unattended-upgrade") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let pamPaths = dynamic(["/lib/security/","/lib64/security/","/lib/x86_64-linux-gnu/security/","/usr/lib64/security/","/usr/lib/security/","/usr/lib/x86_64-linux-gnu/security/"]);
let pkgMgrs = dynamic(["dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","update-alternatives","unattended-upgrade","unattended-upgr"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (pamPaths)
| where FileName startswith "pam_" and FileName endswith ".so"
| where InitiatingProcessFileName !in~ (pkgMgrs)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Trojanized OpenSSH binary replacement (ssh, sshd, scp)

`UC_5_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash values(Filesystem.process_name) as writer_process values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/usr/bin/ssh","/usr/sbin/sshd","/usr/bin/scp","/usr/bin/sftp","/usr/bin/ssh-agent","/usr/bin/ssh-keygen","/bin/ssh","/sbin/sshd")) (Filesystem.action=created OR Filesystem.action=modified OR Filesystem.action=renamed) by Filesystem.dest Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | search NOT writer_process IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","update-alternatives","unattended-upgrade") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let sshPaths = dynamic(["/usr/bin/ssh","/usr/sbin/sshd","/usr/bin/scp","/usr/bin/sftp","/usr/bin/ssh-agent","/usr/bin/ssh-keygen","/bin/ssh","/sbin/sshd","/usr/local/bin/ssh","/usr/local/sbin/sshd"]);
let pkgMgrs = dynamic(["dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","update-alternatives","unattended-upgrade","unattended-upgr"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| extend FullPath = strcat(FolderPath, iff(FolderPath endswith "/", "", "/"), FileName)
| where FullPath in~ (sshPaths)
| where InitiatingProcessFileName !in~ (pkgMgrs)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, FullPath, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Nginx FastCGI bridge to air-gap: fcgiwrap/'uptime' spawning ssh from web request

`UC_5_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_name) as child values(Processes.parent_process_name) as parent values(Processes.parent_process) as parent_cmd values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("fcgiwrap","uptime","nginx") OR Processes.process_name="uptime") (Processes.process_name IN ("ssh","scp","sftp","nc","ncat","socat","netcat","bash","sh")) by Processes.dest Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | search NOT (parent="nginx" AND child IN ("nginx")) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (InitiatingProcessFileName in~ ("fcgiwrap","uptime") or InitiatingProcessParentFileName in~ ("fcgiwrap","uptime"))
| where FileName in~ ("ssh","scp","sftp","nc","ncat","netcat","socat","bash","sh","dash")
| extend NginxChain = iff(InitiatingProcessParentFileName in~ ("nginx","php-fpm"), true, false)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, NginxChain
| order by Timestamp desc
```

### smbd masquerade SOCKS5 proxy: smbd from non-canonical path or unexpected parent

`UC_5_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_path) as path values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.parent_process) as parent_cmd values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name="smbd" by Processes.dest Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)` | search NOT path IN ("/usr/sbin/smbd","/usr/local/sbin/smbd","/opt/samba/sbin/smbd") OR NOT parent IN ("systemd","init","smbd") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let canonicalSmbd = dynamic(["/usr/sbin/smbd","/usr/local/sbin/smbd","/opt/samba/sbin/smbd","/usr/libexec/smbd"]);
let canonicalParents = dynamic(["systemd","init","smbd"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "smbd"
| extend FullPath = strcat(FolderPath, iff(FolderPath endswith "/","","/"), FileName)
| where FullPath !in~ (canonicalSmbd) or InitiatingProcessFileName !in~ (canonicalParents)
| extend SuspiciousPath = FolderPath has_any ("/tmp/","/var/tmp/","/dev/shm/","/home/","/root/","/opt/","/var/lib/")
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName =~ "smbd"
    | where RemotePort !in (137,138,139,445)
    | summarize NetPorts = make_set(RemotePort), NetPeers = make_set(RemoteIP) by DeviceId, InitiatingProcessId
  ) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| project Timestamp, DeviceName, FullPath, ProcessCommandLine, SuspiciousPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, NetPorts, NetPeers
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
