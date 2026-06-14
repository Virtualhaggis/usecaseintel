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
- **T1090** — Proxy
- **T1021.004** — Remote Services: SSH
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1036.005** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GS-Netcat reverse shell calling gs.thc.org relay (Velvet Ant Operation Highland)

`UC_4_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.src_ip) as src_ip values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as process from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="gs.thc.org" OR All_Traffic.dest="*.gs.thc.org") by All_Traffic.src host All_Traffic.user | `drop_dm_object_name(All_Traffic)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.query) as query from datamodel=Network_Resolution.DNS where (DNS.query="gs.thc.org" OR DNS.query="*.gs.thc.org") by DNS.src host | `drop_dm_object_name(DNS)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let Relay = dynamic(["gs.thc.org"]);
let Net = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl in~ (Relay) or RemoteUrl endswith ".gs.thc.org"
    | project Timestamp, DeviceName, DeviceId, RemoteUrl, RemoteIP, RemotePort, Protocol,
              InitiatingProcessFileName, InitiatingProcessFolderPath,
              InitiatingProcessCommandLine, InitiatingProcessAccountName,
              InitiatingProcessSHA256;
let Dns = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse" or ActionType has "Dns"
    | where AdditionalFields has "gs.thc.org" or RemoteUrl has "gs.thc.org"
    | project Timestamp, DeviceName, DeviceId, RemoteUrl, AdditionalFields,
              InitiatingProcessFileName, InitiatingProcessCommandLine;
Net | union Dns
    | order by Timestamp desc
```

### Backdoored pam_unix.so / PAM module replacement (Velvet Ant credential harvest)

`UC_4_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.action) as action values(Filesystem.process_name) as process values(Filesystem.process_path) as process_path values(Filesystem.user) as user values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/lib/security/*","/lib64/security/*","/usr/lib/security/*","/usr/lib64/security/*","/usr/lib/x86_64-linux-gnu/security/*") OR Filesystem.file_name IN ("pam_unix.so","pam_sshd.so","pam_sss.so","pam_tally2.so","pam_succeed_if.so")) Filesystem.action IN ("created","modified","renamed") NOT (Filesystem.process_name IN ("dpkg","rpm","apt","apt-get","yum","dnf","zypper","pacman","rpm-ostree","unattended-upgrade")) by host Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let PamDirs = dynamic([@"/lib/security/", @"/lib64/security/", @"/usr/lib/security/", @"/usr/lib64/security/", @"/usr/lib/x86_64-linux-gnu/security/"]);
let PkgMgrs = dynamic(["dpkg","rpm","apt","apt-get","yum","dnf","zypper","pacman","rpm-ostree","unattended-upgrade","PackageKit"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (PamDirs)
| where FileName endswith ".so"
| where InitiatingProcessFileName !in~ (PkgMgrs)
| where InitiatingProcessCommandLine !has "update-alternatives"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Trojanized OpenSSH binary (ssh/sshd/scp) replacement outside package manager

`UC_4_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.action) as action values(Filesystem.process_name) as process values(Filesystem.process_path) as process_path values(Filesystem.user) as user values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/scp","/usr/bin/sftp","/usr/libexec/openssh/sftp-server","/usr/local/sbin/sshd","/usr/local/bin/ssh")) Filesystem.action IN ("created","modified","renamed") NOT (Filesystem.process_name IN ("dpkg","rpm","apt","apt-get","yum","dnf","zypper","pacman","unattended-upgrade","update-alternatives")) by host Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let SshBins = dynamic([@"/usr/sbin/sshd", @"/usr/bin/ssh", @"/usr/bin/scp", @"/usr/bin/sftp", @"/usr/libexec/openssh/sftp-server", @"/usr/local/sbin/sshd", @"/usr/local/bin/ssh", @"/usr/local/bin/scp"]);
let PkgMgrs = dynamic(["dpkg","rpm","apt","apt-get","yum","dnf","zypper","pacman","rpm-ostree","unattended-upgrade","PackageKit","update-alternatives"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| extend FullPath = strcat(FolderPath, FileName)
| where FullPath in~ (SshBins)
| where InitiatingProcessFileName !in~ (PkgMgrs)
| project Timestamp, DeviceName, ActionType, FullPath, SHA256, MD5, FileSize,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### fcgiwrap spawning ssh/scp/uptime — Velvet Ant air-gap execution bridge

`UC_4_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process) as parent_process values(Processes.process) as process values(Processes.user) as user values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where (Processes.parent_process_name="fcgiwrap" OR Processes.parent_process="*fcgiwrap*") (Processes.process_name IN ("ssh","scp","sshpass","nc","ncat","socat","uptime","bash","sh","dash")) by host Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process) as parent_process values(Processes.process) as process values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name="uptime" Processes.process_name IN ("ssh","scp","sshpass","nc") by host Processes.process_name | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (InitiatingProcessFileName =~ "fcgiwrap" 
         and (FileName in~ ("ssh","scp","sshpass","nc","ncat","socat","uptime","bash","sh","dash","python","python3","perl")
              or FolderPath !startswith "/usr/bin/" and FolderPath !startswith "/bin/" and FolderPath !startswith "/usr/lib/cgi-bin/"))
   or (InitiatingProcessFileName =~ "uptime" 
         and FileName in~ ("ssh","scp","sshpass","nc","ncat","bash","sh"))
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ParentSHA256 = InitiatingProcessSHA256,
          ChildImage = FolderPath,
          ChildName = FileName,
          ChildCmd = ProcessCommandLine,
          ChildSHA256 = SHA256,
          GrandparentImage = InitiatingProcessParentFileName
| order by Timestamp desc
```

### smbd masquerade — SOCKS5 proxy running as 'smbd -D' from wrong path or parent

`UC_4_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name values(Processes.process_path) as process_path values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process="*smbd*-D*" OR (Processes.process_name="smbd" AND Processes.process="*-D*")) NOT (Processes.process_path IN ("/usr/sbin/smbd","/usr/local/sbin/smbd")) by host Processes.process_path Processes.parent_process_name Processes.user | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name="smbd" Processes.parent_process_name!="systemd" Processes.parent_process_name!="init" Processes.parent_process_name!="samba" Processes.parent_process_name!="smbd" by host Processes.parent_process_name Processes.process_path | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LegitSmbdPaths = dynamic([@"/usr/sbin/smbd", @"/usr/local/sbin/smbd"]);
let LegitParents = dynamic(["systemd","init","samba","samba-bgqd","smbd","winbindd"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "smbd" and ProcessCommandLine has "-D"
| extend FullPath = strcat(FolderPath, FileName)
| where FullPath !in~ (LegitSmbdPaths)
   or InitiatingProcessFileName !in~ (LegitParents)
| project Timestamp, DeviceName, AccountName, FullPath, FileName,
          ProcessCommandLine, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine
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
