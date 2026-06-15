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
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1556** — Modify Authentication Process
- **T1554** — Compromise Host Software Binary
- **T1056.001** — Input Capture: Keylogging
- **T1572** — Protocol Tunneling
- **T1021.004** — Remote Services: SSH
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090** — Proxy
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1573** — Encrypted Channel
- **T1095** — Non-Application Layer Protocol
- **T1219** — Remote Access Software

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Velvet Ant PAM backdoor — unauthorized pam_unix.so / PAM module modification on Linux

`UC_7_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN (created,modified,written,renamed) (Filesystem.file_path="/lib/security/pam_*.so" OR Filesystem.file_path="/lib64/security/pam_*.so" OR Filesystem.file_path="/usr/lib/security/pam_*.so" OR Filesystem.file_path="/usr/lib64/security/pam_*.so" OR Filesystem.file_path="/lib/x86_64-linux-gnu/security/pam_*.so") NOT (Filesystem.process_name IN (dpkg,rpm,yum,apt,"apt-get",dnf,zypper,"unattended-upgrade","unattended-upgr","rpm-ostree")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath matches regex @"^/(usr/)?lib(64)?(/x86_64-linux-gnu)?/security/?$"
| where FileName startswith "pam_" and FileName endswith ".so"
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","apt","apt-get","dnf","zypper","unattended-upgrade","unattended-upgr","rpm-ostree")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          PreviousFileName, PreviousFolderPath
| order by Timestamp desc
```

### Velvet Ant trojanized OpenSSH — unauthorized sshd/ssh/scp binary replacement

`UC_7_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN (created,modified,written,renamed) (Filesystem.file_path="/usr/sbin/sshd" OR Filesystem.file_path="/usr/bin/ssh" OR Filesystem.file_path="/usr/bin/scp" OR Filesystem.file_path="/usr/libexec/openssh/sftp-server" OR Filesystem.file_path="/usr/lib/openssh/sftp-server" OR Filesystem.file_path="/usr/local/sbin/sshd" OR Filesystem.file_path="/usr/local/bin/ssh") NOT (Filesystem.process_name IN (dpkg,rpm,yum,apt,"apt-get",dnf,zypper,"unattended-upgrade","rpm-ostree")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let ssh_binaries = dynamic(["sshd","ssh","scp","sftp-server","ssh-keygen","ssh-agent","ssh-add"]);
let pkg_mgrs = dynamic(["dpkg","rpm","yum","apt","apt-get","dnf","zypper","unattended-upgrade","unattended-upgr","rpm-ostree"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in~ (ssh_binaries)
| where FolderPath matches regex @"^/(usr/)?(s?bin|libexec/openssh|lib/openssh|local/(s?bin|libexec))/?$"
| where InitiatingProcessFileName !in~ (pkg_mgrs)
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, FileSize,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          PreviousFileName, PreviousFolderPath
| order by Timestamp desc
```

### Velvet Ant air-gap bridge — fcgiwrap/uptime spawning SSH from HTTP-driven FastCGI

`UC_7_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name=fcgiwrap OR Processes.parent_process_name=uptime OR Processes.parent_process_name=nginx) Processes.process_name IN (ssh,scp,sftp,nc,ncat,socat,bash,sh,curl,wget,python,python3,perl) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | where NOT (parent_process_name="nginx" AND process_name IN ("sh","bash") AND process LIKE "%logrotate%") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let suspicious_children = dynamic(["ssh","scp","sftp","nc","ncat","socat","bash","sh","dash","curl","wget","python","python3","perl"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("fcgiwrap","uptime","nginx")
| where FileName in~ (suspicious_children)
| where not (InitiatingProcessFileName =~ "nginx" and FileName in~ ("sh","bash") and ProcessCommandLine has_any ("logrotate","reload"))
| project Timestamp, DeviceName, AccountName,
          ParentFile = InitiatingProcessFileName,
          ParentPath = InitiatingProcessFolderPath,
          ParentCmd  = InitiatingProcessCommandLine,
          ChildFile  = FileName,
          ChildPath  = FolderPath,
          ChildCmd   = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### SOCKS5 proxy masquerading as 'smbd -D' from non-Samba install path

`UC_7_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=smbd OR Processes.process LIKE "smbd -D%" OR Processes.process LIKE "smbd %-D%") NOT (Processes.process_path="/usr/sbin/smbd" OR Processes.process_path="/usr/local/samba/sbin/smbd" OR Processes.process_path="/opt/samba/sbin/smbd" OR Processes.process_path="/usr/local/sbin/smbd" OR Processes.process_path="/snap/samba/*/usr/sbin/smbd") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_path Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "smbd" or ProcessCommandLine matches regex @"(?i)^|\s)smbd\s+(-[A-Za-z]*D|--?daemon)"
| where FolderPath !startswith "/usr/sbin"
      and FolderPath !startswith "/usr/local/samba/sbin"
      and FolderPath !startswith "/usr/local/sbin"
      and FolderPath !startswith "/opt/samba"
      and FolderPath !startswith "/snap/samba"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          SHA256, MD5
| order by Timestamp desc
```

### GS-Netcat reverse shell — host beacons to gs.thc.org Global Socket relay

`UC_7_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="gs.thc.org" OR DNS.query="*.thc.org" OR DNS.answer="gs.thc.org") by DNS.src DNS.dest DNS.query DNS.answer DNS.record_type | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="gs.thc.org" OR All_Traffic.url="*gs.thc.org*" OR All_Traffic.dest_category="GlobalSocketRelay") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)`]
```

**Defender KQL:**
```kql
union
(
  DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has "gs.thc.org" or RemoteUrl endswith ".thc.org"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
            RemoteUrl, RemoteIP, RemotePort, Protocol,
            InitiatingProcessFileName, InitiatingProcessFolderPath,
            InitiatingProcessCommandLine, SourceTable="DeviceNetworkEvents"
),
(
  DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | where RemoteUrl has "gs.thc.org" or RemoteUrl endswith ".thc.org"
     or AdditionalFields has "gs.thc.org"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
            RemoteUrl, RemoteIP="", RemotePort=int(null), Protocol="DNS",
            InitiatingProcessFileName, InitiatingProcessFolderPath,
            InitiatingProcessCommandLine, SourceTable="DeviceEvents"
)
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
