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
- **T1040** — Network Sniffing
- **T1572** — Protocol Tunneling
- **T1021.004** — Remote Services: SSH
- **T1090.001** — Internal Proxy
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1036** — Masquerading
- **T1090** — Proxy
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573.001** — Encrypted Channel: Symmetric Cryptography
- **T1219** — Remote Access Software

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Velvet Ant PAM module replacement in /lib/security/ (pam_unix.so backdoor)

`UC_4_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.action="created" OR Filesystem.action="modified") AND (Filesystem.file_path="/lib/security/*" OR Filesystem.file_path="/lib64/security/*" OR Filesystem.file_path="/usr/lib/security/*" OR Filesystem.file_path="/usr/lib64/security/*") AND Filesystem.file_name="*.so" AND NOT Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","authselect","unattended-upgrade") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_path Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any ("/lib/security/","/lib64/security/","/usr/lib/security/","/usr/lib64/security/")
| where FileName endswith ".so"
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","authselect","unattended-upgrade","packagekitd")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### OpenSSH binary trojanization (sshd/ssh/scp replaced outside package update)

`UC_4_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.action="created" OR Filesystem.action="modified") AND (Filesystem.file_path="/usr/sbin/sshd" OR Filesystem.file_path="/usr/bin/ssh" OR Filesystem.file_path="/usr/bin/scp" OR Filesystem.file_path="/usr/bin/sftp" OR Filesystem.file_path="/usr/bin/ssh-keygen" OR Filesystem.file_path="/usr/bin/ssh-agent" OR Filesystem.file_path="/usr/bin/ssh-add") AND NOT Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","unattended-upgrade","packagekitd") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let OpenSSHPaths = dynamic(["/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/scp","/usr/bin/sftp","/usr/bin/ssh-keygen","/usr/bin/ssh-agent","/usr/bin/ssh-add","/usr/libexec/openssh/sftp-server"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| extend FullPath = strcat(FolderPath, FileName)
| where FullPath in~ (OpenSSHPaths) or (FolderPath in~ ("/usr/sbin/","/usr/bin/","/usr/libexec/openssh/") and FileName in~ ("sshd","ssh","scp","sftp","ssh-keygen","ssh-agent","ssh-add","sftp-server"))
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","unattended-upgrade","packagekitd","rpm2cpio")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, ActionType, FullPath, FileName, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### fcgiwrap spawning SSH/network child — Velvet Ant Nginx air-gap proxy chain

`UC_4_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="fcgiwrap" OR Processes.parent_process="*fcgiwrap*") AND (Processes.process_name IN ("ssh","scp","sftp","nc","ncat","netcat","socat","curl","wget","bash","sh","dash") OR Processes.process_path="*/uptime") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "fcgiwrap" or InitiatingProcessParentFileName =~ "fcgiwrap" or InitiatingProcessCommandLine has "fcgiwrap"
| where FileName in~ ("ssh","scp","sftp","nc","ncat","netcat","socat","bash","sh","dash","curl","wget")
   or FolderPath endswith "/uptime"
   or ProcessCommandLine has_any ("ssh ","ssh -","scp ","socat ")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
          InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

### smbd -D daemon from non-Samba path — Velvet Ant SOCKS5 proxy masquerade

`UC_4_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="smbd" OR Processes.process="smbd*-D*") AND NOT (Processes.process_path="/usr/sbin/smbd" OR Processes.process_path="/usr/lib/samba/*" OR Processes.process_path="/opt/samba/*" OR Processes.process_path="/snap/samba/*" OR Processes.process_path="/var/lib/snapd/snap/samba/*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "smbd" or ProcessCommandLine matches regex @"(?i)^[^\s]*\bsmbd\b\s+-D\b")
| where ProcessCommandLine has "-D"
| where not (FolderPath in~ ("/usr/sbin/","/usr/lib/samba/","/opt/samba/sbin/","/opt/samba/bin/") or FolderPath startswith "/snap/samba/" or FolderPath startswith "/var/lib/snapd/snap/samba/")
| where InitiatingProcessFileName !in~ ("systemd","init","systemd-init","start-stop-daemon")
   or (InitiatingProcessFileName =~ "systemd" and not (FolderPath in~ ("/usr/sbin/","/usr/lib/samba/")))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Outbound connection or DNS resolution for GS-Netcat relay gs.thc.org

`UC_4_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
(| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="gs.thc.org" OR DNS.query="*.gs.thc.org" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)`) | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="gs.thc.org" OR All_Traffic.app="*gs.thc.org*" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)`] | append [| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process="*gs.thc.org*" by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookBack = 90d;
union isfuzzy=true
  (DeviceNetworkEvents
   | where Timestamp > ago(LookBack)
   | where RemoteUrl has "gs.thc.org" or RemoteUrl =~ "gs.thc.org"
   | project Timestamp, DeviceName, EvtType="NetworkConnect", Indicator=RemoteUrl, RemoteIP, RemotePort,
             InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName),
  (DeviceEvents
   | where Timestamp > ago(LookBack)
   | where ActionType in ("DnsConnectionInspected","ConnectionSuccess") and (RemoteUrl has "gs.thc.org" or AdditionalFields has "gs.thc.org")
   | project Timestamp, DeviceName, EvtType=ActionType, Indicator=RemoteUrl, RemoteIP, RemotePort,
             InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName=InitiatingProcessAccountName),
  (DeviceProcessEvents
   | where Timestamp > ago(LookBack)
   | where ProcessCommandLine has "gs.thc.org" or InitiatingProcessCommandLine has "gs.thc.org"
   | project Timestamp, DeviceName, EvtType="ProcessCmdline", Indicator=ProcessCommandLine, RemoteIP="", RemotePort=int(0),
             InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName)
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
