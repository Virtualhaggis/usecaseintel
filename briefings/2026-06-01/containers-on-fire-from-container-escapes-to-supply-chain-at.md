# [CRIT] Containers on fire: from container escapes to supply chain attacks

**Source:** Securelist (Kaspersky), Aikido
**Published:** 2026-06-01
**Article:** https://securelist.com/container-attack-vectors/120010/

## Threat Profile

Table of Contents
Introduction 
Principles of containerization 
Current attack vectors 
Exploiting host system vulnerabilities 
Malicious actions inside the container 
Container escape 
Privileged containers 
CAP_SYS_ADMIN 
CAP_SYS_MODULE 
CAP_SYS_PTRACE 
CAP_NET_ADMIN 
Exploitation of orchestration APIs 
Supply chain attacks 
Takeaways 
Authors
Alexander Chudnov 
Introduction 
Modern infrastructures universally rely on containerization to deploy applications, scale services, and build cloud pla…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2019-5736`
- **CVE:** `CVE-2022-0492`
- **CVE:** `CVE-2024-21626`
- **IPv4 (defanged):** `94.154.172.43`
- **Domain (defanged):** `audit.checkmarx.cx`
- **SHA256:** `24680027afadea90c7c713821e214b15cb6c922e67ac01109fb1edb3ee4741d9`
- **SHA256:** `2a6a35f06118ff7d61bfd36a5788557b695095e7c9a609b4a01956883f146f50`
- **SHA1:** `2b12cc5cc91ec483048abcbd6d523cdc9ebae3f3`
- **SHA1:** `250f3633529457477a9f8fd3db3472e94383606a`
- **MD5:** `d47de3772f2d61a043e7047431ef4cf4`
- **MD5:** `e1023db24a29ab0229d99764e2c8deba`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1611** — Escape to Host
- **T1610** — Deploy Container
- **T1068** — Exploitation for Privilege Escalation
- **T1554** — Compromise Host Software Binary
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1528** — Steal Application Access Token
- **T1613** — Container and Resource Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### TeamPCP Checkmarx KICS supply-chain stealer C2 callback (audit.checkmarx.cx / 94.154.172.43)

`UC_132_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="94.154.172.43" OR All_Traffic.dest="audit.checkmarx.cx" OR All_Traffic.dest="*.audit.checkmarx.cx") by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let bad_ips = dynamic(["94.154.172.43"]);
let bad_domains = dynamic(["audit.checkmarx.cx"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (bad_ips) or RemoteUrl has_any (bad_domains)
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, Protocol, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

### Privileged container launch — docker run --privileged from non-CI parent

`UC_132_8` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.process_name="docker" OR Processes.process_name="podman" OR Processes.process_name="nerdctl") Processes.process="*--privileged*" (Processes.process="* run *" OR Processes.process="* create *") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where NOT (parent_process_name IN ("containerd-shim","containerd-shim-runc-v2","buildkitd","kubelet","Runner.Listener","runner","gitlab-runner","jenkins","agent","bash") AND user IN ("jenkins","gitlab-runner","github-runner"))
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("docker","podman","nerdctl")
| where ProcessCommandLine has "--privileged"
| where ProcessCommandLine has_any (" run "," create "," exec ")
| where not(InitiatingProcessFileName has_any ("containerd-shim","buildkitd","kubelet","Runner.Listener","gitlab-runner","jenkins","github-runner"))
| where not(InitiatingProcessAccountName in~ ("jenkins","gitlab-runner","github-runner","buildkite-agent"))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Container escape via cgroups release_agent write (CVE-2022-0492)

`UC_132_9` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/cgroup/*/release_agent" OR Filesystem.file_name="release_agent" OR Filesystem.file_path="*/cgroup/*/notify_on_release") (Filesystem.action="created" OR Filesystem.action="modified" OR Filesystem.action="write") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has "/cgroup/" and (FileName == "release_agent" or FolderPath has "release_agent" or FileName == "notify_on_release")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### runC binary modified outside package manager (CVE-2019-5736 / CVE-2024-21626)

`UC_132_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/usr/bin/runc" OR Filesystem.file_path="/usr/sbin/runc" OR Filesystem.file_path="/usr/local/bin/runc" OR Filesystem.file_path="/usr/bin/docker-runc" OR Filesystem.file_path="/usr/libexec/docker/docker-runc") (Filesystem.action="created" OR Filesystem.action="modified" OR Filesystem.action="write" OR Filesystem.action="renamed") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | search NOT process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","snap","snapd","zypper","containerd")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath in~ ("/usr/bin/runc","/usr/sbin/runc","/usr/local/bin/runc","/usr/bin/docker-runc","/usr/libexec/docker/docker-runc") or FileName in~ ("runc","docker-runc")
| where FolderPath has_any ("/usr/bin","/usr/sbin","/usr/local/bin","/usr/libexec")
| where not(InitiatingProcessFileName in~ ("dpkg","apt","apt-get","yum","dnf","rpm","snap","snapd","zypper","containerd"))
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, ActionType, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Kubernetes API curl/wget with ServiceAccount token from container

`UC_132_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where (Processes.process_name="curl" OR Processes.process_name="wget" OR Processes.process_name="http" OR Processes.process_name="httpie") (Processes.process="*/api/v1/namespaces*" OR Processes.process="*/api/v1/pods*" OR Processes.process="*/var/run/secrets/kubernetes.io/serviceaccount/token*" OR Processes.process="*kubernetes.default.svc*" OR Processes.process="*:6443/api/*" OR Processes.process="*:8443/api/v1/*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | search NOT parent_process_name IN ("kubelet","kubectl","helm")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("curl","wget","http","httpie")
| where ProcessCommandLine has_any ("/api/v1/namespaces","/api/v1/pods","/var/run/secrets/kubernetes.io/serviceaccount/token","kubernetes.default.svc",":6443/api/",":8443/api/v1/")
| where not(InitiatingProcessFileName in~ ("kubelet","kubectl","helm","argocd","flux"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — Containers on fire: from container escapes to supply chain attacks

`UC_132_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Containers on fire: from container escapes to supply chain attacks ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/tcp/*" OR Filesystem.file_path="*/usr/local/sbin*" OR Filesystem.file_path="*/usr/local/bin*" OR Filesystem.file_path="*/usr/sbin*" OR Filesystem.file_path="*/usr/bin*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Containers on fire: from container escapes to supply chain attacks
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/tcp/", "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2019-5736`, `CVE-2022-0492`, `CVE-2024-21626`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `94.154.172.43`, `audit.checkmarx.cx`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `24680027afadea90c7c713821e214b15cb6c922e67ac01109fb1edb3ee4741d9`, `2a6a35f06118ff7d61bfd36a5788557b695095e7c9a609b4a01956883f146f50`, `2b12cc5cc91ec483048abcbd6d523cdc9ebae3f3`, `250f3633529457477a9f8fd3db3472e94383606a`, `d47de3772f2d61a043e7047431ef4cf4`, `e1023db24a29ab0229d99764e2c8deba`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 12 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
