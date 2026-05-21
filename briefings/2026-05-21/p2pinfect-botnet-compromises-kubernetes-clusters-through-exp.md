# [CRIT] P2PInfect Botnet Compromises Kubernetes Clusters Through Exposed Redis Instances

**Source:** Cyber Security News
**Published:** 2026-05-21
**Article:** https://cybersecuritynews.com/p2pinfect-botnet-compromises-kubernetes-clusters-through-exposed-redis-instances/

## Threat Profile

Home Cyber Security News 
P2PInfect Botnet Compromises Kubernetes Clusters Through Exposed Redis Instances 
By Tushar Subhra Dutta 
May 21, 2026 
A well-known botnet is now targeting cloud environments in a more calculated way than before. P2PInfect, a Rust-written peer-to-peer malware active since mid-2023, has been observed compromising Kubernetes clusters by breaking into Redis instances left exposed to the internet. 
The campaign marks a notable shift, moving from simple server infections to…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-0543`
- **CVE:** `CVE-2025-49844`
- **CVE:** `CVE-2025-11953`
- **CVE:** `CVE-2025-55182`
- **IPv4 (defanged):** `8.210.50.65`
- **IPv4 (defanged):** `8.218.225.42`
- **IPv4 (defanged):** `8.210.178.40`
- **IPv4 (defanged):** `47.86.5.176`
- **IPv4 (defanged):** `178.62.63.125`
- **IPv4 (defanged):** `47.237.140.12`
- **IPv4 (defanged):** `47.83.124.121`
- **IPv4 (defanged):** `47.86.33.195`
- **MD5:** `80676a539765a9e117f20b6b99887eca`
- **MD5:** `5d1ca537c4bedebf2f4d276d4199ea95`
- **MD5:** `a1a35afebb585917675534de3d610c93`
- **MD5:** `08ad2c2877edda9a050b81d011c1c003`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1027** — Obfuscated Files or Information
- **T1059.004** — Unix Shell
- **T1203** — Exploitation for Client Execution
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090.001** — Internal Proxy
- **T1129** — Shared Modules
- **T1554** — Compromise Host Software Binary
- **T1552.005** — Credentials from Cloud Instance Metadata API
- **T1082** — System Information Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Unauthorised inbound TCP/6379 to Kubernetes Redis pods from public Internet

`UC_8_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src_ip) as src_ip values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.action) as action from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=6379 All_Traffic.action=allowed NOT (All_Traffic.src_category=internal OR All_Traffic.src_ip IN (10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16)) by All_Traffic.dest_ip All_Traffic.src_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | where count >= 1 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where LocalPort == 6379
| where ActionType in ("InboundConnectionAccepted", "ConnectionSuccess")
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("redis-server", "redis-server.exe")
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine
| summarize ConnCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, RemoteIP, LocalIP
| order by FirstSeen desc
```

### [LLM] Redis container spawning shell (sh/bash) or download utility — P2PInfect post-SLAVEOF execution

`UC_8_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name="redis-server" Processes.process_name IN ("sh","bash","dash","curl","wget","python","python3","perl","nc","ncat","socat") by Processes.dest Processes.parent_process_name Processes.process_name Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "redis-server"
| where FileName in~ ("sh", "bash", "dash", "curl", "wget", "python", "python3", "perl", "nc", "ncat", "socat", "chmod", "chown")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256, MD5
| order by Timestamp desc
```

### [LLM] Outbound connections from Kubernetes pods to known P2PInfect mesh peer IPs

`UC_8_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src_ip) as src_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("8.210.50.65","8.218.225.42","8.210.178.40","47.86.5.176","178.62.63.125","47.237.140.12","47.83.124.121","47.86.33.195") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let P2PInfectPeers = dynamic(["8.210.50.65","8.218.225.42","8.210.178.40","47.86.5.176","178.62.63.125","47.237.140.12","47.83.124.121","47.86.33.195"]);
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteIP in (P2PInfectPeers)
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| summarize ConnCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Peers = make_set(RemoteIP), Ports = make_set(RemotePort) by DeviceName, InitiatingProcessFileName
| order by FirstSeen asc
```

### [LLM] P2PInfect malicious Redis module dropped — known MD5 hash match

`UC_8_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("80676a539765a9e117f20b6b99887eca","5d1ca537c4bedebf2f4d276d4199ea95","a1a35afebb585917675534de3d610c93","08ad2c2877edda9a050b81d011c1c003") by Filesystem.dest Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let P2PInfectHashes = dynamic(["80676a539765a9e117f20b6b99887eca","5d1ca537c4bedebf2f4d276d4199ea95","a1a35afebb585917675534de3d610c93","08ad2c2877edda9a050b81d011c1c003"]);
DeviceFileEvents
| where Timestamp > ago(180d)
| where MD5 in (P2PInfectHashes)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, MD5, SHA256, FileSize, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Kubernetes pod accessing cloud instance metadata service from Redis context

`UC_8_11` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src_ip) as src_ip values(Processes.process) as cmdline from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="169.254.169.254" All_Traffic.app IN ("redis-server","sh","bash","curl","wget","python","python3") by All_Traffic.src_ip All_Traffic.app All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "169.254.169.254"
| where InitiatingProcessFileName in~ ("redis-server", "sh", "bash", "dash", "curl", "wget", "python", "python3", "perl", "nc", "ncat")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `8.210.50.65`, `8.218.225.42`, `8.210.178.40`, `47.86.5.176`, `178.62.63.125`, `47.237.140.12`, `47.83.124.121`, `47.86.33.195`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-0543`, `CVE-2025-49844`, `CVE-2025-11953`, `CVE-2025-55182`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `80676a539765a9e117f20b6b99887eca`, `5d1ca537c4bedebf2f4d276d4199ea95`, `a1a35afebb585917675534de3d610c93`, `08ad2c2877edda9a050b81d011c1c003`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 12 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
