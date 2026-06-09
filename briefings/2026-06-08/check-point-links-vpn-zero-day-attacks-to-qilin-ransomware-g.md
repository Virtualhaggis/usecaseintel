# [CRIT] Check Point links VPN zero-day attacks to Qilin ransomware gang

**Source:** BleepingComputer
**Published:** 2026-06-08
**Article:** https://www.bleepingcomputer.com/news/security/check-point-links-vpn-zero-day-attacks-to-qilin-ransomware-gang/

## Threat Profile

Check Point links VPN zero-day attacks to Qilin ransomware gang 
By Sergiu Gatlan 
June 8, 2026
09:05 AM
0 
Israeli cybersecurity company Check Point has released security updates to patch a critical flaw affecting Remote Access VPN and Mobile Access deployments, which was exploited in zero-day attacks.
Tracked as CVE-2026-50751 , this vulnerability can be exploited by unauthenticated, remote attackers to bypass authentication on targeted Mobile Access / SSL VPNs, Remote Access VPNs, or Spark fi…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-50751`
- **CVE:** `CVE-2026-50752`
- **IPv4 (defanged):** `45.77.149.152`
- **IPv4 (defanged):** `209.182.225.136`
- **IPv4 (defanged):** `38.60.157.139`
- **IPv4 (defanged):** `162.33.177.101`
- **IPv4 (defanged):** `45.76.26.42`
- **IPv4 (defanged):** `144.208.127.155`
- **IPv4 (defanged):** `38.54.88.201`
- **IPv4 (defanged):** `38.54.107.167`
- **IPv4 (defanged):** `66.42.99.200`
- **MD5:** `52fda5c1b9704544f32ee98d9060e689`
- **MD5:** `51d39aa39478beeac94f2d12f682ecce`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1133** — External Remote Services
- **T1556** — Modify Authentication Process
- **T1078** — Valid Accounts
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1572** — Protocol Tunneling
- **T1657** — Financial Theft
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Inbound IKEv1 traffic from Qilin VPN-bypass infrastructure to Check Point gateways

`UC_27_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.transport) as transport from datamodel=Network_Traffic.All_Traffic where All_Traffic.src_ip IN ("45.77.149.152","209.182.225.136","38.60.157.139","162.33.177.101","45.76.26.42","144.208.127.155","38.54.88.201","38.54.107.167") AND (All_Traffic.dest_port IN (500,4500) OR All_Traffic.transport="esp") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("45.77.149.152","209.182.225.136","38.60.157.139","162.33.177.101","45.76.26.42","144.208.127.155","38.54.88.201","38.54.107.167")
| where RemotePort in (500, 4500) or Protocol =~ "esp"
| project Timestamp, DeviceName, ActionType, LocalIP, LocalPort, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] Check Point IKEv1 Remote Access VPN session with no machine certificate (CVE-2026-50751 bypass shape)

`UC_27_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.user) as user values(Authentication.src) as src_ip values(Authentication.dest) as gateway from datamodel=Authentication.Authentication where Authentication.app IN ("checkpoint","checkpoint-fw","checkpoint-mobileaccess","checkpoint-ra") AND Authentication.action="success" by Authentication.signature Authentication.authentication_method Authentication.dest | `drop_dm_object_name(Authentication)` | search authentication_method="IKEv1" OR signature="*legacy*" OR signature="*ike_v1*" | search NOT authentication_method IN ("machine_certificate","cert","x509") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Downstream view — endpoints authenticating to AD via Check Point VPN pool, no Defender direct visibility of the IKE handshake itself
let VpnAttackerSrc = dynamic(["45.77.149.152","209.182.225.136","38.60.157.139","162.33.177.101","45.76.26.42","144.208.127.155","38.54.88.201","38.54.107.167"]);
IdentityLogonEvents
| where Timestamp > ago(45d)
| where ActionType == "LogonSuccess"
| where Protocol in~ ("Kerberos","NTLM","Ldap")
| where IPAddress in (VpnAttackerSrc)
   or DeviceName has_any ("vpn","ra-","mobileaccess","checkpoint")
| project Timestamp, ActionType, AccountUpn, AccountName, IPAddress, DeviceName, Protocol, LogonType, Application
| order by Timestamp desc
```

### [LLM] Long-lived VPN tunnel from VPS hosting ranges (Vultr/Cogent) attributed to Qilin VPN-bypass C2

`UC_27_8` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as session_start max(_time) as session_end sum(All_Traffic.bytes) as total_bytes from datamodel=Network_Traffic.All_Traffic where All_Traffic.src_ip IN ("45.77.149.152","209.182.225.136","38.60.157.139","162.33.177.101","45.76.26.42","144.208.127.155","38.54.88.201","38.54.107.167") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | eval duration_min = round((session_end - session_start)/60, 1) | where duration_min >= 30 | convert ctime(session_start) ctime(session_end) | sort - duration_min
```

**Defender KQL:**
```kql
let QilinIPs = dynamic(["45.77.149.152","209.182.225.136","38.60.157.139","162.33.177.101","45.76.26.42","144.208.127.155","38.54.88.201","38.54.107.167"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (QilinIPs) or LocalIP in (QilinIPs)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Connections=count(), Bytes=sum(toint(coalesce(tostring(parse_json(AdditionalFields).BytesSent),"0"))) by DeviceName, DeviceId, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName
| extend DurationMin = datetime_diff("minute", LastSeen, FirstSeen)
| where DurationMin >= 30 or Connections >= 50
| order by DurationMin desc
```

### [LLM] Qilin post-compromise payload hashes (52fda5c1, 51d39aa3) on hosts reachable from VPN concentrator

`UC_27_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_hash IN ("52fda5c1b9704544f32ee98d9060e689","51d39aa39478beeac94f2d12f682ecce") by Processes.dest Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let QilinHashes = dynamic(["52fda5c1b9704544f32ee98d9060e689","51d39aa39478beeac94f2d12f682ecce"]);
union isfuzzy=true
  (DeviceProcessEvents
   | where Timestamp > ago(60d)
   | where MD5 in (QilinHashes) or InitiatingProcessMD5 in (QilinHashes)
   | project Timestamp, DeviceName, DeviceId, EventTable="DeviceProcessEvents", FileName, FolderPath, MD5, SHA256, ProcessCommandLine, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceFileEvents
   | where Timestamp > ago(60d)
   | where MD5 in (QilinHashes)
   | project Timestamp, DeviceName, DeviceId, EventTable="DeviceFileEvents", FileName, FolderPath, MD5, SHA256, ProcessCommandLine="", AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceImageLoadEvents
   | where Timestamp > ago(60d)
   | where MD5 in (QilinHashes)
   | project Timestamp, DeviceName, DeviceId, EventTable="DeviceImageLoadEvents", FileName, FolderPath, MD5, SHA256, ProcessCommandLine="", AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine="")
| order by Timestamp desc
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-50751`, `CVE-2026-50752`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.77.149.152`, `209.182.225.136`, `38.60.157.139`, `162.33.177.101`, `45.76.26.42`, `144.208.127.155`, `38.54.88.201`, `38.54.107.167` _(+1 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `52fda5c1b9704544f32ee98d9060e689`, `51d39aa39478beeac94f2d12f682ecce`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
