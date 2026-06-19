# [HIGH] F5 issues out-of-band patches for critical NGINX vulnerabilities

**Source:** BleepingComputer
**Published:** 2026-06-18
**Article:** https://www.bleepingcomputer.com/news/security/f5-issues-out-of-band-patches-for-critical-nginx-vulnerabilities/

## Threat Profile

F5 issues out-of-band patches for critical NGINX vulnerabilities 
By Sergiu Gatlan 
June 18, 2026
07:33 AM
0 
Cybersecurity company F5 has released out-of-band security updates to address multiple NGINX web server vulnerabilities, including two critical-severity flaws that could allow attackers to execute code on vulnerable systems.
The two critical vulnerabilities were found in the ngx_http_v3_module ( CVE-2026-42530 ) and the ngx_http_proxy_v2_module and ngx_http_grpc_module ( CVE-2026-42055 )…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-42530`
- **CVE:** `CVE-2026-42055`
- **CVE:** `CVE-2026-11311`
- **CVE:** `CVE-2026-50107`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1499.004** — Endpoint Denial of Service: Application or System Exploitation
- **T1505.004** — Server Software Component: IIS Components
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable NGINX versions exposed to CVE-2026-42530 / CVE-2026-42055

`UC_54_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-42530","CVE-2026-42055","CVE-2026-11311","CVE-2026-50107") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.signature Vulnerabilities.severity | `drop_dm_object_name(Vulnerabilities)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-42530","CVE-2026-42055","CVE-2026-11311","CVE-2026-50107")
| where SoftwareName has_any ("nginx","nginx plus","nginx gateway fabric","nginx instance manager")
| project Timestamp, DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing, PublicIP) by DeviceId) on DeviceId
| order by IsInternetFacing desc, VulnerabilitySeverityLevel asc
```

### NGINX worker process abnormal restart fan-out (CVE-2026-42530 / 42055 post-exploit crash signal)

`UC_54_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="nginx" OR Processes.process_name="nginx") (Processes.process="*worker process*" OR Processes.action="terminated") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where count >= 3 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let WindowMinutes = 10m;
DeviceProcessEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName =~ "nginx" or FileName =~ "nginx"
| where ActionType in ("ProcessCreated","ProcessCreatedUsingWmiCommand")
| where ProcessCommandLine has_any ("worker process","-s reload","master process")
| summarize WorkerRespawns = count(), StartTime = min(Timestamp), EndTime = max(Timestamp) by DeviceId, DeviceName, bin(Timestamp, WindowMinutes)
| where WorkerRespawns >= 5     // 5 = empirical worker-respawn floor; healthy nginx restarts cluster on reload, exploit-driven crashes spread over time
| order by WorkerRespawns desc
```

### Oversized HTTP request headers against NGINX (CVE-2026-42055 trigger condition)

`UC_54_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.status) as statuses from datamodel=Web.Web where Web.bytes_in > 524288 by Web.src Web.dest Web.http_user_agent | `drop_dm_object_name(Web)` | where count >= 1 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

### NGINX Gateway Fabric arbitrary directive injection (CVE-2026-11311 / CVE-2026-50107)

`UC_54_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as users values(Filesystem.process_name) as procs from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/etc/nginx/conf.d/*","/etc/nginx/nginx.conf","/etc/nginx-gateway/*") Filesystem.action IN ("created","modified") by Filesystem.dest Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any ("/etc/nginx/", "/etc/nginx-gateway/", "/usr/local/nginx/conf/", "/etc/nginx/conf.d/")
| where FileName endswith ".conf" or FileName == "nginx.conf"
| where InitiatingProcessFileName !in~ ("dpkg","rpm","apt","yum","dnf","ansible-playbook","puppet","chef-client","salt-minion","helm","kubectl")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
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
  - CVE(s): `CVE-2026-42530`, `CVE-2026-42055`, `CVE-2026-11311`, `CVE-2026-50107`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 8 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
