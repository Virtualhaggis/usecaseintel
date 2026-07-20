# [HIGH] Attacking an FTP Client: MGETting more than you bargained for

**Source:** Snyk
**Published:** 2018-04-04
**Article:** https://snyk.io/blog/attacking-an-ftp-client/

## Threat Profile

Snyk Blog In this article
Written by Danny Grander 
April 4, 2018
0 mins read Introduction We often hear about vulnerabilities in HTTP clients, such as web browsers, that are typically exploited by malicious web content, there’s nothing new here. But did you know that the FTP clients themselves can also have vulnerabilities that can be exploited? FTP clients can be targeted by malicious servers that the clients connect to.
In this blog post, I’ll show an interesting path traversal vulnerability …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2018-1315`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1565.001** — Data Manipulation: Stored Data Manipulation
- **T1068** — Exploitation for Privilege Escalation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### FTP client / Hive (commons-net) overwrites Unix auth files via path-traversal LIST (CVE-2018-1315)

`UC_3596_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/passwd" OR Filesystem.file_path="/etc/shadow" OR Filesystem.file_path="/etc/sudoers" OR Filesystem.file_path="*/.ssh/authorized_keys") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.user Filesystem.process_guid 
| `drop_dm_object_name(Filesystem)` 
| join type=inner process_guid [| tstats `summariesonly` values(Processes.process_name) as process_name values(Processes.process) as process from datamodel=Endpoint.Processes where (Processes.process_name=java OR Processes.process_name=hive OR Processes.process_name=beeline OR Processes.process_name=node OR Processes.process_name=ftp OR Processes.process_name=lftp OR Processes.process_name=ncftp) by Processes.process_guid | `drop_dm_object_name(Processes)`] 
| table firstTime lastTime dest user process_name process file_path file_name count
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("passwd","shadow","sudoers") and FolderPath has "/etc/")
     or (FileName =~ "authorized_keys" and FolderPath has "/.ssh")
| where InitiatingProcessFileName has_any ("java","hive","beeline","node","python","ftp","lftp","ncftp")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, ActionType, SHA256
| order by Timestamp desc
```

### FTP control-channel connection followed by write to Unix system path (CVE-2018-1315 traversal chain)

`UC_3596_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as fileTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/passwd" OR Filesystem.file_path="/etc/shadow" OR Filesystem.file_path="/etc/sudoers" OR Filesystem.file_path="*/.ssh/authorized_keys") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.user _time span=1s 
| `drop_dm_object_name(Filesystem)` 
| join type=inner dest [| tstats `summariesonly` count from datamodel=Network_Traffic where All_Traffic.dest_port=21 by All_Traffic.src _time span=1s | `drop_dm_object_name(All_Traffic)` | rename src as dest, _time as net_time, count as ftp_conns] 
| eval delta=_time-net_time | where delta>=0 AND delta<=300 
| table fileTime net_time delta dest user file_path file_name
```

**Defender KQL:**
```kql
let Window = 5m;
let FtpConn = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemotePort == 21
    | project NetTime = Timestamp, DeviceId, RemoteIP, FtpProc = InitiatingProcessFileName, FtpCmd = InitiatingProcessCommandLine;
DeviceFileEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("passwd","shadow","sudoers") and FolderPath has "/etc/")
     or (FileName =~ "authorized_keys" and FolderPath has "/.ssh")
| join kind=inner FtpConn on DeviceId
| where Timestamp between (NetTime .. NetTime + Window)
| project FileWriteTime = Timestamp, NetTime, DeviceName, DeviceId, InitiatingProcessFileName, FolderPath, FileName, RemoteIP, FtpProc, FtpCmd
| order by FileWriteTime desc
```

### Article-specific behavioural hunt — Attacking an FTP Client: MGETting more than you bargained for

`UC_3596_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Attacking an FTP Client: MGETting more than you bargained for ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("autoexec.bat"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/var/data/sync/*" OR Filesystem.file_path="*/var/data/sync/passwd*" OR Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_path="*/var/data/sync/../../../../etc/passwd*" OR Filesystem.file_path="*/home/root/.ssh/authorized_keys*" OR Filesystem.file_name IN ("autoexec.bat"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Attacking an FTP Client: MGETting more than you bargained for
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("autoexec.bat"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/var/data/sync/", "/var/data/sync/passwd", "/etc/passwd", "/var/data/sync/../../../../etc/passwd", "/home/root/.ssh/authorized_keys") or FileName in~ ("autoexec.bat"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2018-1315`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
