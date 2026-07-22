# [HIGH] Estée Lauder discloses data breach via Oracle E-Business flaw

**Source:** BleepingComputer
**Published:** 2026-07-20
**Article:** https://www.bleepingcomputer.com/news/security/est-e-lauder-discloses-data-breach-via-oracle-e-business-flaw/

## Threat Profile

Estée Lauder discloses data breach via Oracle E-Business flaw 
By Bill Toulas 
July 20, 2026
06:39 PM
0 
Cosmetics giant Estée Lauder is notifying customers of a data breach after hackers exploited a flaw in Oracle E-Business Suite that the company used for human resources (HR) operations.
The company says that last month it identified an intrusion that had occurred on August 9, 2025, which led to the threat actor obtaining " personal information of certain individuals."
“We became aware of a cy…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-61882`
- **IPv4 (defanged):** `200.107.207.26`
- **IPv4 (defanged):** `185.181.60.11`
- **IPv4 (defanged):** `161.97.99.49`
- **IPv4 (defanged):** `162.55.17.215`
- **IPv4 (defanged):** `104.194.11.200`
- **Domain (defanged):** `pubstorm.com`
- **Domain (defanged):** `pubstorm.net`
- **SHA256:** `76b6d36e04e367a2334c445b51e1ecce97e4c614e88dfb4f72b104ca0f31235d`
- **MD5:** `b296d3b3115762096286f225696a9bb1`
- **MD5:** `23094d64721a279c0ce637584b87d6f1`
- **MD5:** `e278700f827590c1dff9e24116bde4da`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1211** — Exploitation for Defense Evasion
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Clop CVE-2025-61882 Oracle EBS exploitation via BI Publisher TemplatePreview / SyncServlet URIs

`UC_44_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*TemplatePreviewPG*" OR Web.url="*/OA_HTML/SyncServlet*" OR Web.url="*/OA_HTML/configurator/UiServlet*" OR Web.url="*/OA_HTML/RF.jsp*") by Web.src, Web.dest, Web.http_method, Web.url, Web.status, Web.http_user_agent
| `drop_dm_object_name(Web)`
| sort - lastTime
```

### Oracle EBS Java app-tier service spawning shell / reverse shell (CVE-2025-61882 post-exploitation)

`UC_44_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.Processes.parent_process_name="java" (Endpoint.Processes.process="*/dev/tcp*" OR Endpoint.Processes.process="*bash -i*" OR Endpoint.Processes.process="*exp.py*" OR Endpoint.Processes.process="*server.py*" OR Endpoint.Processes.process="*oracle_ebs_nday_exploit*") by Endpoint.Processes.dest, Endpoint.Processes.user, Endpoint.Processes.parent_process, Endpoint.Processes.process_name, Endpoint.Processes.process
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "java" or InitiatingProcessCommandLine has_any ("oracle.apps","XMLPublisher","XDOTemplate","FNDLIBR")
| where FileName in~ ("bash","sh","dash","ksh","python","python3","perl","curl","wget","nc","ncat")
| where ProcessCommandLine has_any ("/dev/tcp","bash -i","exp.py","server.py","oracle_ebs_nday_exploit")
   or ProcessCommandLine matches regex @"-i\s*>&\s*/dev/tcp"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Clop CVE-2025-61882 Oracle EBS C2 / exfiltration beacon to known infrastructure

`UC_44_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("200.107.207.26","185.181.60.11","161.97.99.49","162.55.17.215","104.194.11.200") by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.app, All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| sort - lastTime
```

**Defender KQL:**
```kql
let c2ips = dynamic(["200.107.207.26","185.181.60.11","161.97.99.49","162.55.17.215","104.194.11.200"]);
let c2domains = dynamic(["pubstorm.com","pubstorm.net","oa.88tech.me"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (c2ips) or RemoteUrl has_any (c2domains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol
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
  - CVE(s): `CVE-2025-61882`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `200.107.207.26`, `185.181.60.11`, `161.97.99.49`, `162.55.17.215`, `104.194.11.200`, `pubstorm.com`, `pubstorm.net`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `76b6d36e04e367a2334c445b51e1ecce97e4c614e88dfb4f72b104ca0f31235d`, `b296d3b3115762096286f225696a9bb1`, `23094d64721a279c0ce637584b87d6f1`, `e278700f827590c1dff9e24116bde4da`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 9 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
