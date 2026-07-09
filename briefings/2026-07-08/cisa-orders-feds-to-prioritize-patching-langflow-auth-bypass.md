# [HIGH] CISA orders feds to prioritize patching Langflow auth bypass flaw

**Source:** BleepingComputer
**Published:** 2026-07-08
**Article:** https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-prioritize-patching-langflow-auth-bypass-flaw/

## Threat Profile

CISA orders feds to prioritize patching Langflow auth bypass flaw 
By Sergiu Gatlan 
July 8, 2026
05:58 AM
0 
The U.S. Cybersecurity and Infrastructure Security Agency (CISA) gave federal agencies until Friday to patch an actively exploited vulnerability in the Langflow visual framework for building AI agents.
Langflow is an attractive target for hackers since it's a popular tool in the AI development ecosystem, offering a drag-and-drop interface to connect nodes into executable pipelines and a …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-55255`
- **CVE:** `CVE-2026-33017`
- **CVE:** `CVE-2025-3248`
- **CVE:** `CVE-2026-5027`
- **CVE:** `CVE-2021-29441`
- **IPv4 (defanged):** `45.207.216.55`
- **IPv4 (defanged):** `45.131.66.106`
- **IPv4 (defanged):** `64.20.53.230`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1213** — Data from Information Repositories
- **T1059** — Command and Scripting Interpreter
- **T1059.004** — Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Langflow flow-ID enumeration chained to /api/v1/responses IDOR (CVE-2026-55255)

`UC_35_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Web.url) as urls values(Web.http_method) as methods min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/api/v1/flows*" OR Web.url="*/api/v1/responses*" OR Web.url="*/api/v1/build_public_tmp*") by Web.src Web.dest span=30m | `drop_dm_object_name(Web)` | where match(urls,"/api/v1/flows") AND (match(urls,"/api/v1/responses") OR match(urls,"/api/v1/build_public_tmp")) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

### Langflow unauth RCE payload POST to /api/v1/build_public_tmp (CVE-2026-33017)

`UC_35_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.http_method) as methods from datamodel=Web.Web where Web.url="*/api/v1/build_public_tmp*" OR Web.url="*/api/v1/auto_login*" by Web.src Web.dest Web.url | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

### Langflow host runs curl/wget piped to sh fetching /slt loader (45.207.216.55)

`UC_35_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*45.207.216.55*" OR Processes.process="*/slt*") AND (Processes.process="*curl*" OR Processes.process="*wget*" OR Processes.process_name IN ("curl","wget","sh","bash","dash")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "45.207.216.55" and ProcessCommandLine has_any ("/slt", "curl", "wget")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Langflow host beacons to JadePuffer/CVE-2026-55255 C2 (45.207.216.55:8084)

`UC_35_8` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_ports from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("45.207.216.55","45.131.66.106","64.20.53.230") by All_Traffic.src All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("45.207.216.55", "45.131.66.106", "64.20.53.230")
| summarize Conns = count(), Ports = make_set(RemotePort), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by LastSeen desc
```

### Langflow exploitation marker file /tmp/lang_pwn created

`UC_35_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Endpoint.Filesystem.file_path="/tmp/lang_pwn" OR Endpoint.Filesystem.file_name="lang_pwn") by Endpoint.Filesystem.dest Endpoint.Filesystem.file_path Endpoint.Filesystem.file_name Endpoint.Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath =~ "/tmp/lang_pwn" or FileName =~ "lang_pwn"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
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
  - CVE(s): `CVE-2026-55255`, `CVE-2026-33017`, `CVE-2025-3248`, `CVE-2026-5027`, `CVE-2021-29441`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.207.216.55`, `45.131.66.106`, `64.20.53.230`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 10 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
