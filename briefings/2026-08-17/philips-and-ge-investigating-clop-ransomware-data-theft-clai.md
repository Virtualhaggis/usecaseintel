# [HIGH] Philips and GE investigating Clop ransomware data theft claims

**Source:** BleepingComputer
**Published:** 2026-08-17
**Article:** https://www.bleepingcomputer.com/news/security/philips-and-ge-investigating-clop-ransomware-data-theft-claims/

## Threat Profile

Philips and GE investigating Clop ransomware data theft claims 
By Sergiu Gatlan 
August 17, 2026
07:25 AM
0 
Tech giants General Electric (GE) and Philips have also confirmed they're investigating claims that the Clop ransomware gang breached their systems and stole data.
While a GE spokesperson said the company is aware of the claim and is "working to assess the potential issue," a Philips spokesperson confirmed its systems were breached but said the incident has been contained and didn't affe…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-12569`
- **IPv4 (defanged):** `216.152.148.54`
- **IPv4 (defanged):** `216.152.151.204`
- **IPv4 (defanged):** `104.243.35.63`
- **IPv4 (defanged):** `5.180.41.35`
- **SHA256:** `55a1eb4c2d3da04376df39d7ba832569c6af1a37a0cf2b95f754ac898023a30c`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1505.003** — Server Software Component: Web Shell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1083** — File and Directory Discovery
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Clop hex-named JSP webshell dropped under PTC Windchill /login (CVE-2026-12569)

`UC_22_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.jsp" (Filesystem.file_path="*\\Windchill\\login\\*" OR Filesystem.file_path="*/Windchill/login/*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.action Filesystem.process_guid
| `drop_dm_object_name(Filesystem)`
| rex field=file_name "^(?<shell>[0-9a-f]{16}\.jsp|dpr_[0-9a-f]{8}\.jsp)$"
| where isnotnull(shell)
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| table firstTime lastTime dest file_path file_name shell action count
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FileName endswith ".jsp"
        and (FolderPath has @"\Windchill\login\" or FolderPath contains "/Windchill/login/")
        and FileName matches regex @"^(?i)([0-9a-f]{16}|dpr_[0-9a-f]{8})\.jsp$")
     or SHA256 =~ "55a1eb4c2d3da04376df39d7ba832569c6af1a37a0cf2b95f754ac898023a30c"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### POST to hex-named JSP webshell under /Windchill/login/ in web/proxy logs

`UC_22_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method=POST (Web.url="*/Windchill/login/*.jsp") by Web.src Web.dest Web.url Web.http_method Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| rex field=url "/Windchill/login/(?<shell>[0-9a-f]{16}\.jsp|dpr_[0-9a-f]{8}\.jsp)"
| where isnotnull(shell)
| eval known_c2=if(src IN ("216.152.148.54","216.152.151.204","104.243.35.63","5.180.41.35"),"yes","no")
| table firstTime lastTime src dest url shell http_method status http_user_agent known_c2 count
```

### PTC Windchill Java/Tomcat process spawning shell or flst.txt recon

`UC_22_8` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("java.exe","javaw.exe","tomcat9.exe","tomcat10.exe","w3wp.exe")) (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe","hostname.exe","ipconfig.exe","systeminfo.exe","tasklist.exe","cscript.exe","wscript.exe","nltest.exe") OR Processes.process="*flst.txt*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe","tomcat9.exe","tomcat10.exe","w3wp.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe","hostname.exe","ipconfig.exe","systeminfo.exe","tasklist.exe","cscript.exe","wscript.exe","nltest.exe")
     or ProcessCommandLine has "flst.txt"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Outbound connection to known Clop CVE-2026-12569 C2 / exploitation IPs

`UC_22_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("216.152.148.54","216.152.151.204","104.243.35.63","5.180.41.35") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest_ip dest_port app transport count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("216.152.148.54","216.152.151.204","104.243.35.63","5.180.41.35")
| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
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
  - CVE(s): `CVE-2026-12569`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `216.152.148.54`, `216.152.151.204`, `104.243.35.63`, `5.180.41.35`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `55a1eb4c2d3da04376df39d7ba832569c6af1a37a0cf2b95f754ac898023a30c`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 10 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
