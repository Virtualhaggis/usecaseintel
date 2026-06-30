# [HIGH] Nissan discloses employee data breach linked to Oracle zero-day attacks

**Source:** BleepingComputer
**Published:** 2026-06-29
**Article:** https://www.bleepingcomputer.com/news/security/nissan-discloses-employee-data-breach-linked-to-oracle-zero-day-attacks/

## Threat Profile

Nissan discloses employee data breach linked to Oracle zero-day attacks 
By Lawrence Abrams 
June 29, 2026
04:40 PM
0 
Nissan is warning that it suffered a data breach affecting current and former employees after threat actors exploited an Oracle PeopleSoft vulnerability in data theft attacks previously linked to the ShinyHunters extortion group.
In breach notifications filed with the California Attorney General's Office, Oracle says these data theft attacks impacted hundreds of companies and th…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-35273`
- **IPv4 (defanged):** `142.11.200.186`
- **IPv4 (defanged):** `142.11.200.187`
- **IPv4 (defanged):** `142.11.200.188`
- **IPv4 (defanged):** `142.11.200.189`
- **IPv4 (defanged):** `142.11.200.190`
- **IPv4 (defanged):** `176.120.22.24`
- **Domain (defanged):** `azurenetfiles.net`
- **SHA256:** `f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc`
- **SHA256:** `d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f`
- **SHA256:** `c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f`
- **SHA256:** `68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309`
- **SHA256:** `2ab684d93c1553fad87041b4dea97188a97e78589deee2a7bacff905564f3a35`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1505.003** — Server Software Component: Web Shell
- **T1059** — Command and Scripting Interpreter
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1219** — Remote Access Software
- **T1568** — Dynamic Resolution
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1567** — Exfiltration Over Web Service
- **T1213** — Data from Information Repositories
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Internet-facing Oracle PeopleSoft exposed/exploited via CVE-2026-35273 PSEMHUB SSRF (ShinyHunters)

`UC_0_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url="*/PSEMHUB*" OR Web.url="*/PSIGW*" by Web.src Web.dest Web.http_method Web.url Web.status Web.http_user_agent | `drop_dm_object_name(Web)` | where status!=404 AND status!=403 | sort - lastTime
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2026-35273"
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago(1d)
    | summarize arg_max(Timestamp, IsInternetFacing, PublicIP) by DeviceId
  ) on DeviceId
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, IsInternetFacing, PublicIP, RecommendedSecurityUpdate
| order by IsInternetFacing desc
```

### Oracle PeopleSoft Java/app-server process spawning shell or recon binary (CVE-2026-35273 post-exploit)

`UC_0_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("java.exe","psae.exe","PSEMAgent.exe","psadmin.exe")) AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","cscript.exe","wscript.exe","node.exe","whoami.exe","net.exe","nltest.exe","certutil.exe","bitsadmin.exe","curl.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where NOT user="*$" | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("java.exe","psae.exe","PSEMAgent.exe","psadmin.exe")
   or InitiatingProcessFolderPath has_any (@"\PeopleSoft\", @"\pt8.6", @"\PT8.6")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","cscript.exe","wscript.exe","node.exe","mshta.exe","rundll32.exe","whoami.exe","net.exe","net1.exe","nltest.exe","certutil.exe","bitsadmin.exe","curl.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### PeopleSoft host beaconing to ShinyHunters MeshCentral C2 (azurenetfiles.net / 142.11.200.184-29 / 176.120.22.24)

`UC_0_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="176.120.22.24" OR All_Traffic.dest_ip="142.11.200.184/29") OR All_Traffic.dest="*azurenetfiles.net*" by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "azurenetfiles.net"
    or ipv4_is_in_range(RemoteIP, "142.11.200.184/29")
    or RemoteIP == "176.120.22.24"
| extend MeshCentralC2 = (RemoteUrl has "agent.ashx" and RemoteUrl has "azurenetfiles.net")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, MeshCentralC2, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### zstd data-staging archives written on PeopleSoft host (ShinyHunters exfil prep)

`UC_0_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem where (Filesystem.file_name="*.zst" OR Filesystem.file_name="*.tar.zst") by Filesystem.dest Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".zst" or FileName endswith ".tar.zst"
| where InitiatingProcessFileName has_any ("zstd.exe","zstd","node.exe","java.exe","psae.exe","powershell.exe","pwsh.exe","cmd.exe","bash","sh","python.exe","python3")
| project Timestamp, DeviceName, FileName, FolderPath, FileSize, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by FileSize desc
```

### Known ShinyHunters PeopleSoft payload/staging file hashes on disk (CVE-2026-35273)

`UC_0_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_name) as process_name from datamodel=Endpoint.Processes where Processes.process_hash IN ("f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc","d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f","c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f","68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309","2ab684d93c1553fad87041b4dea97188a97e78589deee2a7bacff905564f3a35") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
let badHashes = dynamic(["f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc","d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f","c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f","68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309","2ab684d93c1553fad87041b4dea97188a97e78589deee2a7bacff905564f3a35"]);
union
(DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 in (badHashes) | project Timestamp, DeviceName, Source="FileWrite", FileName, FolderPath, SHA256, Actor=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine),
(DeviceProcessEvents | where Timestamp > ago(30d) | where SHA256 in (badHashes) | project Timestamp, DeviceName, Source="ProcessExec", FileName, FolderPath, SHA256, Actor=InitiatingProcessFileName, Cmd=ProcessCommandLine)
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-35273`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `142.11.200.186`, `142.11.200.187`, `142.11.200.188`, `142.11.200.189`, `142.11.200.190`, `176.120.22.24`, `azurenetfiles.net`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc`, `d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f`, `c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f`, `68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309`, `2ab684d93c1553fad87041b4dea97188a97e78589deee2a7bacff905564f3a35`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 8 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
