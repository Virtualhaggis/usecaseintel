# [CRIT] First VPN Dismantled in Global Takedown Over Use by 25 Ransomware Groups

**Source:** The Hacker News
**Published:** 2026-05-22
**Article:** https://thehackernews.com/2026/05/first-vpn-dismantled-in-global-takedown.html

## Threat Profile

First VPN Dismantled in Global Takedown Over Use by 25 Ransomware Groups 
 Ravie Lakshmanan  May 22, 2026 Cybercrime / Infrastructure 
Authorities in Europe and North America have announced the dismantling of a criminal virtual private network (VPN) service used by criminal actors to obscure the origins of ransomware attacks, data theft, scanning, and denial-of-service attacks.
The disruption of First VPN Service was led by France and the Netherlands, with several other nations supporting the …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `2.223.66.103`
- **IPv4 (defanged):** `5.181.234.59`
- **IPv4 (defanged):** `92.38.148.58`
- **Domain (defanged):** `1vpns.com`
- **Domain (defanged):** `1vpns.net`
- **Domain (defanged):** `1vpns.org`
- **Domain (defanged):** `exploit.in`
- **Domain (defanged):** `xss.is`

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1572** — Protocol Tunneling
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1593.002** — Search Open Websites/Domains: Search Engines
- **T1588.002** — Obtain Capabilities: Tool

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Outbound connections to seized First VPN exit node IPs

`UC_128_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest in ("2.223.66.103","5.181.234.59","92.38.148.58") by All_Traffic.src, All_Traffic.user, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app, All_Traffic.transport | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - count
```

**Defender KQL:**
```kql
let exitNodes = dynamic(["2.223.66.103","5.181.234.59","92.38.148.58"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (exitNodes)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, Protocol, RemoteUrl
| order by Timestamp desc
```

### [LLM] Endpoint resolution or web traffic to seized 1vpns[.]com/net/org domains

`UC_128_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("1vpns.com","1vpns.net","1vpns.org","*.1vpns.com","*.1vpns.net","*.1vpns.org") by DNS.src, DNS.query, DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | sort - count
```

**Defender KQL:**
```kql
let domains = dynamic(["1vpns.com","1vpns.net","1vpns.org"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (domains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### [LLM] Endpoint visits to Russian-speaking cybercrime forums Exploit.in / XSS.is

`UC_128_6` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url IN ("*exploit.in*","*xss.is*") OR Web.dest IN ("exploit.in","xss.is","*.exploit.in","*.xss.is") by Web.src, Web.user, Web.url, Web.dest, Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - count
| append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("exploit.in","xss.is","*.exploit.in","*.xss.is") by DNS.src, DNS.query | `drop_dm_object_name(DNS)`]
```

**Defender KQL:**
```kql
let forums = dynamic(["exploit.in","xss.is"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (forums)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `2.223.66.103`, `5.181.234.59`, `92.38.148.58`, `1vpns.com`, `1vpns.net`, `1vpns.org`, `exploit.in`, `xss.is`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 7 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
