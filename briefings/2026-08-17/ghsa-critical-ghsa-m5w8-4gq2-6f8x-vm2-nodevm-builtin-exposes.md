# [CRIT] [GHSA / CRITICAL] GHSA-m5w8-4gq2-6f8x: vm2: NodeVM `builtin: ['*']` exposes `os` and `dns` — process-wide observability reads AND writes that hijack the host (sibling class of GHSA-9g8x-92q2-p28f)

**Source:** GitHub Security Advisories
**Published:** 2026-08-17
**Article:** https://github.com/advisories/GHSA-m5w8-4gq2-6f8x

## Threat Profile

vm2: NodeVM `builtin: ['*']` exposes `os` and `dns` — process-wide observability reads AND writes that hijack the host (sibling class of GHSA-9g8x-92q2-p28f)

# NodeVM `builtin: ['*']` exposes `os` and `dns` — process-wide observability reads AND writes that hijack the host (sibling class of GHSA-9g8x-92q2-p28f)

**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) chained with CWE-732 (Incorrect Permission Assignment for Critical Resource) and CWE-285 (Improper Authoriz…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.004** — Application Layer Protocol: DNS
- **T1557** — Adversary-in-the-Middle

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Node.js process direct DNS egress to external resolver (vm2 dns.setServers host hijack)

`UC_11_2` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=53 (All_Traffic.app IN ("node.exe","node") OR All_Traffic.process_name IN ("node.exe","node")) NOT All_Traffic.dest IN ("8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9","149.112.112.112") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| where NOT cidrmatch("10.0.0.0/8",dest) AND NOT cidrmatch("172.16.0.0/12",dest) AND NOT cidrmatch("192.168.0.0/16",dest)
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where RemotePort == 53
| where RemoteIPType == "Public"
| where RemoteIP !in ("8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9","149.112.112.112")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ConnCount=count() by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP
| order by FirstSeen desc
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

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-m5w8-4gq2-6f8x: vm2: NodeVM `builtin: ['*']` exposes `os`

`UC_11_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-m5w8-4gq2-6f8x: vm2: NodeVM `builtin: ['*']` exposes `os` ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("test-poc.js","dns.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("test-poc.js","dns.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-m5w8-4gq2-6f8x: vm2: NodeVM `builtin: ['*']` exposes `os`
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("test-poc.js", "dns.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("test-poc.js", "dns.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
