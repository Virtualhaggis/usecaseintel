# [CRIT] Trellix Breach – RansomHouse Claims Access to Parts of Source Code

**Source:** Cyber Security News
**Published:** 2026-05-08
**Article:** https://cybersecuritynews.com/trellix-breach/

## Threat Profile

Home Cyber Security News 
Trellix Breach – RansomHouse Claims Access to Parts of Source Code 
By Guru Baran 
May 8, 2026 
Trellix, the global cybersecurity firm formed from the merger of McAfee Enterprise and FireEye, has confirmed unauthorized access to a portion of its source code repository, with the RansomHouse ransomware group formally claiming responsibility for the attack.
Trellix reported a data breach involving unauthorized access to a portion of its source code repository, which was di…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Unix Shell
- **T1082** — System Information Discovery
- **T1562.004** — Disable or Modify System Firewall
- **T1489** — Service Stop
- **T1490** — Inhibit System Recovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] RansomHouse MrAgent ESXi reconnaissance — esxcli formatter=csv + uname + firewall disable

`UC_10_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process="*esxcli*--formatter=csv*network*nic*list*" OR Processes.process="*esxcli*network firewall set*--enabled*false*" OR Processes.process="*esxcli*network firewall unload*" OR Processes.process="uname -a" OR Processes.process="*/etc/init.d/firewall*stop*") by Processes.dest Processes.user Processes.process _time span=10m | `drop_dm_object_name(Processes)` | stats dc(process) as UniqueCmds values(process) as Commands min(_time) as firstTime by dest user _time | where UniqueCmds >= 2 | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
// MrAgent ESXi staging — esxcli + uname + firewall disable observed within 10m on same host
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where (ProcessCommandLine has "esxcli" and ProcessCommandLine has "--formatter=csv" and ProcessCommandLine has "network nic list")
     or (ProcessCommandLine has "esxcli" and ProcessCommandLine has "network firewall" and ProcessCommandLine has "--enabled" and ProcessCommandLine has "false")
     or (ProcessCommandLine has "esxcli" and ProcessCommandLine has "network firewall unload")
     or (ProcessCommandLine matches regex @"(?i)\buname\s+-a\b")
| extend Bucket = bin(Timestamp, 10m)
| summarize UniqueCmds = dcount(ProcessCommandLine), Commands = make_set(ProcessCommandLine, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DeviceName, AccountName, Bucket
| where UniqueCmds >= 2
| order by FirstSeen desc
```

### [LLM] Mario ESXi mass VM shutdown — burst of esxcli/vim-cmd power-off prior to encryption

`UC_10_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process="*esxcli vm process kill*" OR Processes.process="*vim-cmd vmsvc/power.off*" OR Processes.process="*vim-cmd vmsvc/power.shutdown*") by Processes.dest Processes.user Processes.process _time span=5m | `drop_dm_object_name(Processes)` | stats count as KillEvents dc(process) as DistinctInvocations values(process) as SampleCmds min(_time) as firstTime max(_time) as lastTime by dest user _time | where KillEvents >= 5 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Mass VM kill on ESXi — encryption staging by Mario / MrAgent
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (ProcessCommandLine has "esxcli" and ProcessCommandLine has "vm" and ProcessCommandLine has "process" and ProcessCommandLine has "kill")
     or (ProcessCommandLine has "vim-cmd" and ProcessCommandLine has "vmsvc/power.off")
     or (ProcessCommandLine has "vim-cmd" and ProcessCommandLine has "vmsvc/power.shutdown")
| extend Bucket = bin(Timestamp, 5m)
| summarize KillEvents = count(), DistinctCmds = dcount(ProcessCommandLine), SampleCmds = make_set(ProcessCommandLine, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DeviceName, AccountName, Bucket
| where KillEvents >= 5
| order by KillEvents desc
```

### [LLM] Known RansomHouse Mario ESXi & MrAgent Windows SHA256 IOC sweep

`UC_10_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.process) as cmdline values(Processes.process_name) as process_name from datamodel=Endpoint.Processes where Processes.process_hash IN ("8189c708706eb7302d7598aeee8cd6bdb048bf1a6dbe29c59e50f0a39fd53973","bfc9b956818efe008c2dbf621244b6dc3de8319e89b9fa83c9e412ce70f82f2c") by Processes.dest Processes.process_hash | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("8189c708706eb7302d7598aeee8cd6bdb048bf1a6dbe29c59e50f0a39fd53973","bfc9b956818efe008c2dbf621244b6dc3de8319e89b9fa83c9e412ce70f82f2c") by Filesystem.dest Filesystem.file_hash | `drop_dm_object_name(Filesystem)`] | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let MarioHashes = dynamic([
  "8189c708706eb7302d7598aeee8cd6bdb048bf1a6dbe29c59e50f0a39fd53973",  // Mario ESXi encryptor
  "bfc9b956818efe008c2dbf621244b6dc3de8319e89b9fa83c9e412ce70f82f2c"   // MrAgent / RansomHouse Windows binary
]);
union isfuzzy=true
  ( DeviceProcessEvents
      | where Timestamp > ago(30d)
      | where SHA256 in (MarioHashes)
      | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, Source = "DeviceProcessEvents" ),
  ( DeviceFileEvents
      | where Timestamp > ago(30d)
      | where SHA256 in (MarioHashes)
      | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, FileName, FolderPath, SHA256, ProcessCommandLine = InitiatingProcessCommandLine, Source = "DeviceFileEvents" ),
  ( DeviceImageLoadEvents
      | where Timestamp > ago(30d)
      | where SHA256 in (MarioHashes)
      | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, FileName, FolderPath, SHA256, ProcessCommandLine = InitiatingProcessCommandLine, Source = "DeviceImageLoadEvents" ),
  ( AlertEvidence
      | where Timestamp > ago(30d)
      | where SHA256 in (MarioHashes)
      | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, Source = "AlertEvidence" )
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

### Article-specific behavioural hunt — Trellix Breach – RansomHouse Claims Access to Parts of Source Code

`UC_10_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Trellix Breach – RansomHouse Claims Access to Parts of Source Code ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Trellix Breach – RansomHouse Claims Access to Parts of Source Code
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 8 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
