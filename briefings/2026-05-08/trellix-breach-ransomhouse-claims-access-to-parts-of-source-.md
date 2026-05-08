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
Trellix reported a data breach involving unauthorized access to a portion of its source code repository, whic…

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
- **T1562.004** — Impair Defenses: Disable or Modify System Firewall
- **T1082** — System Information Discovery
- **T1016** — System Network Configuration Discovery
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] RansomHouse MrAgent ESXi firewall disable + esxcli reconnaissance chain

`UC_0_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd from datamodel=Endpoint.Processes where Processes.process_name="esxcli" (Processes.process="*network firewall set*--enabled*false*" OR Processes.process="*network nic list*" OR Processes.process="*ip interface ipv4 get*") by Processes.dest Processes.user Processes.process _time span=1s | `drop_dm_object_name(Processes)` | eval evt=case(match(cmd,"firewall set.*--enabled\s+false"),"fw_off", match(cmd,"network nic list"),"recon_nic", match(cmd,"ip interface ipv4 get"),"recon_ip") | stats min(_time) as firstSeen max(_time) as lastSeen values(evt) as evts values(cmd) as cmds by dest user | where mvcount(evts)>=2 AND mvfind(evts,"fw_off")>=0 AND (lastSeen-firstSeen)<=600
```

**Defender KQL:**
```kql
// MrAgent ESXi initialisation: esxcli recon + firewall disable within 10 min on the same host
let _win = 10m;
let _fw = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "esxcli" or InitiatingProcessFileName =~ "esxcli" or ProcessCommandLine has "esxcli"
    | where ProcessCommandLine has "network firewall set" and ProcessCommandLine has "--enabled" and ProcessCommandLine has "false"
    | project FwTime = Timestamp, DeviceId, DeviceName, FwAccount = AccountName, FwCmd = ProcessCommandLine;
let _recon = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "esxcli" or InitiatingProcessFileName =~ "esxcli" or ProcessCommandLine has "esxcli"
    | where ProcessCommandLine has_any ("network nic list", "ip interface ipv4 get")
    | where ProcessCommandLine has "--formatter" and ProcessCommandLine has "csv"
    | project ReconTime = Timestamp, DeviceId, ReconCmd = ProcessCommandLine;
_fw
| join kind=inner _recon on DeviceId
| where ReconTime between (FwTime - _win .. FwTime + _win)
| project DeviceName, FwAccount, FwTime, FwCmd, ReconTime, ReconCmd,
          DeltaSec = datetime_diff('second', FwTime, ReconTime)
| order by FwTime desc
```

### [LLM] RansomHouse MrAgent binary launched with C2 IP:port argument list

`UC_0_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="mragent" OR Processes.process="*/mragent *" OR Processes.process="./mragent *") Processes.process="*.*.*.*:*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | rex field=process "(?<c2_endpoints>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})(,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})*)" | where isnotnull(c2_endpoints)
```

**Defender KQL:**
```kql
// MrAgent binary executed with embedded IP:port C2 endpoints
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName =~ "mragent"
   or InitiatingProcessFileName =~ "mragent"
   or FolderPath has "mragent"
   or ProcessCommandLine has "mragent"
| where ProcessCommandLine matches regex @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b"
| extend C2 = extract_all(@"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})", ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, C2,
          ParentImage = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          SHA256
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

`UC_0_4` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 7 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
