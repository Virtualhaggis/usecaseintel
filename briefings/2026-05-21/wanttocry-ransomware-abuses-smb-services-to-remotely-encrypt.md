# [HIGH] WantToCry Ransomware Abuses SMB Services to Remotely Encrypt Files

**Source:** Cyber Security News
**Published:** 2026-05-21
**Article:** https://cybersecuritynews.com/wanttocry-ransomware-abuses-smb-services/

## Threat Profile

Home Cyber Security News 
WantToCry Ransomware Abuses SMB Services to Remotely Encrypt Files 
By Tushar Subhra Dutta 
May 21, 2026 
A ransomware strain called WantToCry has been targeting businesses by abusing a widely used file-sharing protocol to encrypt files without dropping any malware on the victim’s system. 
The attacks mark a notable shift in how ransomware operators approach campaigns, serving as a warning to any organization that still has file-sharing services exposed to the open inte…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `87.225.105.217`
- **IPv4 (defanged):** `109.69.58.213`
- **IPv4 (defanged):** `185.189.13.56`
- **IPv4 (defanged):** `185.200.191.37`
- **IPv4 (defanged):** `194.36.179.18`
- **IPv4 (defanged):** `194.36.179.30`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1110.001** — Password Guessing
- **T1133** — External Remote Services
- **T1485** — Data Destruction
- **T1565.001** — Stored Data Manipulation
- **T1071.002** — File Transfer Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1572** — Protocol Tunneling

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SMB brute-force followed by successful external network logon (WantToCry initial access)

`UC_10_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as failedCount, min(_time) as failFirst, max(_time) as failLast from datamodel=Authentication where Authentication.action=failure AND Authentication.dest_port IN (139,445) AND NOT (Authentication.src IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")) by Authentication.dest, Authentication.src, Authentication.user | `drop_dm_object_name(Authentication)` | where failedCount >= 10 | join type=inner dest src user [ | tstats `summariesonly` min(_time) as successFirst from datamodel=Authentication where Authentication.action=success AND Authentication.dest_port IN (139,445) AND NOT (Authentication.src IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")) by Authentication.dest, Authentication.src, Authentication.user | `drop_dm_object_name(Authentication)` ] | where successFirst >= failFirst AND successFirst <= (failLast + 1800) | eval known_wanttocry_ip=if(src IN ("87.225.105.217","109.69.58.213","185.189.13.56","185.200.191.37","194.36.179.18","194.36.179.30"),"yes","no") | table failFirst, failLast, successFirst, src, dest, user, failedCount, known_wanttocry_ip | sort - successFirst
```

**Defender KQL:**
```kql
let SuspiciousIPs = dynamic(["87.225.105.217","109.69.58.213","185.189.13.56","185.200.191.37","194.36.179.18","194.36.179.30"]);
let AttackerHosts = dynamic(["WIN-J9D866ESJ2","WIN-LVFRVQFMKO"]);
let FailThreshold = 10;
let Window = 30m;
let Failures = DeviceLogonEvents
    | where Timestamp > ago(7d)
    | where ActionType == "LogonFailed"
    | where LogonType == "Network"
    | where RemoteIPType == "Public"
    | where AccountName !endswith "$"
    | summarize FailedCount = count(), FailFirst = min(Timestamp), FailLast = max(Timestamp)
              by DeviceName, RemoteIP, AccountName
    | where FailedCount >= FailThreshold;
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where LogonType == "Network"
| where RemoteIPType == "Public"
| join kind=inner Failures on DeviceName, RemoteIP, AccountName
| where Timestamp between (FailFirst .. FailLast + Window)
| extend KnownWantToCryIP = iff(RemoteIP in (SuspiciousIPs), "yes", "no")
| extend KnownAttackerHost = iff(RemoteDeviceName in~ (AttackerHosts), "yes", "no")
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteDeviceName,
          FailedCount, FailFirst, FailLast, KnownWantToCryIP, KnownAttackerHost
| order by Timestamp desc
```

### [LLM] WantToCry ransom note !Want_To_Cry.txt dropped via SMB share

`UC_10_7` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstSeen, values(Filesystem.file_path) as paths, values(Filesystem.process_name) as proc, values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","renamed","modified") AND (Filesystem.file_name="!Want_To_Cry.txt" OR Filesystem.file_name="!want_to_cry.txt") by Filesystem.dest, Filesystem.file_name | `drop_dm_object_name(Filesystem)` | table firstSeen, dest, file_name, paths, proc, user, count | sort - firstSeen
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName =~ "!Want_To_Cry.txt"
| extend RemoteSMBSource = iff(isnotempty(RequestSourceIP) or isnotempty(ShareName), "yes", "no")
| project Timestamp, DeviceName, FolderPath, FileName, FileSize,
          InitiatingProcessFileName, InitiatingProcessAccountName,
          RequestProtocol, RequestSourceIP, RequestSourcePort,
          RequestAccountName, RequestAccountDomain, ShareName,
          RemoteSMBSource
| order by Timestamp desc
```

### [LLM] Mass file rewrite to .want_to_cry extension over SMB session (WantToCry remote encryption)

`UC_10_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as writeCount, dc(Filesystem.file_path) as uniquePaths, min(_time) as firstSeen, max(_time) as lastSeen, values(Filesystem.user) as users, values(Filesystem.process_name) as processes from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","renamed","modified") AND Filesystem.file_name="*.want_to_cry" by Filesystem.dest, _time span=15m | `drop_dm_object_name(Filesystem)` | where writeCount >= 5 | sort - firstSeen
```

**Defender KQL:**
```kql
let KnownC2 = dynamic(["87.225.105.217","109.69.58.213","185.189.13.56","185.200.191.37","194.36.179.18","194.36.179.30"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName endswith ".want_to_cry" or PreviousFileName endswith ".want_to_cry"
| extend SMBSourced = iff(isnotempty(RequestSourceIP) or isnotempty(ShareName) or InitiatingProcessFileName =~ "System", 1, 0)
| extend KnownC2Hit = iff(RequestSourceIP in (KnownC2), 1, 0)
| summarize WriteCount = count(),
            UniquePaths = dcount(FolderPath),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            Shares = make_set(ShareName, 20),
            SourceIPs = make_set(RequestSourceIP, 20),
            RequestAccounts = make_set(RequestAccountName, 20),
            SMBSourcedHits = sum(SMBSourced),
            KnownC2Hits = sum(KnownC2Hit)
            by DeviceName, bin(Timestamp, 15m)
| where WriteCount >= 5
| order by FirstSeen desc
```

### [LLM] Network communication with WantToCry encryption-infrastructure IPs

`UC_10_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, sum(All_Traffic.bytes_in) as bytesIn, sum(All_Traffic.bytes_out) as bytesOut, min(_time) as firstSeen, max(_time) as lastSeen, values(All_Traffic.dest_port) as dports, values(All_Traffic.app) as apps from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("87.225.105.217","109.69.58.213","185.189.13.56","185.200.191.37","194.36.179.18","194.36.179.30") OR All_Traffic.src IN ("87.225.105.217","109.69.58.213","185.189.13.56","185.200.191.37","194.36.179.18","194.36.179.30")) by All_Traffic.src, All_Traffic.dest, All_Traffic.action | `drop_dm_object_name(All_Traffic)` | sort - firstSeen
```

**Defender KQL:**
```kql
let WantToCryIPs = dynamic(["87.225.105.217","109.69.58.213","185.189.13.56","185.200.191.37","194.36.179.18","194.36.179.30"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (WantToCryIPs)
| extend Direction = case(ActionType has "Inbound", "inbound", ActionType has "Connect", "outbound", "unknown")
| project Timestamp, DeviceName, ActionType, Direction, RemoteIP, RemotePort, Protocol,
          LocalIP, LocalPort, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `87.225.105.217`, `109.69.58.213`, `185.189.13.56`, `185.200.191.37`, `194.36.179.18`, `194.36.179.30`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
