# [CRIT] Over 24,000 exposed server BMCs leak password hash via decades-old flaw

**Source:** BleepingComputer
**Published:** 2026-07-28
**Article:** https://www.bleepingcomputer.com/news/security/over-24-000-exposed-server-bmcs-leak-password-hash-via-decades-old-flaw/

## Threat Profile

Over 24,000 exposed server BMCs leak password hash via decades-old flaw 
By Bill Toulas 
July 28, 2026
08:10 AM
0 


More than 24,000 internet-exposed servers are leaking authentication password hashes due to a 20-year-old vulnerability in their Baseboard Management Controller (BMC) interface.


For at least a third of them, researchers were able to find the correct password using dictionaries and the patterns on factory stickers for default credentials.


The exposed servers are vulnerabl…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2013-4786`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1046** — Network Service Discovery
- **T1595.001** — Active Scanning: Scanning IP Blocks
- **T1212** — Exploitation for Credential Access
- **T1110.002** — Brute Force: Password Cracking
- **T1210** — Exploitation of Remote Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Internet-exposed IPMI/BMC management plane on UDP 623 (CVE-2013-4786 exposure)

`UC_0_4` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=623 All_Traffic.transport=udp by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dvc
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where LocalPort == 623
| where RemoteIPType == "Public"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Attempts=count(), Sources=dcount(RemoteIP), SampleSources=make_set(RemoteIP, 25) by DeviceName, LocalIP, LocalPort
| order by Attempts desc
```

### External IPMI RAKP hash-harvest sweep across many BMCs (UDP 623 fan-out)

`UC_0_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(All_Traffic.dest_ip) as bmc_count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=623 All_Traffic.transport=udp by All_Traffic.src_ip _time span=1h
| `drop_dm_object_name(All_Traffic)`
| where bmc_count >= 20
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - bmc_count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where LocalPort == 623
| where RemoteIPType == "Public"
| summarize BMCsHit=dcount(DeviceName), Attempts=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Targets=make_set(DeviceName, 50) by RemoteIP
| where BMCsHit >= 5   // 5 monitored shared-LAN BMCs from one external IP = sweep, not a single admin
| order by BMCsHit desc
```

### Internal host sweeping management plane on UDP 623 (compromised BMC pivot)

`UC_0_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(All_Traffic.dest_ip) as bmc_count values(All_Traffic.app) as app min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=623 All_Traffic.transport=udp (All_Traffic.src_category=internal OR All_Traffic.dest_category=internal) by All_Traffic.src_ip _time span=1h
| `drop_dm_object_name(All_Traffic)`
| where bmc_count >= 10
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - bmc_count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 623
| where RemoteIPType == "Private"
| where InitiatingProcessAccountName !endswith "$"
| summarize BMCsTargeted=dcount(RemoteIP), Attempts=count(), Targets=make_set(RemoteIP, 50), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| where BMCsTargeted >= 10   // one host hitting 10+ internal BMCs on IPMI = management-plane sweep
| order by BMCsTargeted desc
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
  - CVE(s): `CVE-2013-4786`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
