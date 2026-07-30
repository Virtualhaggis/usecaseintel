# [CRIT] Toy Ghouls’ new toy: the GenieLocker ransomware

**Source:** Securelist (Kaspersky)
**Published:** 2026-07-30
**Article:** https://securelist.com/genielocker-ransomware-for-windows-linux-and-esxi/120843/

## Threat Profile

Table of Contents
Introduction 
Technical details 
Modus operandi 
Initial Access 
Discovery and Credential Access 
Lateral Movement and Command and Control 
Impact 
Encryption Trojan for Windows 
Arguments and launch 
Anti-debugging 
Preparing for encryption 
File encryption and cryptography 
Encryption Trojan for ESXi and Linux 
ESXi and Linux features 
File encryption 
Victims 
Conclusions 
Indicators of compromise 
GenieLocker for Windows 
GenieLocker for Linux and ESXi 
C2 
Authors
Fedor Si…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `89.125.66.101`
- **MD5:** `5d62c1349b8981c396c9a23f4f8f053c`
- **MD5:** `9201e35e2993612612919a3c71302cab`
- **MD5:** `A50EAAF514F4F84E61CA2455A8789753`
- **MD5:** `F08F476F26B01D142CA73923DE65FC0C`
- **MD5:** `FD46A80C2F45577263328984EDF7F4DC`
- **MD5:** `DE3CFBB50F66079BFEE20A6F64E59433`
- **MD5:** `780C8F4C6F077DA4DA96582987920362`
- **MD5:** `D87D0B01D95ACC936B7DC47B8F41937A`
- **MD5:** `34A7F28E0BB69B0D49BACC88BDF20AC1`
- **MD5:** `A8842616C9057D5CF6E1FE1FA8C3C160`
- **MD5:** `34B8828635F88078735799A3C1AC8E28`
- **MD5:** `D3E06EB34D8EEE7EF92CAC3AD0A20FF5`
- **MD5:** `C68B6862725777651085650DB34947FC`
- **MD5:** `9CD514FF2809CE0B993E3B8649E82A94`
- **MD5:** `824CA1E906CC073EE5B0F3519DF69A8F`
- **MD5:** `25480DAD40152EF3D0C6D38EECC9BD9B`
- **MD5:** `7DAD78584795AA5C160520CC6ACCF260`
- **MD5:** `18F61C6D686CFFD131C9FD3F3437064B`
- **MD5:** `9969A8221312DBA70DD5CBDDF83A146C`
- **MD5:** `F7B9E36E94163A9A303160945F99267A`
- **MD5:** `B893EAFED0659F70D4AC250F09073723`
- **MD5:** `D661CF666B9ACBAB7CFEAE1127A261A9`
- **MD5:** `3A4479B51890373BFC4A011EF41FE376`
- **MD5:** `58C0DDA52B8F069660166D61FD74F911`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1486** — Data Encrypted for Impact
- **T1219** — Remote Access Software
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — Toy Ghouls’ new toy: the GenieLocker ransomware

`UC_5_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Toy Ghouls’ new toy: the GenieLocker ransomware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("socks5.exe","config.msi","kftd.exe","genie_encrypt.exe","run.exe","run2.exe","genie.exe","consultant.exe","tempo.exe","kernel.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/vmware/welcome*" OR Filesystem.file_name IN ("socks5.exe","config.msi","kftd.exe","genie_encrypt.exe","run.exe","run2.exe","genie.exe","consultant.exe","tempo.exe","kernel.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Toy Ghouls’ new toy: the GenieLocker ransomware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("socks5.exe", "config.msi", "kftd.exe", "genie_encrypt.exe", "run.exe", "run2.exe", "genie.exe", "consultant.exe", "tempo.exe", "kernel.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/vmware/welcome") or FileName in~ ("socks5.exe", "config.msi", "kftd.exe", "genie_encrypt.exe", "run.exe", "run2.exe", "genie.exe", "consultant.exe", "tempo.exe", "kernel.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `89.125.66.101`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `5d62c1349b8981c396c9a23f4f8f053c`, `9201e35e2993612612919a3c71302cab`, `A50EAAF514F4F84E61CA2455A8789753`, `F08F476F26B01D142CA73923DE65FC0C`, `FD46A80C2F45577263328984EDF7F4DC`, `DE3CFBB50F66079BFEE20A6F64E59433`, `780C8F4C6F077DA4DA96582987920362`, `D87D0B01D95ACC936B7DC47B8F41937A` _(+16 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
