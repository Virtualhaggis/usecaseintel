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
- **MD5:** `a50eaaf514f4f84e61ca2455a8789753`
- **MD5:** `f08f476f26b01d142ca73923de65fc0c`
- **MD5:** `fd46a80c2f45577263328984edf7f4dc`
- **MD5:** `de3cfbb50f66079bfee20a6f64e59433`
- **MD5:** `780c8f4c6f077da4da96582987920362`
- **MD5:** `d87d0b01d95acc936b7dc47b8f41937a`
- **MD5:** `34a7f28e0bb69b0d49bacc88bdf20ac1`
- **MD5:** `5d62c1349b8981c396c9a23f4f8f053c`
- **MD5:** `a8842616c9057d5cf6e1fe1fa8c3c160`
- **MD5:** `34b8828635f88078735799a3c1ac8e28`
- **MD5:** `d3e06eb34d8eee7ef92cac3ad0a20ff5`
- **MD5:** `c68b6862725777651085650db34947fc`
- **MD5:** `9cd514ff2809ce0b993e3b8649e82a94`
- **MD5:** `824ca1e906cc073ee5b0f3519df69a8f`
- **MD5:** `25480dad40152ef3d0c6d38eecc9bd9b`
- **MD5:** `7dad78584795aa5c160520cc6accf260`
- **MD5:** `18f61c6d686cffd131c9fd3f3437064b`
- **MD5:** `9969a8221312dba70dd5cbddf83a146c`
- **MD5:** `f7b9e36e94163a9a303160945f99267a`
- **MD5:** `b893eafed0659f70d4ac250f09073723`
- **MD5:** `d661cf666b9acbab7cfeae1127a261a9`
- **MD5:** `3a4479b51890373bfc4a011ef41fe376`
- **MD5:** `58c0dda52b8f069660166d61fd74f911`
- **MD5:** `9201e35e2993612612919a3c71302cab`

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
- **T1480.001** — Execution Guardrails: Environmental Keying
- **T1078** — Valid Accounts
- **T1199** — Trusted Relationship
- **T1046** — Network Service Discovery
- **T1018** — Remote System Discovery
- **T1003.001** — OS Credential Dumping: LSASS Memory
- **T1555.005** — Credentials from Password Stores: Password Managers
- **T1555** — Credentials from Password Stores
- **T1572** — Protocol Tunneling
- **T1090** — Proxy
- **T1021.004** — Remote Services: SSH
- **T1490** — Inhibit System Recovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GenieLocker Windows ransomware execution via secret-argument hex + --percent/--recursive flags

`UC_107_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_hash="5d62c1349b8981c396c9a23f4f8f053c" OR (Processes.process="*--percent*" AND Processes.process="*--recursive*") OR (Processes.process="*--percent*" AND Processes.process="*--log*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | where user!="*$" | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where MD5 == "5d62c1349b8981c396c9a23f4f8f053c"
   or (ProcessCommandLine has "--percent" and ProcessCommandLine has "--recursive")
   or (ProcessCommandLine has "--percent" and ProcessCommandLine has "--log")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, MD5, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### External-partner VPN logon with valid credentials (trusted-relationship abuse)

`UC_107_9` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication.Authentication where Authentication.action="success" (Authentication.authentication_method="NTLM" OR Authentication.authentication_method="Kerberos" OR nodename=Authentication) by Authentication.src Authentication.user Authentication.dest Authentication.app | `drop_dm_object_name(Authentication)` | where user!="*$" AND NOT (cidrmatch("10.0.0.0/8",src) OR cidrmatch("172.16.0.0/12",src) OR cidrmatch("192.168.0.0/16",src)) | iplocation src | sort - lastTime
```

**Defender KQL:**
```kql
DeviceLogonEvents
| where Timestamp > ago(30d)
| where ActionType == "LogonSuccess"
| where LogonType in ("Network","RemoteInteractive")
| where RemoteIPType == "Public"
| where AccountName !endswith "$"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hosts=make_set(DeviceName,20), Count=count() by AccountName, RemoteIP, LogonType
| order by FirstSeen desc
```

### SoftPerfect Network Scanner (netscan.exe) execution for internal discovery

`UC_107_10` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="netscan.exe" OR Processes.original_file_name="netscan.exe") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | where user!="*$" | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "netscan.exe"
   or ProcessVersionInfoOriginalFileName =~ "netscan.exe"
   or ProcessVersionInfoProductName has "Network Scanner"
   or ProcessVersionInfoCompanyName has "SoftPerfect"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName
| order by Timestamp desc
```

### Mimikatz credential dumping via command-line/module signature

`UC_107_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*sekurlsa::*" OR Processes.process="*lsadump::*" OR Processes.process="*privilege::debug*" OR Processes.process="*kerberos::*" OR Processes.process="*mimikatz*" OR Processes.process_name="mimikatz.exe" OR Processes.original_file_name="mimikatz.exe") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | where user!="*$" | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("sekurlsa::","lsadump::","privilege::debug","kerberos::","crypto::","mimikatz")
   or FileName =~ "mimikatz.exe"
   or ProcessVersionInfoOriginalFileName =~ "mimikatz.exe"
   or ProcessVersionInfoFileDescription has "mimikatz"
   or ProcessVersionInfoCompanyName has "gentilkiwi"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### KeePassXC .kdbx vault access/copy by non-KeePass process

`UC_107_12` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.kdbx" AND Filesystem.action="created" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where NOT process_name IN ("keepassxc.exe","keepass.exe") | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".kdbx"
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where InitiatingProcessFileName !in~ ("keepassxc.exe","keepass.exe","keepassxc-cli.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, PreviousFolderPath, ActionType
| order by Timestamp desc
```

### socks5.exe / anomalous Windows OpenSSH server for pivot tunneling

`UC_107_13` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="socks5.exe" OR Processes.process_name="sshd.exe" OR (Processes.process_name="ssh.exe" AND Processes.process="*-D *")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | where user!="*$" | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "socks5.exe"
   or FileName =~ "sshd.exe"
   or (FileName =~ "ssh.exe" and ProcessCommandLine has "-D")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Reverse SSH tunnel and C2 beacon to GenieLocker C2 89.125.66.101

`UC_107_14` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="89.125.66.101" by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "89.125.66.101"
   or (InitiatingProcessFileName in~ ("ssh.exe","plink.exe") and InitiatingProcessCommandLine has "-R" and RemoteIPType == "Public")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### GenieLocker ELF encryptor on Linux/ESXi via --percent/--recursive flags

`UC_107_15` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.process="*--percent*" AND Processes.process="*--recursive*") OR (Processes.process="*--percent*" AND Processes.process="*--log*")) AND Processes.os="Linux" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (ProcessCommandLine has "--percent" and ProcessCommandLine has "--recursive")
     or (ProcessCommandLine has "--percent" and ProcessCommandLine has "--log")
| where FolderPath startswith "/" or FolderPath has "/tmp/" or FolderPath has "/var/"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
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

`UC_107_7` · phase: **exploit** · confidence: **High**

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
  - file hash IOC(s): `a50eaaf514f4f84e61ca2455a8789753`, `f08f476f26b01d142ca73923de65fc0c`, `fd46a80c2f45577263328984edf7f4dc`, `de3cfbb50f66079bfee20a6f64e59433`, `780c8f4c6f077da4da96582987920362`, `d87d0b01d95acc936b7dc47b8f41937a`, `34a7f28e0bb69b0d49bacc88bdf20ac1`, `5d62c1349b8981c396c9a23f4f8f053c` _(+16 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 16 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
