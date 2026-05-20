# [CRIT] The Gentlemen Ransomware Attacks Windows, Linux, NAS, BSD, and ESXi Attacks

**Source:** Cyber Security News
**Published:** 2026-05-19
**Article:** https://cybersecuritynews.com/the-gentlemen-ransomware-attacks-windows/

## Threat Profile

Home Cyber Security News 
The Gentlemen Ransomware Attacks Windows, Linux, NAS, BSD, and ESXi Attacks 
By Tushar Subhra Dutta 
May 19, 2026 
A ransomware group called The Gentlemen has been quietly building one of the most aggressive cybercriminal operations seen in recent years. 
Emerging publicly in the second half of 2025, the group rapidly scaled its activity to become one of the top two most active ransomware threats globally by early 2026. 
What makes this group stand out is not just its s…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `91.107.247.163`
- **IPv4 (defanged):** `45.86.230.112`
- **SHA256:** `992c951f4af57ca7cd8396f5ed69c2199fd6fd4ae5e93726da3e198e78bec0a5`
- **SHA256:** `025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a`
- **SHA256:** `22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67`
- **SHA256:** `2ed9494e9b7b68415b4eb151c922c82c0191294d0aa443dd2cb5133e6bfe3d5d`
- **SHA256:** `3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235`
- **SHA256:** `48d9b2ce4fcd6854a3164ce395d7140014e0b58b77680623f3e4ca22d3a6e7fd`
- **SHA256:** `62c2c24937d67fdeb43f2c9690ab10e8bb90713af46945048db9a94a465ffcb8`
- **SHA256:** `860a6177b055a2f5aa61470d17ec3c69da24f1cdf0a782237055cba431158923`
- **SHA256:** `87d25d0e5880b3b5cd30106853cbfc6ef1ad38966b30d9bd5b99df46098e546c`
- **SHA256:** `8c87134c1b45e990e9568f0a3899b0076f94be16d3c40fa824ac1e6c6ee892db`
- **SHA256:** `91415e0b9fe4e7cbe43ec0558a7adf89423de30d22b00b985c2e4b97e75076b1`
- **SHA256:** `994d6d1edb57f945f4284cc0163ec998861c7496d85f6d45c08657c9727186e3`
- **SHA256:** `9f61ff4deb8afced8b1ecdc8787a134c63bde632b18293fbfc94a91749e3e454`
- **SHA256:** `a7a19cab7aab606f833fa8225bc94ec9570a6666660b02cc41a63fe39ea8b0ad`
- **SHA256:** `b67958afc982cafbe1c3f114b444d7f4c91a88a3e7a86f89ab8795ac2110d1e6`
- **SHA256:** `c46b5a18ab3fb5fd1c5c8288a41c75bf0170c10b5e829af89370a12c86dd10f8`
- **SHA256:** `c7f7b5a6e7d93221344e6368c7ab4abf93e162f7567e1a7bcb8786cb8a183a73`
- **SHA256:** `ec368ae0b4369b6ef0da244774995c819c63cffb7fd2132379963b9c1640ccd2`
- **SHA256:** `efaf8e7422ffd09c7f03f1a5b4e5c2cc32b05334c18d1ccb9673667f8f43108f`
- **SHA256:** `f736be55193c77af346dbe905e25f6a1dee3ec1aedca8989ad2088e4f6576b12`
- **SHA256:** `fc75ed2159e0c8274076e46a37671cfb8d677af9f586224da1713df89490a958`
- **SHA256:** `fe1033335a045c696c900d435119d210361966e2fb5cd1ba3382608cfa2c8e68`
- **SHA256:** `5dc607c8990841139768884b1b43e1403496d5a458788a1937be139594f01dca`
- **SHA256:** `7a311b584497e8133cd85950fec6132904dd5b02388a9feed3f5e057fb891d09`
- **SHA256:** `4c82fbafef9bab484a2fbe23e4ec8aac06e8e296d6c9e496f4a589f97fd4ab71`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1059** — Command and Scripting Interpreter
- **T1090** — Proxy
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1491.001** — Defacement: Internal Defacement
- **T1489** — Service Stop
- **T1490** — Inhibit System Recovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] The Gentlemen Ransomware payload hash sweep (Windows + Linux + tooling)

`UC_13_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("992c951f4af57ca7cd8396f5ed69c2199fd6fd4ae5e93726da3e198e78bec0a5","025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a","22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67","2ed9494e9b7b68415b4eb151c922c82c0191294d0aa443dd2cb5133e6bfe3d5d","3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235","48d9b2ce4fcd6854a3164ce395d7140014e0b58b77680623f3e4ca22d3a6e7fd","62c2c24937d67fdeb43f2c9690ab10e8bb90713af46945048db9a94a465ffcb8","860a6177b055a2f5aa61470d17ec3c69da24f1cdf0a782237055cba431158923","87d25d0e5880b3b5cd30106853cbfc6ef1ad38966b30d9bd5b99df46098e546c","8c87134c1b45e990e9568f0a3899b0076f94be16d3c40fa824ac1e6c6ee892db","91415e0b9fe4e7cbe43ec0558a7adf89423de30d22b00b985c2e4b97e75076b1","994d6d1edb57f945f4284cc0163ec998861c7496d85f6d45c08657c9727186e3","9f61ff4deb8afced8b1ecdc8787a134c63bde632b18293fbfc94a91749e3e454","a7a19cab7aab606f833fa8225bc94ec9570a6666660b02cc41a63fe39ea8b0ad","b67958afc982cafbe1c3f114b444d7f4c91a88a3e7a86f89ab8795ac2110d1e6","c46b5a18ab3fb5fd1c5c8288a41c75bf0170c10b5e829af89370a12c86dd10f8","c7f7b5a6e7d93221344e6368c7ab4abf93e162f7567e1a7bcb8786cb8a183a73","ec368ae0b4369b6ef0da244774995c819c63cffb7fd2132379963b9c1640ccd2","efaf8e7422ffd09c7f03f1a5b4e5c2cc32b05334c18d1ccb9673667f8f43108f","f736be55193c77af346dbe905e25f6a1dee3ec1aedca8989ad2088e4f6576b12","fc75ed2159e0c8274076e46a37671cfb8d677af9f586224da1713df89490a958","fe1033335a045c696c900d435119d210361966e2fb5cd1ba3382608cfa2c8e68","5dc607c8990841139768884b1b43e1403496d5a458788a1937be139594f01dca","7a311b584497e8133cd85950fec6132904dd5b02388a9feed3f5e057fb891d09","4c82fbafef9bab484a2fbe23e4ec8aac06e8e296d6c9e496f4a589f97fd4ab71") by host Processes.user Processes.process_name Processes.process Processes.process_hash Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let GentlemenHashes = dynamic(["992c951f4af57ca7cd8396f5ed69c2199fd6fd4ae5e93726da3e198e78bec0a5","025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a","22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67","2ed9494e9b7b68415b4eb151c922c82c0191294d0aa443dd2cb5133e6bfe3d5d","3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235","48d9b2ce4fcd6854a3164ce395d7140014e0b58b77680623f3e4ca22d3a6e7fd","62c2c24937d67fdeb43f2c9690ab10e8bb90713af46945048db9a94a465ffcb8","860a6177b055a2f5aa61470d17ec3c69da24f1cdf0a782237055cba431158923","87d25d0e5880b3b5cd30106853cbfc6ef1ad38966b30d9bd5b99df46098e546c","8c87134c1b45e990e9568f0a3899b0076f94be16d3c40fa824ac1e6c6ee892db","91415e0b9fe4e7cbe43ec0558a7adf89423de30d22b00b985c2e4b97e75076b1","994d6d1edb57f945f4284cc0163ec998861c7496d85f6d45c08657c9727186e3","9f61ff4deb8afced8b1ecdc8787a134c63bde632b18293fbfc94a91749e3e454","a7a19cab7aab606f833fa8225bc94ec9570a6666660b02cc41a63fe39ea8b0ad","b67958afc982cafbe1c3f114b444d7f4c91a88a3e7a86f89ab8795ac2110d1e6","c46b5a18ab3fb5fd1c5c8288a41c75bf0170c10b5e829af89370a12c86dd10f8","c7f7b5a6e7d93221344e6368c7ab4abf93e162f7567e1a7bcb8786cb8a183a73","ec368ae0b4369b6ef0da244774995c819c63cffb7fd2132379963b9c1640ccd2","efaf8e7422ffd09c7f03f1a5b4e5c2cc32b05334c18d1ccb9673667f8f43108f","f736be55193c77af346dbe905e25f6a1dee3ec1aedca8989ad2088e4f6576b12","fc75ed2159e0c8274076e46a37671cfb8d677af9f586224da1713df89490a958","fe1033335a045c696c900d435119d210361966e2fb5cd1ba3382608cfa2c8e68","5dc607c8990841139768884b1b43e1403496d5a458788a1937be139594f01dca","7a311b584497e8133cd85950fec6132904dd5b02388a9feed3f5e057fb891d09","4c82fbafef9bab484a2fbe23e4ec8aac06e8e296d6c9e496f4a589f97fd4ab71"]);
union isfuzzy=true
  (DeviceProcessEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (GentlemenHashes) or InitiatingProcessSHA256 in (GentlemenHashes)
   | project Timestamp, DeviceName, ActionType="ProcessExecution", FileName, FolderPath, SHA256, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceFileEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (GentlemenHashes)
   | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, AccountName=InitiatingProcessAccountName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### [LLM] SystemBC C2 beacon to The Gentlemen infrastructure (91.107.247.163, 45.86.230.112)

`UC_13_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_ports values(All_Traffic.app) as app values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("91.107.247.163","45.86.230.112") AND All_Traffic.action!="blocked" by All_Traffic.src All_Traffic.src_ip All_Traffic.dest All_Traffic.user host | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("91.107.247.163", "45.86.230.112")
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, Protocol,
          InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessSHA256, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] The Gentlemen ransom-note / wallpaper artifact write (READMEGENTLEMEN.txt + gentlemen.bmp)

`UC_13_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths dc(Filesystem.file_path) as path_count from datamodel=Endpoint.Filesystem where (Filesystem.file_name="READMEGENTLEMEN.txt" OR Filesystem.file_name="gentlemen.bmp") AND Filesystem.action IN ("created","modified","written") by host Filesystem.user Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName =~ "READMEGENTLEMEN.txt" or FileName =~ "gentlemen.bmp"
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            DropCount = count(),
            Paths = make_set(FolderPath, 50)
            by DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessFolderPath,
               InitiatingProcessSHA256, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by FirstSeen desc
```

### [LLM] Pre-encryption mass service stoppage targeting databases / backups / virtualization (Gentlemen pattern)

`UC_13_11` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd_samples from datamodel=Endpoint.Processes where (Processes.process_name IN ("net.exe","net1.exe","sc.exe","powershell.exe","pwsh.exe","taskkill.exe")) AND (Processes.process="*stop*" OR Processes.process="*Stop-Service*" OR Processes.process="*taskkill*") AND (Processes.process="*MSSQL*" OR Processes.process="*SQLAgent*" OR Processes.process="*MySQL*" OR Processes.process="*MongoDB*" OR Processes.process="*PostgreSQL*" OR Processes.process="*Oracle*" OR Processes.process="*Veeam*" OR Processes.process="*Acronis*" OR Processes.process="*BackupExec*" OR Processes.process="*Cohesity*" OR Processes.process="*Rubrik*" OR Processes.process="*VMware*" OR Processes.process="*vmms*" OR Processes.process="*AnyDesk*" OR Processes.process="*TeamViewer*" OR Processes.process="*MSExchange*" OR Processes.process="*VSS*") by host Processes.user Processes.process_name Processes.parent_process_name _time span=10m | `drop_dm_object_name(Processes)` | where count >= 5 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let TargetServices = dynamic(["MSSQL","SQLAgent","MySQL","MongoDB","PostgreSQL","Oracle","Veeam","Acronis","BackupExec","Cohesity","Rubrik","VMware","vmms","AnyDesk","TeamViewer","MSExchange","VSS","BackupAssist","Symantec","Carbonite"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("net.exe", "net1.exe", "sc.exe", "powershell.exe", "pwsh.exe", "taskkill.exe", "wmic.exe")
| where (ProcessCommandLine has_any ("stop", "Stop-Service", "taskkill", "Set-Service", "sc delete", "sc config"))
  and ProcessCommandLine has_any (TargetServices)
| where AccountName !endswith "$"
| where InitiatingProcessFileName !in~ ("veeam.backup.shell.exe","vssadmin.exe","trustedinstaller.exe","msiexec.exe","setup.exe")
| summarize StopCount = count(),
            SampleCmds = make_set(ProcessCommandLine, 10),
            DistinctServices = dcount(ProcessCommandLine),
            InitiatorProc = any(InitiatingProcessFileName)
            by DeviceName, AccountName, bin(Timestamp, 10m)
| where StopCount >= 5
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

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `91.107.247.163`, `45.86.230.112`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `992c951f4af57ca7cd8396f5ed69c2199fd6fd4ae5e93726da3e198e78bec0a5`, `025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a`, `22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67`, `2ed9494e9b7b68415b4eb151c922c82c0191294d0aa443dd2cb5133e6bfe3d5d`, `3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235`, `48d9b2ce4fcd6854a3164ce395d7140014e0b58b77680623f3e4ca22d3a6e7fd`, `62c2c24937d67fdeb43f2c9690ab10e8bb90713af46945048db9a94a465ffcb8`, `860a6177b055a2f5aa61470d17ec3c69da24f1cdf0a782237055cba431158923` _(+17 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
