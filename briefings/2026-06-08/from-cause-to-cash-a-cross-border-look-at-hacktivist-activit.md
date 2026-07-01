# [CRIT] From cause to cash: a cross-border look at hacktivist activity

**Source:** Securelist (Kaspersky)
**Published:** 2026-06-08
**Article:** https://securelist.com/tr/hacktivists-broaden-attack-geography/120115/

## Threat Profile

Threat Response 
Table of Contents
Overlapping activity streams 
Technical details 
Vulnerable web servers and fd.aspx 
Scripts deployed 
Publicly available utilities 
C2 and communications 
Sliver 
Havoc 
Apollo 
Adaptix 
BlackSalt Backdoor 
EDR killers 
Connection to the ClearWater ransomware 
File encryption 
Additional functionality 
Updated Blackout Locker 
Rust dropper 
Blackout Locker 
Screen locker 
Attack geography 
Takeaways 
Detection by Kaspersky solutions 
Indicators of compromise 
…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-44976`
- **IPv4 (defanged):** `185.221.153.121`
- **IPv4 (defanged):** `77.72.85.62`
- **IPv4 (defanged):** `45.150.109.2`
- **IPv4 (defanged):** `212.46.12.182`
- **IPv4 (defanged):** `130.49.155.112`
- **IPv4 (defanged):** `45.112.194.82`
- **IPv4 (defanged):** `138.226.236.52`
- **IPv4 (defanged):** `85.137.253.186`
- **Domain (defanged):** `asp.net`
- **MD5:** `09d0517a1f69feff8186655ae3b567e0`
- **MD5:** `26100db3f56880110a92a2b4742d6eaf`
- **MD5:** `cf682a6fee80a78be578b1edd82627fa`
- **MD5:** `2d5533fb65ebb50a5a5fd53e62d73b9a`
- **MD5:** `fe04d230db612ea24af3826fda667131`
- **MD5:** `2db94ee3ec69988588702bd77999a5d4`
- **MD5:** `f88d2b5c3b885ad5a9c1c44551bccc60`
- **MD5:** `1e1edf879b2dc6c9892a22bfa5985db1`
- **MD5:** `78250fa890220821e2b91e31b965de59`
- **MD5:** `f2af797ac45b9f578c53cc49e5797397`
- **MD5:** `0c32bfdf83ecebe3a1399d261dc8ff57`
- **MD5:** `e14cc9a959bbe16c48b8dff063b311f3`
- **MD5:** `36b3be503c6e34613ff50cb28e0f3ddb`
- **MD5:** `c12ebe625737ed0908b045e811f14ecd`
- **MD5:** `1c0924f5711a24821921de5ad822213b`
- **MD5:** `d78adab5e16c26d4cd14fe38f77e29e6`
- **MD5:** `6cf548445c39aff844be96d73c89e376`
- **MD5:** `911a21aa999c324dc960d3498eec528e`
- **MD5:** `68e310de44c3165ffffa25bc495d6fc5`
- **MD5:** `4f41a22b3e7469fb6b45a42d71ec7087`
- **MD5:** `80e5bde401d6b0ca96015ae9cfeb6535`
- **MD5:** `1c82a94c362a9e98a66ae57d6ff37900`
- **MD5:** `fa04aeedc0d2f5bb6ed357fdae1c1435`
- **MD5:** `555a6722436d7cf7de396e0c57d32a27`
- **MD5:** `b974141ff9ad1efb60dd9e16977266ca`
- **MD5:** `7da855b2fd9b52f9088e64d656164637`
- **MD5:** `d08056c2ac28933d6843658c2c8c574f`
- **MD5:** `038cab0c60c53cf12f048272014024c0`
- **MD5:** `c183033d86d2e052b8eb0deb2136ab29`
- **MD5:** `bc0ebf67986eea803b4c9633ed3a4bb5`
- **MD5:** `18618f4b468ba4e64c2e1072a6da2134`
- **MD5:** `1742a9fa35e253614b76ac0f687ba02e`
- **MD5:** `c7eb6da3aa216816079a1b785097552a`
- **MD5:** `3ee38b944e5c83922f99641846f7db0c`
- **MD5:** `d8ff7f417d56fa2a3baf3c8933013a25`
- **MD5:** `1ff222457f5e0e32adfa8341f260dde7`
- **MD5:** `ede8ce887dd9ab7add0f0fc872d51369`
- **MD5:** `1344e6bc51cea35befb4adff7a25899b`
- **MD5:** `2a09162d72aa416e18bab46070043a13`
- **MD5:** `841b7d3863b49f62d4faa9949ff5df38`
- **MD5:** `1bd1ca848b15530e39792b4fe6f31367`
- **MD5:** `b36968b98046d1b033d84f292e7ca1cb`
- **MD5:** `663a479d6d24c767f1d3229a0a91554b`
- **MD5:** `54a308f734095d54ae0e1c86c849a2d8`
- **MD5:** `3137958eb830186826d486afd9222aee`
- **MD5:** `1d09499cb2d7d70df903b60602a58887`
- **MD5:** `d74262f968dc3f378c4021a89d16a292`
- **MD5:** `3d9cbc944f9a9e127550ffb4e8394965`
- **MD5:** `bcd3859f4ddd72c4690d76c3b4ef8955`
- **MD5:** `3a9b0875fc692944c180b165a83a0d17`
- **MD5:** `c558e6a9d0a697c757aa6d7782e269c9`
- **MD5:** `61647db645f7cc221046999ef1dbe1d1`
- **MD5:** `02493e1cb684be6a1a1fc6334a56c516`
- **MD5:** `a3dba01c76571adc0797801ff30f2b90`
- **MD5:** `3f4fbba101b209b00e70787fd5bab819`
- **MD5:** `cd0c5b9e4e47df4231d02ed87ff49f26`
- **MD5:** `b8a13e808b5b5f1836d3e559755139d0`
- **MD5:** `60f8b115aec8a13b0069efc84fc645f5`
- **MD5:** `da55b5612a80ef20ec75b68151e7ff4b`
- **MD5:** `7d35b4961914ad83a57f8832d8e870d8`
- **MD5:** `334abbdc99d359aab2ea371dd4eda5f2`
- **MD5:** `389a1bbdbf5c91bd1c179227f5ae0923`
- **MD5:** `87d48fbccb4aaee95222e215ecb7ebec`
- **MD5:** `76c819185e3c8b8557a2c3986ab80a7c`
- **MD5:** `6d19c8eea11d50c01d20f18382a964d1`
- **MD5:** `8db0adf8fd6dc6195d7ae55e37e49f97`
- **MD5:** `08f3a14a2337eb9936c38f5159be007c`
- **MD5:** `717ab7624c192f6f8dd38994116c28dc`
- **MD5:** `d1c51b92939aa168f0951a8368841373`
- **MD5:** `5398b7eaa94f0ee570b1c5642b559047`
- **MD5:** `d65a79ea9257637c77cab6e087468912`
- **MD5:** `008cd423ca45134d3343f66cced1d104`
- **MD5:** `9741672506f26813c71839aaa6aa3882`
- **MD5:** `06bed0a0906e52c764b3b7016d6a4428`
- **MD5:** `08c069f133ac27cbc02a0ed79e4e87ba`
- **MD5:** `a36082c998391a3ebaf05ba4f834172c`
- **MD5:** `9810ea6752112b3569ddc096e1a72e1d`
- **MD5:** `10824d14c814524155f2b529cf5fee43`
- **MD5:** `242038139842ec79ec1044c64eb0804a`
- **MD5:** `53ba13cc6066adfd67f8098c0a5b8dde`
- **MD5:** `84bb66a982710c5536143a07d84e8749`
- **MD5:** `fa3c222f6b53d6a2e35a54600f6aa011`
- **MD5:** `0b1870d57221eec6f3bbef648e71a724`
- **MD5:** `5e81f72614db42615489266be11b1d09`
- **MD5:** `4c8a0531653b5398a35c6b1b80ff1350`
- **MD5:** `83f66862c0cc40da20236fd6b47138fd`
- **MD5:** `56be07e46fd452315008ed246ebbf52b`
- **MD5:** `579e8bbd6a5bcca89b5acd6fb5db32db`
- **MD5:** `dd8fea244afc8223b961f1d9d6ac8c5d`
- **MD5:** `62123c39477389d500e74e82782adea5`
- **MD5:** `6d365de5c5a13006b7cadd6bc6876e84`
- **MD5:** `2f40bcee90abed0898e92521da17e52d`
- **MD5:** `6dfef58ef68fb7965a23da8be3141af9`
- **MD5:** `56d1de3159adbfda20aca593c99901f9`
- **MD5:** `96dbdc2651d829bf9ba35674dd4bfcae`
- **MD5:** `129225b3e93c17f131bcc2a982ffb09a`
- **MD5:** `9f37fff7e5d22f83fc1c0872ad5332f9`
- **MD5:** `cf54f6cbdb4dbf1ce6fc2e5be4ca3b20`
- **MD5:** `e99efd77392e2b4fe4d9bf5728a12b98`
- **MD5:** `f2dc794bf93887e281ad89209493065a`
- **MD5:** `d13997b1716e4c82ab454285202eafdc`
- **MD5:** `ecb57d8793514aa02314417265b1853f`
- **MD5:** `3b974ff986445e5944c51179d19bd6be`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1547.001** — Persistence (article-specific)
- **T1543.003** — Persistence (article-specific)

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

### Article-specific behavioural hunt — From cause to cash: a cross-border look at hacktivist activity

`UC_238_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — From cause to cash: a cross-border look at hacktivist activity ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("anydesk.exe","upd.exe","winhost.exe","update1.exe","akolo.exe","install.bat","servicechecker.bat","backupsrv.exe","backupagnt.exe","windowsinternal.updatecomponent.dll","demon.x64.exe","windowsservicehelper.exe","svc.exe","kil.exe","killer.exe") OR Processes.process_path="*C:\Windows\System32\inetsrv\*" OR Processes.process_path="*C:\ProgramData\ClearWater_x64.exe*" OR Processes.process_path="*\AppData\Local\Microsoft\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Windows\System32\inetsrv\*" OR Filesystem.file_path="*C:\ProgramData\ClearWater_x64.exe*" OR Filesystem.file_path="*\AppData\Local\Microsoft\*" OR Filesystem.file_name IN ("anydesk.exe","upd.exe","winhost.exe","update1.exe","akolo.exe","install.bat","servicechecker.bat","backupsrv.exe","backupagnt.exe","windowsinternal.updatecomponent.dll","demon.x64.exe","windowsservicehelper.exe","svc.exe","kil.exe","killer.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*" OR Registry.registry_path="*HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PersonalizationCSP*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — From cause to cash: a cross-border look at hacktivist activity
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("anydesk.exe", "upd.exe", "winhost.exe", "update1.exe", "akolo.exe", "install.bat", "servicechecker.bat", "backupsrv.exe", "backupagnt.exe", "windowsinternal.updatecomponent.dll", "demon.x64.exe", "windowsservicehelper.exe", "svc.exe", "kil.exe", "killer.exe") or FolderPath has_any ("C:\Windows\System32\inetsrv\", "C:\ProgramData\ClearWater_x64.exe", "\AppData\Local\Microsoft\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Windows\System32\inetsrv\", "C:\ProgramData\ClearWater_x64.exe", "\AppData\Local\Microsoft\") or FileName in~ ("anydesk.exe", "upd.exe", "winhost.exe", "update1.exe", "akolo.exe", "install.bat", "servicechecker.bat", "backupsrv.exe", "backupagnt.exe", "windowsinternal.updatecomponent.dll", "demon.x64.exe", "windowsservicehelper.exe", "svc.exe", "kil.exe", "killer.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `185.221.153.121`, `77.72.85.62`, `45.150.109.2`, `212.46.12.182`, `130.49.155.112`, `45.112.194.82`, `138.226.236.52`, `85.137.253.186` _(+1 more)_

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-44976`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `09d0517a1f69feff8186655ae3b567e0`, `26100db3f56880110a92a2b4742d6eaf`, `cf682a6fee80a78be578b1edd82627fa`, `2d5533fb65ebb50a5a5fd53e62d73b9a`, `fe04d230db612ea24af3826fda667131`, `2db94ee3ec69988588702bd77999a5d4`, `f88d2b5c3b885ad5a9c1c44551bccc60`, `1e1edf879b2dc6c9892a22bfa5985db1` _(+95 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 10 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
