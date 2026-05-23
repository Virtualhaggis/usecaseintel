# [CRIT] Hackers Use Six-Layer Persistence to Maintain Access on Compromised FreePBX Systems

**Source:** Cyber Security News
**Published:** 2026-05-22
**Article:** https://cybersecuritynews.com/hackers-use-six-layer-persistence/

## Threat Profile

Home Cyber Security News 
Hackers Use Six-Layer Persistence to Maintain Access on Compromised FreePBX Systems 
By Tushar Subhra Dutta 
May 22, 2026 
A hacker group known as INJ3CTOR3 has been running an active campaign against FreePBX systems, deploying a newly discovered PHP webshell called JOMANGY that uses six separate persistence layers to stay embedded on compromised servers. 
The campaign targets internet-exposed VoIP phone systems and routes calls through them at the victims’ expense, a s…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-64328`
- **CVE:** `CVE-2025-57819`
- **IPv4 (defanged):** `45.95.147.178`
- **IPv4 (defanged):** `45.234.176.202`
- **IPv4 (defanged):** `160.119.76.250`
- **IPv4 (defanged):** `169.150.218.33`
- **IPv4 (defanged):** `169.150.218.37`
- **IPv4 (defanged):** `146.70.129.114`
- **Domain (defanged):** `crm.razatelefonia.pro`
- **SHA1:** `6ea9c6d2d932532a4cd44c7974fb1a0a87dbfcf9`
- **MD5:** `a8b65af6c142736ccf80420e44df240f`
- **MD5:** `ec4ca4db5ec0b782e51224fa7082ac06`
- **MD5:** `b92c65af386ed772972b43cab0d55a4a`
- **MD5:** `bfcedbc1831779921a0ee2cfaee004f2`
- **MD5:** `cf710203400b8c466e6dfcafcf36a411`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1053.003** — Scheduled Task/Job: Cron
- **T1222.002** — File and Directory Permissions Modification: Linux and Mac
- **T1546** — Event Triggered Execution
- **T1136.001** — Create Account: Local Account
- **T1078.003** — Valid Accounts: Local Accounts
- **T1505.003** — Server Software Component: Web Shell
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1547.006** — Boot or Logon Autostart Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] INJ3CTOR3 JOMANGY C2 beacon to 45.95.147.178 / k.php / wr.php

`UC_11_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as ports values(All_Traffic.bytes_in) as bytes_in values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("45.95.147.178","45.234.176.202","160.119.76.250") OR All_Traffic.url IN ("*45.95.147.178/k.php*","*45.95.147.178/z/wr.php*","*45.95.147.178/z/wor.php*","*45.95.147.178/z/post/root.php*","*45.95.147.178/z/post/noroot.php*")) by All_Traffic.src All_Traffic.dest All_Traffic.url All_Traffic.app | `drop_dm_object_name(All_Traffic)` | eval beacon_pattern=if(lastTime-firstTime>1800 AND count>=10,"true","false") | sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("45.95.147.178","45.234.176.202","160.119.76.250")
   or RemoteUrl has_any ("/k.php","/z/wr.php","/z/wor.php","/z/post/root.php","/z/post/noroot.php")
| where InitiatingProcessFileName in~ ("curl","wget","php","php-fpm","cron","crond","bash","sh")
| summarize ConnCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            ConnGapSeconds = datetime_diff('second', max(Timestamp), min(Timestamp)),
            URLs = make_set(RemoteUrl, 10), Procs = make_set(InitiatingProcessCommandLine, 10)
            by DeviceName, RemoteIP, InitiatingProcessFileName
| where ConnCount >= 5 and ConnGapSeconds >= 600   // sustained polling over >10 minutes
| order by ConnCount desc
```

### [LLM] Immutable crontab persistence — chattr +i on cron paths (JOMANGY layer 3)

`UC_11_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.process) as cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name="chattr" OR Processes.process="*chattr*") AND (Processes.process="*+i*" OR Processes.process="*+ai*" OR Processes.process="*+ia*") AND (Processes.process="*cron*" OR Processes.process="*crontab*" OR Processes.process="*/var/spool/cron*" OR Processes.process="*/etc/cron.d*" OR Processes.process="*/.*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "chattr" or ProcessCommandLine has "chattr"
| where ProcessCommandLine has_any (" +i"," +ai"," +ia","+i ")
| where ProcessCommandLine has_any ("cron","crontab","/var/spool/cron","/etc/cron.d","/etc/cron.daily","/etc/cron.hourly","/.config","/.cache","/tmp/.","/var/tmp/.")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] FreePBX backdoor account creation — INJ3CTOR3 UID-0 names blended with legit accounts

`UC_11_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime values(Processes.user) as actor values(Processes.process) as cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("useradd","adduser","usermod") AND (Processes.process="*newfpbx*" OR Processes.process="*newfpbxs*" OR Processes.process="*xhimax*" OR Processes.process="*sugarmaint*" OR Processes.process="*supermaint*" OR Processes.process="*asteriskuser*" OR Processes.process="*freepbxuser*" OR Processes.process="*spamfilter*" OR Processes.process="*issabel*" OR Processes.process="*sangoma*" OR Processes.process=" emo " OR Processes.process=" hima " OR Processes.process="*supports*") by Processes.dest Processes.process_name | `drop_dm_object_name(Processes)` | sort - firstTime
```

**Defender KQL:**
```kql
let JomangyAccountNames = dynamic(["newfpbx","newfpbxs","xhimax","sugarmaint","supermaint","asteriskuser","freepbxuser","spamfilter","issabel","sangoma","emo","hima","supports","support","centos","admin","asterisk"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("useradd","adduser","usermod","groupadd")
   or ProcessCommandLine has_any ("useradd ","adduser ","usermod ")
| extend NameMatched = tostring(set_intersect(JomangyAccountNames, split(tolower(ProcessCommandLine), " ")))
| where ProcessCommandLine has_any (JomangyAccountNames)
   or ProcessCommandLine matches regex @"(?i)useradd\s+.*(-o\s+)?(-u\s+0|--uid\s+0)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, NameMatched
| order by Timestamp desc
```

### [LLM] JOMANGY persistence layer 6 — license.php / ajax.php drop in FreePBX module dirs

`UC_11_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime values(Filesystem.user) as user values(Filesystem.process_name) as writer from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified","write") AND (Filesystem.file_path="/var/www/html/admin/modules/freepbx_ha/license.php" OR Filesystem.file_path="/var/www/html/admin/modules/phones/ajax.php" OR Filesystem.file_name="tryRoot1.sh" OR Filesystem.file_name="wr.php" OR Filesystem.file_name="wor.php" OR Filesystem.file_name="zen.php" OR Filesystem.file_name="ask.php" OR Filesystem.file_name="_md5.php") by Filesystem.dest Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has "/var/www/html/admin/modules/" 
   and (FolderPath has_any ("/freepbx_ha/","/phones/")
        or FileName in~ ("license.php","tryRoot1.sh","wr.php","wor.php","zen.php","ask.php","_md5.php","k.php"))
   or FileName =~ "tryRoot1.sh"
   or SHA1 == "6ea9c6d2d932532a4cd44c7974fb1a0a87dbfcf9"
   or MD5 in ("a8b65af6c142736ccf80420e44df240f","ec4ca4db5ec0b782e51224fa7082ac06","b92c65af386ed772972b43cab0d55a4a","bfcedbc1831779921a0ee2cfaee004f2","cf710203400b8c466e6dfcafcf36a411")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] JOMANGY shell profile re-infection injection (persistence layer 2)

`UC_11_13` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime values(Filesystem.user) as user values(Filesystem.process_name) as writer values(Filesystem.process) as cmd from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified","write") AND (Filesystem.file_path="/root/.bashrc" OR Filesystem.file_path="/root/.bash_profile" OR Filesystem.file_path="/root/.profile" OR Filesystem.file_path="/etc/profile" OR Filesystem.file_path="/etc/bash.bashrc" OR Filesystem.file_path="/etc/profile.d/*") AND (Filesystem.process_name IN ("php","php-fpm","apache2","httpd","nginx","sh","bash") OR Filesystem.process="*45.95.147.178*" OR Filesystem.process="*k.php*") by Filesystem.dest Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | sort - firstTime
```

**Defender KQL:**
```kql
let ProfilePaths = dynamic(["/root/.bashrc","/root/.bash_profile","/root/.profile","/etc/profile","/etc/bash.bashrc"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath in (ProfilePaths) or FolderPath startswith "/etc/profile.d/" or FileName in~ (".bashrc",".bash_profile",".profile")
| where InitiatingProcessFileName in~ ("php","php-fpm","apache2","httpd","nginx","sh","bash","dash")
   or InitiatingProcessCommandLine has_any ("45.95.147.178","45.234.176.202","k.php","wr.php","wor.php","trace_e1ebf9066a951be519a24140711839ea","bm2cjjnRXac1WW3KT7k6MKTR")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] JOMANGY webshell watermark / marker string in web tree or hosted files

`UC_11_14` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
(index=web_logs OR sourcetype=apache:access OR sourcetype=nginx:access) (uri_path="*.php" OR uri="*.php") | search _raw="*trace_e1ebf9066a951be519a24140711839ea*" OR _raw="*bm2cjjnRXac1WW3KT7k6MKTR*" | stats count min(_time) as firstTime max(_time) as lastTime values(src) as src values(uri_path) as paths by host | append [| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/var/www/*" OR Filesystem.file_path="/usr/share/freepbx/*" OR Filesystem.file_path="/etc/asterisk/*") AND Filesystem.file_name="*.php" by Filesystem.dest Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`] | sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(90d)
| where FolderPath has_any ("/var/www/","/usr/share/freepbx/","/etc/asterisk/")
| where FileName endswith ".php" or FileName endswith ".sh"
| where AdditionalFields has_any ("trace_e1ebf9066a951be519a24140711839ea","bm2cjjnRXac1WW3KT7k6MKTR","ZenharR","JOMANGY")
   or SHA1 == "6ea9c6d2d932532a4cd44c7974fb1a0a87dbfcf9"
   or MD5 in ("a8b65af6c142736ccf80420e44df240f","ec4ca4db5ec0b782e51224fa7082ac06","b92c65af386ed772972b43cab0d55a4a","bfcedbc1831779921a0ee2cfaee004f2","cf710203400b8c466e6dfcafcf36a411")
| project Timestamp, DeviceName, FolderPath, FileName, SHA1, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Hackers Use Six-Layer Persistence to Maintain Access on Compromised FreePBX Syst

`UC_11_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Use Six-Layer Persistence to Maintain Access on Compromised FreePBX Syst ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("tryroot1.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/var/www/html/admin/modules/freepbx_ha/license.php*" OR Filesystem.file_name IN ("tryroot1.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Use Six-Layer Persistence to Maintain Access on Compromised FreePBX Syst
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("tryroot1.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/var/www/html/admin/modules/freepbx_ha/license.php") or FileName in~ ("tryroot1.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.95.147.178`, `45.234.176.202`, `160.119.76.250`, `169.150.218.33`, `169.150.218.37`, `146.70.129.114`, `crm.razatelefonia.pro`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-64328`, `CVE-2025-57819`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `6ea9c6d2d932532a4cd44c7974fb1a0a87dbfcf9`, `a8b65af6c142736ccf80420e44df240f`, `ec4ca4db5ec0b782e51224fa7082ac06`, `b92c65af386ed772972b43cab0d55a4a`, `bfcedbc1831779921a0ee2cfaee004f2`, `cf710203400b8c466e6dfcafcf36a411`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 15 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
