# [HIGH] FortiBleed credential-theft campaign linked to Lynx ransomware

**Source:** BleepingComputer
**Published:** 2026-07-01
**Article:** https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/

## Threat Profile

FortiBleed credential-theft campaign linked to Lynx ransomware 
By Lawrence Abrams 
July 1, 2026
05:37 PM
0 
The massive FortiBleed credential theft campaign has been linked to the INC and Lynx ransomware operations, suggesting the stolen Fortinet credentials were intended to fuel future network intrusions.
Earlier this month, a server containing credentials stolen from more than 73,000 Fortinet devices was discovered exposed on the internet. Researchers found the server contained downloaded For…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-24858`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1136.001** — Create Account: Local Account
- **T1078.003** — Valid Accounts: Local Accounts
- **T1110.004** — Brute Force: Credential Stuffing
- **T1110.003** — Brute Force: Password Spraying
- **T1078** — Valid Accounts
- **T1602.002** — Data from Configuration Repository: Network Device Configuration Dump
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1490** — Inhibit System Recovery
- **T1657** — Financial Theft

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### FortiBleed 'adminin' backdoor local account creation and logon

`UC_1_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("net.exe","net1.exe","powershell.exe","pwsh.exe")) Processes.process="*adminin*" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process,"(?i)(user\s+adminin.*(/add|-add)|New-LocalUser.*adminin|Add-LocalGroupMember.*adminin)") | sort - lastTime
```

**Defender KQL:**
```kql
union
 (DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where ProcessCommandLine has "adminin"
  | where (FileName in~ ("net.exe","net1.exe") and ProcessCommandLine has "user" and ProcessCommandLine has_any ("/add","-add"))
       or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("New-LocalUser","Add-LocalGroupMember"))
  | project Timestamp, DeviceName, Signal="LocalAccountCreated", Account="adminin", Detail=ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName),
 (DeviceLogonEvents
  | where Timestamp > ago(30d)
  | where AccountName =~ "adminin"
  | project Timestamp, DeviceName, Signal="BackdoorAccountLogon", Account=AccountName, Detail=strcat("LogonType=", tostring(LogonType), " RemoteIP=", RemoteIP), InitiatingProcessFileName, InitiatingProcessAccountName=AccountDomain)
| order by Timestamp desc
```

### Credential-stuffing burst culminating in success against FortiGate SSL-VPN / SSO

`UC_1_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication.Authentication where (Authentication.app="fortigate" OR Authentication.app="*ssl*vpn*" OR Authentication.app="*vpn*") by Authentication.src Authentication.action Authentication.user | `drop_dm_object_name(Authentication)` | stats sum(eval(if(action="failure",count,0))) as failures sum(eval(if(action="success",count,0))) as successes dc(user) as user_count values(user) as users by src | where failures >= 20 AND successes >= 1 AND user_count >= 10 | sort - failures
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(1d)
| summarize Failures = countif(ErrorCode != 0), Successes = countif(ErrorCode == 0), DistinctUsers = dcount(AccountUpn), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleApps = make_set(Application, 5) by IPAddress
| where DistinctUsers >= 10 and Failures >= 20 and Successes >= 1   // one IP, 10+ users, 20+ fails, >=1 success = stuffing signature
| order by Failures desc
```

### FortiGate admin login and configuration download from external IP

`UC_1_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication.Authentication where Authentication.app="fortigate" Authentication.action="success" (Authentication.user="admin" OR Authentication.user="*admin*") by Authentication.src Authentication.dest Authentication.user | `drop_dm_object_name(Authentication)` | where NOT (cidrmatch("10.0.0.0/8",src) OR cidrmatch("172.16.0.0/12",src) OR cidrmatch("192.168.0.0/16",src)) | sort - lastTime
```

### Outbound connection to FortiBleed operator infrastructure 85.11.187.8

`UC_1_8` · phase: **c2** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="85.11.187.8" OR All_Traffic.src="85.11.187.8") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "85.11.187.8"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Lynx/INC ransomware mass file encryption via .lynx extension

`UC_1_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Filesystem.file_path) as file_count values(Filesystem.file_name) as sample_files from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.lynx" by Filesystem.dest Filesystem.process_name Filesystem.user _time span=10m | `drop_dm_object_name(Filesystem)` | where file_count >= 25 | sort - file_count
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileRenamed","FileCreated","FileModified")
| where FileName endswith ".lynx"
| summarize FileCount = dcount(FolderPath), SampleFiles = make_set(FileName, 5), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Proc = any(InitiatingProcessFileName), ProcCmd = any(InitiatingProcessCommandLine) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 10m)
| where FileCount >= 25   // 25 = mass-encryption burst; lower to 1 for max sensitivity given unique extension
| order by FirstSeen desc
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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
  - CVE(s): `CVE-2026-24858`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 10 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
