# [CRIT] Android Spyware Asin Targets Arabic Users via Fake News, PDF and War Map Apps

**Source:** The Hacker News, Unit 42 (Palo Alto)
**Published:** 2026-06-05
**Article:** https://thehackernews.com/2026/06/android-spyware-asin-targets-arabic.html

## Threat Profile

Threat Research Center 
High Profile Threats 
Vulnerabilities 
Vulnerabilities 
Threat Brief: Active Exploitation of PAN-OS CVE-2026-0257 
2 min read 
Related Products Advanced URL Filtering Cortex Cortex Xpanse GlobalProtect Next-Generation Firewall 
By: Andy Piazza 
Unit 42 
Published: June 5, 2026 
Categories: High Profile Threats 
Vulnerabilities 
Tags: CVE-2026-0257 
Vulnerability 
Palo Alto Networks Unit 42 has observed active exploitation of PAN-OS vulnerability CVE-2026-0257 by an uniden…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-0257`
- **IPv4 (defanged):** `23.128.228.6`
- **IPv4 (defanged):** `104.207.144.154`
- **IPv4 (defanged):** `146.19.216.119`
- **IPv4 (defanged):** `146.19.216.120`
- **IPv4 (defanged):** `146.19.216.125`
- **IPv4 (defanged):** `179.43.172.213`
- **IPv4 (defanged):** `185.195.232.139`
- **IPv4 (defanged):** `198.12.106.60`
- **IPv4 (defanged):** `202.144.192.47`
- **IPv4 (defanged):** `209.99.191.137`
- **IPv4 (defanged):** `79.130.26.202`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1133** — External Remote Services
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PAN-OS CVE-2026-0257 GlobalProtect login from Unit 42 IOC IPs

`UC_15_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.user) as user values(Authentication.dest) as dest values(Authentication.action) as action from datamodel=Authentication where Authentication.app="globalprotect" Authentication.action="success" Authentication.src IN ("23.128.228.6","104.207.144.154","146.19.216.119","146.19.216.120","146.19.216.125","179.43.172.213","185.195.232.139","198.12.106.60","202.144.192.47") by Authentication.src Authentication.user Authentication.dest | `drop_dm_object_name(Authentication)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Defender XDR has no native PAN-OS GP telemetry — see sentinel_kql for the CommonSecurityLog hunt.
// If GP logs are normalised via MDE custom connector to DeviceNetworkEvents, fall back to RemoteIP IOC match:
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("23.128.228.6","104.207.144.154","146.19.216.119","146.19.216.120","146.19.216.125","179.43.172.213","185.195.232.139","198.12.106.60","202.144.192.47")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, LocalPort
```

### [LLM] PAN-OS GlobalProtect login with CVE-2026-0257 PoC hard-coded host-id / device-name

`UC_15_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.user) as user values(Authentication.src) as src values(Authentication.dest) as dest from datamodel=Authentication where Authentication.app="globalprotect" Authentication.action="success" (Authentication.src_nt_host IN ("WINDOWS-LAPTOP-001","DESKTOP-GP01","GP-CLIENT") OR Authentication.host_id IN ("aa:bb:cc:dd:ee:ff","00:11:22:33:44:55")) by Authentication.src_nt_host Authentication.host_id Authentication.user Authentication.src | `drop_dm_object_name(Authentication)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// PAN-OS GP host-id/device-name values do not flow into Defender XDR tables natively.
// If GP logs are ingested via custom MDE connector into AdditionalFields, this is the shape:
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType has "GlobalProtect"
| where AdditionalFields has_any ("aa:bb:cc:dd:ee:ff","00:11:22:33:44:55","WINDOWS-LAPTOP-001","DESKTOP-GP01","GP-CLIENT")
| project Timestamp, DeviceName, ActionType, RemoteIP, AccountName, AdditionalFields
```

### [LLM] PAN-OS GlobalProtect login matching CVE-2026-0257 PoC client fingerprint

`UC_15_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.user) as user values(Authentication.src) as src from datamodel=Authentication where Authentication.app="globalprotect" Authentication.action="success" Authentication.endpoint_os_version="Microsoft Windows 10 Pro 64-bit" (Authentication.user_domain="" OR Authentication.user_domain="-" OR NOT Authentication.user_domain="*") by Authentication.user Authentication.src Authentication.endpoint_os_version | `drop_dm_object_name(Authentication)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// PAN-OS GP client-info strings do not flow into Defender XDR natively.
// Where GP logs are ingested via a custom MDE connector, the substring lives in AdditionalFields:
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType has "GlobalProtect"
| where AdditionalFields has "Microsoft Windows 10 Pro 64-bit"
| where AdditionalFields has_any ("source_user_info.domain=\"\"","source_user_info.domain=null","\"domain\":\"\"")
| project Timestamp, DeviceName, ActionType, RemoteIP, AccountName, AdditionalFields
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
  - IP / domain IOC(s): `23.128.228.6`, `104.207.144.154`, `146.19.216.119`, `146.19.216.120`, `146.19.216.125`, `179.43.172.213`, `185.195.232.139`, `198.12.106.60` _(+3 more)_

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-0257`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 9 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
