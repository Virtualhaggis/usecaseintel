# [HIGH] FortiBleed leak exposes Fortinet VPN credentials for 73,000 devices.

**Source:** BleepingComputer
**Published:** 2026-06-18
**Article:** https://www.bleepingcomputer.com/news/security/fortibleed-leak-exposes-fortinet-vpn-credentials-for-73-000-devices/

## Threat Profile

FortiBleed leak exposes Fortinet VPN credentials for 73,000 devices. 
By Lawrence Abrams 
June 17, 2026
11:12 AM
0 
A newly discovered data leak dubbed "FortiBleed" has exposed what appears to be a collection of Fortinet and FortiGate VPN credentials for 73,932 firewall URLs at organizations worldwide.
The exposed data was first discovered by security researcher Bob Diachenko, who says he found a server containing what appeared to be valid Fortinet VPN credentials, including usernames, email add…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `mail.inspocenergy.com`
- **Domain (defanged):** `staterid.co.in`
- **Domain (defanged):** `toyoda.io`
- **Domain (defanged):** `foxconn.com`
- **Domain (defanged):** `chevron.com`
- **Domain (defanged):** `mercedes-benz.com`
- **Domain (defanged):** `att.net`
- **Domain (defanged):** `comcast.com`

## MITRE ATT&CK Techniques

- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1078** — Valid Accounts
- **T1133** — External Remote Services
- **T1110.001** — Password Guessing
- **T1110.003** — Password Spraying
- **T1556** — Modify Authentication Process

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### FortiGate SSL VPN successful login from anonymizer/new-geography post-FortiBleed

`UC_40_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src values(Authentication.src_ip) as src_ip from datamodel=Authentication where Authentication.app="fortigate" Authentication.action="success" (Authentication.signature="ssl-login-fail" OR Authentication.signature="ssl-new-con" OR Authentication.signature="sslvpn_login") by Authentication.user Authentication.dest _time span=1h | `drop_dm_object_name(Authentication)` | join type=left user [ | tstats `summariesonly` values(Authentication.src_ip) as baseline_src_ip from datamodel=Authentication where Authentication.app="fortigate" Authentication.action="success" earliest=-30d@d latest=-1d@d by Authentication.user | `drop_dm_object_name(Authentication)` ] | eval new_ip=if(isnull(mvfind(baseline_src_ip,src_ip)),1,0) | where new_ip=1 | iplocation src_ip | table firstTime user dest src_ip Country City
```

**Defender KQL:**
```kql
// FortiGate SSL VPN logs typically arrive via 3rd-party MDE connector or surface in DeviceLogonEvents only when the VPN client logs onto the endpoint. Best-effort: surface RemoteInteractive/Network logons immediately preceded by VPN client connect, from non-corp IPs.
let LookbackDays = 7d;
let KnownCorpSubnets = dynamic(["10.","172.16.","172.17.","172.18.","172.19.","172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.","172.28.","172.29.","172.30.","172.31.","192.168."]);
DeviceLogonEvents
| where Timestamp > ago(LookbackDays)
| where ActionType == "LogonSuccess"
| where LogonType in ("RemoteInteractive","Network")
| where isnotempty(RemoteIP) and RemoteIPType == "Public"
| where not(RemoteIP startswith_cs KnownCorpSubnets[0])
| join kind=leftanti (
    DeviceLogonEvents
    | where Timestamp between (ago(60d) .. ago(LookbackDays))
    | where ActionType == "LogonSuccess"
    | summarize by AccountName, RemoteIP
) on AccountName, RemoteIP
| project Timestamp, DeviceName, AccountName, AccountDomain, LogonType, RemoteIP, RemoteDeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### FortiGate SSL VPN authentication brute-force burst (FortiBleed harvesting campaign)

`UC_40_3` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where Authentication.app="fortigate" Authentication.action="failure" (Authentication.signature="ssl-login-fail" OR Authentication.signature="sslvpn_login_fail") by Authentication.src_ip _time span=10m | `drop_dm_object_name(Authentication)` | where count >= 50 | iplocation src_ip | table _time src_ip count Country City
```

**Defender KQL:**
```kql
// FortiGate brute-force telemetry is not natively in MDE. Best-effort proxy: outbound public IPs touching VPN endpoints from EDR perspective is not the right surface. Use sentinel_kql instead.
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 443
| where InitiatingProcessFileName has_any ("FortiClient.exe","FortiSSLVPNdaemon.exe")
| summarize Attempts=count() by RemoteIP, bin(Timestamp, 10m)
| where Attempts > 30
| order by Timestamp desc
```

### Microsoft SQL Server brute-force burst correlated with FortiBleed operator MO

`UC_40_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where Authentication.app="mssql" Authentication.action="failure" by Authentication.src_ip Authentication.user _time span=10m | `drop_dm_object_name(Authentication)` | stats sum(count) as Attempts dc(user) as UniqUsers values(user) as Users by src_ip | where Attempts >= 100
```

**Defender KQL:**
```kql
let WindowMinutes = 10m;
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| where InitiatingProcessFileName =~ "sqlservr.exe"
| summarize Attempts=count(),
            UniqueAccounts=dcount(AccountName),
            SampleAccounts=make_set(AccountName, 10)
            by DeviceName, RemoteIP, bin(Timestamp, WindowMinutes)
| where Attempts >= 100
| order by Timestamp desc
```

### FortiGate management/admin portal login success from public internet source

`UC_40_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(Authentication.src_ip) as src_ip from datamodel=Authentication where Authentication.app="fortigate" Authentication.action="success" (Authentication.signature="admin login" OR Authentication.signature="admin_login_success" OR Authentication.signature="login") by Authentication.user Authentication.dest _time span=1h | `drop_dm_object_name(Authentication)` | iplocation src_ip | search NOT (src_ip=10.0.0.0/8 OR src_ip=172.16.0.0/12 OR src_ip=192.168.0.0/16) | table firstTime user dest src_ip Country City
```

**Defender KQL:**
```kql
// FortiGate admin-portal auth does not surface on Defender XDR; CommonSecurityLog (Sentinel) is the right pivot. Best-effort EDR proxy: outbound HTTPS/SSH from admin workstations to FortiGate management IPs.
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (22, 443, 8443)
| where InitiatingProcessFileName has_any ("putty.exe","plink.exe","chrome.exe","msedge.exe","firefox.exe")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
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
  - IP / domain IOC(s): `mail.inspocenergy.com`, `staterid.co.in`, `toyoda.io`, `foxconn.com`, `chevron.com`, `mercedes-benz.com`, `att.net`, `comcast.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
