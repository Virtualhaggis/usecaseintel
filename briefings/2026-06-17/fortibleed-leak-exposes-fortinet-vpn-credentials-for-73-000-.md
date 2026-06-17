# [HIGH] FortiBleed leak exposes Fortinet VPN credentials for 73,000 devices.

**Source:** BleepingComputer
**Published:** 2026-06-17
**Article:** https://www.bleepingcomputer.com/news/security/fortibleed-leak-exposes-fortinet-vpn-credentials-for-73-000-devices/

## Threat Profile

FortiBleed leak exposes Fortinet VPN credentials for 73,000 devices. 
By Lawrence Abrams 
June 17, 2026
11:12 AM
0 


A newly discovered data leak dubbed "FortiBleed" has exposed what appears to be a collection of Fortinet and FortiGate VPN credentials for 73,932 firewall URLs at organizations worldwide.


The exposed data was first discovered by security researcher Bob Diachenko, who says he found a server containing what appeared to be valid Fortinet VPN credentials, including usernames, e…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `mailitsippc.com`
- **Domain (defanged):** `statergie.cn`
- **Domain (defanged):** `loyalz.io`
- **Domain (defanged):** `foxconn.com`
- **Domain (defanged):** `chevron.com`
- **Domain (defanged):** `mercedes-benz.com`
- **Domain (defanged):** `comcast.com`

## MITRE ATT&CK Techniques

- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1110.001** — Password Guessing
- **T1110.003** — Password Spraying
- **T1133** — External Remote Services
- **T1078** — Valid Accounts
- **T1087.002** — Domain Account Discovery
- **T1482** — Domain Trust Discovery
- **T1018** — Remote System Discovery
- **T1078.002** — Valid Accounts: Domain Accounts
- **T1071.001** — Application Layer Protocol: Web
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service
- **T1602.002** — Data from Configuration Repository: Network Device Configuration Dump
- **T1119** — Automated Collection

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### FortiGate SSL VPN credential-stuffing: high-volume auth failures from few sources

`UC_0_2` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Authentication.user) AS distinct_users, values(Authentication.dest) AS targets FROM datamodel=Authentication WHERE Authentication.action=failure AND Authentication.app IN ("fortigate","fortinet-ssl-vpn","sslvpn") BY Authentication.src, _time span=5m | `drop_dm_object_name(Authentication)` | where count>=100 AND distinct_users>=20 | sort - count
```

### FortiGate SSL VPN successful logon from new country / ASN for established account

`UC_0_3` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) AS firstSeen FROM datamodel=Authentication WHERE Authentication.action=success AND Authentication.app IN ("fortigate","fortinet-ssl-vpn","sslvpn") earliest=-30d@d latest=-1d@d BY Authentication.user, Authentication.src | `drop_dm_object_name(Authentication)` | rename src AS baseline_src, user AS baseline_user | inputlookup append=t fortigate_recent_logons.csv | eval baseline=if(isnotnull(firstSeen),1,0) | stats max(baseline) AS baseline, latest(_time) AS recent_time BY user, src | where baseline=0 AND recent_time>=relative_time(now(),"-1d@d")
```

### FortiGate VPN logon followed by AD reconnaissance from VPN pool IP

`UC_0_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) AS vpn_time FROM datamodel=Authentication WHERE Authentication.action=success AND Authentication.app IN ("fortigate","fortinet-ssl-vpn","sslvpn") BY Authentication.user, Authentication.src_ip | `drop_dm_object_name(Authentication)` | rename user AS user_vpn, src_ip AS vpn_src | join type=inner user_vpn [| tstats `summariesonly` count, values(Processes.process) AS process, values(Processes.process_name) AS process_name, min(_time) AS recon_time FROM datamodel=Endpoint.Processes WHERE Processes.process_name IN ("nltest.exe","dsquery.exe","net.exe","net1.exe","adfind.exe","SharpHound.exe","BloodHound.exe") OR Processes.process IN ("*net group*","*Get-ADUser*","*Get-DomainController*","*trustdmp*") BY Processes.user, Processes.dest | `drop_dm_object_name(Processes)` | rename user AS user_vpn] | where recon_time>=vpn_time AND recon_time<=vpn_time+1800 | table vpn_time, recon_time, user_vpn, vpn_src, dest, process_name, process
```

**Defender KQL:**
```kql
let WindowMin = 30m;
let VpnLogons = IdentityLogonEvents
    | where Timestamp > ago(7d)
    | where ActionType == "LogonSuccess"
    | where Application has_any ("FortiGate","Fortinet","SSL VPN","sslvpn") or Protocol has "SSLVPN"
    | project VpnLogonTime = Timestamp, VpnUser = tolower(AccountName), VpnAccountDomain = AccountDomain, VpnSrcIP = IPAddress;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("nltest.exe","dsquery.exe","net.exe","net1.exe","adfind.exe","SharpHound.exe","BloodHound.exe","PowerView.ps1")
   or ProcessCommandLine has_any ("net group /domain","net user /domain","Get-ADUser","Get-ADComputer","Get-DomainController","Get-DomainTrust","nltest /domain_trusts","nltest /dclist","trustdmp")
| extend ProcUser = tolower(AccountName)
| join kind=inner VpnLogons on $left.ProcUser == $right.VpnUser
| where Timestamp between (VpnLogonTime .. VpnLogonTime + WindowMin)
| project Timestamp, DeviceName, AccountName, AccountDomain, FileName, ProcessCommandLine, InitiatingProcessFileName, VpnSrcIP, VpnLogonTime,
          DelaySec = datetime_diff('second', Timestamp, VpnLogonTime)
| order by Timestamp desc
```

### Internal host egress to FortiBleed C2 infrastructure (mailitsippc / statergie / loyalz)

`UC_0_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) AS firstSeen, max(_time) AS lastSeen, values(DNS.src) AS hosts FROM datamodel=Network_Resolution WHERE DNS.query IN ("mailitsippc.com","*.mailitsippc.com","statergie.cn","*.statergie.cn","loyalz.io","*.loyalz.io") BY DNS.query | `drop_dm_object_name(DNS)` | append [| tstats `summariesonly` count, min(_time) AS firstSeen, max(_time) AS lastSeen, values(All_Traffic.src) AS hosts FROM datamodel=Network_Traffic WHERE All_Traffic.dest IN ("mailitsippc.com","statergie.cn","loyalz.io") BY All_Traffic.dest | `drop_dm_object_name(All_Traffic)`] | sort - lastSeen
```

**Defender KQL:**
```kql
let C2 = dynamic(["mailitsippc.com","statergie.cn","loyalz.io"]);
union
  (DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (C2)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Source="DeviceNetworkEvents"),
  (DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | where RemoteUrl has_any (C2) or AdditionalFields has_any (C2)
    | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort=int(null), Source="DeviceEvents-DNS")
| order by Timestamp desc
```

### FortiGate config-export / backup-config from non-baseline admin source

`UC_0_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) AS firstSeen, values(All_Changes.dest) AS appliances, values(All_Changes.src) AS src_ips, values(All_Changes.command) AS commands FROM datamodel=Change WHERE All_Changes.vendor_product="FortiGate" AND (All_Changes.command IN ("execute backup config*","execute backup full-config*","execute backup ipsuserdefsig") OR All_Changes.action IN ("cfg-backup","config-backup")) BY All_Changes.user, All_Changes.src | `drop_dm_object_name(All_Changes)` | join type=left user, src [| tstats `summariesonly` count AS baseline FROM datamodel=Change WHERE All_Changes.vendor_product="FortiGate" earliest=-60d@d latest=-1d@d BY All_Changes.user, All_Changes.src | `drop_dm_object_name(All_Changes)` | rename count AS baseline_count] | where isnull(baseline_count) OR baseline_count<3
```

### Microsoft SQL Server high-volume failed logons (Event 18456) from few sources

`UC_0_7` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Authentication.user) AS distinct_users, values(Authentication.dest) AS targets FROM datamodel=Authentication WHERE Authentication.app="mssql" AND Authentication.action=failure BY Authentication.src, _time span=5m | `drop_dm_object_name(Authentication)` | where count>=200 AND distinct_users>=15 | sort - count
```

**Defender KQL:**
```kql
DeviceLogonEvents
| where Timestamp > ago(1h)
| where ActionType == "LogonFailed"
| where InitiatingProcessFileName =~ "sqlservr.exe" or AdditionalFields has "sqlservr"
| where isnotempty(RemoteIP)
| summarize FailedAttempts = count(),
            DistinctUsers = dcount(AccountName),
            TargetedHosts = make_set(DeviceName, 30),
            SampleUsers = make_set(AccountName, 20)
          by RemoteIP, bin(Timestamp, 5m)
| where FailedAttempts >= 200 and DistinctUsers >= 15
| order by FailedAttempts desc
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
  - IP / domain IOC(s): `mailitsippc.com`, `statergie.cn`, `loyalz.io`, `foxconn.com`, `chevron.com`, `mercedes-benz.com`, `comcast.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
