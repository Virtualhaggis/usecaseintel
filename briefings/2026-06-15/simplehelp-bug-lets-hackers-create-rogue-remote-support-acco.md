# [HIGH] SimpleHelp bug lets hackers create rogue remote support accounts

**Source:** BleepingComputer
**Published:** 2026-06-15
**Article:** https://www.bleepingcomputer.com/news/security/simplehelp-bug-lets-hackers-create-rogue-remote-support-accounts/

## Threat Profile

SimpleHelp bug lets hackers create rogue remote support accounts 
By Bill Toulas 
June 15, 2026
04:06 PM
0 
A vulnerability in the SimpleHelp remote management software allows unauthenticated attackers to create privileged technician accounts on servers using the OpenID Connect (OIDC) authentication protocol.
The flaw is tracked as CVE-2026-48558 and received a critical severity rating. It impacts SimpleHelp versions 5.5.15 and older, as well as 6.0 pre-release versions.
Researchers at offensive…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-48558`
- **Domain (defanged):** `horizon3.ai`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1136.001** — Create Account: Local Account
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1219** — Remote Access Software
- **T1059** — Command and Scripting Interpreter
- **T1072** — Software Deployment Tools
- **T1133** — External Remote Services
- **T1098** — Account Manipulation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Rogue SimpleHelp Technician account created via OIDC bypass (CVE-2026-48558)

`UC_33_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Authentication.src) as src values(Authentication.user) as user values(Authentication.signature) as signature from datamodel=Authentication where Authentication.app="SimpleHelp" (Authentication.signature IN ("TechnicianCreated","TechnicianRegistered","OIDCLogin","technician_added") OR Authentication.action="success") Authentication.authentication_method="OIDC" by Authentication.user Authentication.src Authentication.dest | `drop_dm_object_name(Authentication)` | where firstSeen >= relative_time(now(),"-7d") | eval suspicious=if(match(user, "(?i)(test|admin[0-9]+|temp|qa|root|svc)") OR len(user)<4 OR match(user,"^[a-z0-9]{8,}$"),1,0)
```

### SimpleHelp 'Remote Access.exe' spawning script interpreters on managed endpoints

`UC_33_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Processes.process) as cmdlines values(Processes.process_name) as childExes values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name="Remote Access.exe" Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","bash.exe","sh.exe") by Processes.dest Processes.parent_process Processes.parent_process_path | `drop_dm_object_name(Processes)` | where firstSeen >= relative_time(now(),"-7d")
```

**Defender KQL:**
```kql
let Lookback = 7d;
let Lolbins = dynamic(["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","bash.exe","sh.exe"]);
DeviceProcessEvents
| where Timestamp > ago(Lookback)
| where InitiatingProcessFileName =~ "Remote Access.exe"
| where InitiatingProcessVersionInfoCompanyName has_any ("SimpleHelp", "SimpleHelp LTD") or InitiatingProcessFolderPath has "SimpleHelp"
| where FileName in~ (Lolbins)
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          ChildSHA256 = SHA256
| order by Timestamp desc
```

### Internet-exposed SimpleHelp servers vulnerable to CVE-2026-48558

`UC_33_6` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Vulnerabilities.severity) as severity values(Vulnerabilities.signature) as signature values(Vulnerabilities.vendor_product) as product from datamodel=Vulnerabilities where (Vulnerabilities.cve="CVE-2026-48558" OR (Vulnerabilities.vendor_product="SimpleHelp" AND Vulnerabilities.signature="SimpleHelp" AND Vulnerabilities.severity="critical")) by Vulnerabilities.dest | `drop_dm_object_name(Vulnerabilities)`
```

**Defender KQL:**
```kql
let Vulnerable = DeviceTvmSoftwareVulnerabilities
    | where CveId == "CVE-2026-48558"
    | summarize arg_max(Timestamp, *) by DeviceId;
let Exposed = DeviceInfo
    | summarize arg_max(Timestamp, IsInternetFacing, PublicIP, OSPlatform) by DeviceId;
Vulnerable
| join kind=leftouter Exposed on DeviceId
| project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion,
          CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, IsInternetFacing, PublicIP
| order by IsInternetFacing desc, Timestamp desc
```

### Newly created SimpleHelp Technician immediately exercises privileged actions

`UC_33_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true min(_time) as createTime from datamodel=Authentication where Authentication.app="SimpleHelp" Authentication.signature IN ("TechnicianCreated","TechnicianRegistered","technician_added") by Authentication.user
| `drop_dm_object_name(Authentication)`
| rename user as suspectUser
| join type=inner suspectUser [
    | tstats summariesonly=true min(_time) as actionTime values(Authentication.action) as actions values(Authentication.src) as srcIPs values(Authentication.dest) as targets from datamodel=Authentication where Authentication.app="SimpleHelp" Authentication.signature IN ("RemoteSessionStarted","ScriptExecuted","TechnicianGroupModified","ConfigChanged","PrivilegeChanged") by Authentication.user
    | `drop_dm_object_name(Authentication)`
    | rename user as suspectUser ]
| eval delaySec=actionTime-createTime
| where delaySec >= 0 AND delaySec <= 900
| convert ctime(createTime) ctime(actionTime)
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

### Article-specific behavioural hunt — SimpleHelp bug lets hackers create rogue remote support accounts

`UC_33_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — SimpleHelp bug lets hackers create rogue remote support accounts ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/opt/SimpleHelp/logs/server.log*" OR Filesystem.file_path="*/opt/SimpleHelp/logs/*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — SimpleHelp bug lets hackers create rogue remote support accounts
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/opt/SimpleHelp/logs/server.log", "/opt/SimpleHelp/logs/"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `horizon3.ai`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-48558`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 8 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
