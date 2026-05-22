# [HIGH] Max severity Cisco Secure Workload flaw gives Site Admin privileges

**Source:** BleepingComputer
**Published:** 2026-05-21
**Article:** https://www.bleepingcomputer.com/news/security/cisco-max-severity-secure-workload-flaw-gives-hackers-site-admin-privileges/

## Threat Profile

Max severity Cisco Secure Workload flaw gives Site Admin privileges 
By Sergiu Gatlan 
May 21, 2026
09:58 AM
0 
Cisco has released security updates to address a maximum-severity Secure Workload vulnerability that allows attackers to gain Site Admin privileges.
Formerly known as Cisco Tetration, Cisco Secure Workload helps admins reduce their network's attack surface through zero trust microsegmentation and stop lateral movement to keep business applications safe.
Tracked as CVE-2026-20223 , the …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-20223`
- **CVE:** `CVE-2026-20182`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1592.002** — Gather Victim Host Information: Software
- **T1068** — Exploitation for Privilege Escalation
- **T1078.001** — Valid Accounts: Default Accounts
- **T1133** — External Remote Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable Cisco Secure Workload version present in asset fleet (CVE-2026-20223)

`UC_36_5` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2026-20223" OR (Vulnerabilities.signature="*Secure Workload*" OR Vulnerabilities.signature="*Tetration*") by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.cve, Vulnerabilities.severity | `drop_dm_object_name(Vulnerabilities)` | eval needs_patch=case(like(signature,"%3.10.%") AND NOT like(signature,"%3.10.8.3%"),"upgrade-to-3.10.8.3", like(signature,"%4.0.%") AND NOT like(signature,"%4.0.3.17%"),"upgrade-to-4.0.3.17", like(signature,"%3.9%"),"migrate-off-3.9-and-earlier", true(),"verify-version") | `convert ctime(firstTime)` | `convert ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(7d)
| where CveId =~ "CVE-2026-20223"
    or (SoftwareVendor =~ "cisco" and (SoftwareName has_any ("secure workload","tetration")))
| join kind=leftouter (
    DeviceTvmSoftwareInventory
    | where Timestamp > ago(7d)
    | where SoftwareVendor =~ "cisco" and SoftwareName has_any ("secure workload","tetration")
    | project DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion
  ) on DeviceId
| extend NeedsPatch = case(
    SoftwareVersion startswith "3.9" or SoftwareVersion startswith "3.8" or SoftwareVersion startswith "3.7", "migrate-off-3.9-and-earlier",
    SoftwareVersion startswith "3.10" and SoftwareVersion != "3.10.8.3" and not(SoftwareVersion matches regex @"^3\.10\.([89]|1[0-9])\."), "upgrade-to-3.10.8.3",
    SoftwareVersion startswith "4.0" and SoftwareVersion != "4.0.3.17" and not(SoftwareVersion matches regex @"^4\.0\.([4-9]|1[0-9])\."), "upgrade-to-4.0.3.17",
    "verify-version"
  )
| project Timestamp, DeviceId, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, NeedsPatch
| order by DeviceName asc
```

### [LLM] Cisco Secure Workload Site Admin action crossing tenant boundary in a single session

`UC_36_6` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Change.object) as distinct_tenants, values(Change.object) as tenants, values(Change.action) as actions, values(Change.src) as src_list, min(_time) as firstTime, max(_time) as lastTime from datamodel=Change where Change.vendor_product="Cisco Secure Workload" OR Change.vendor_product="Cisco Tetration" (Change.user_role="Site Admin" OR Change.user_role="SITE_ADMIN" OR Change.change_type="site_admin_*") by Change.user, Change.src, _time span=10m | `drop_dm_object_name(Change)` | where distinct_tenants >= 2 | `convert ctime(firstTime)` | `convert ctime(lastTime)`
```

### [LLM] Anomalous unauthenticated REST access to Cisco Secure Workload appliance from non-management subnet

`UC_36_7` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(All_Traffic.src) as src_count, values(All_Traffic.src) as src_ips, values(All_Traffic.dest_port) as dest_ports, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("$secure_workload_appliances$") OR All_Traffic.dest_category="cisco_secure_workload") All_Traffic.dest_port IN (443, 8443, 9443) NOT (All_Traffic.src_category="management_subnet" OR All_Traffic.src IN ("$management_subnet_cidrs$")) by All_Traffic.dest, All_Traffic.src, All_Traffic.app, _time span=5m | `drop_dm_object_name(All_Traffic)` | `convert ctime(firstTime)` | `convert ctime(lastTime)` | sort - count
```

**Defender KQL:**
```kql
let SecureWorkloadAppliances = dynamic(["REPLACE.WITH.APPLIANCE.IPs"]);
let ManagementSubnets = dynamic(["10.10.10.0/24","10.10.11.0/24"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","InboundConnectionAccepted")
| where RemoteIP in (SecureWorkloadAppliances)
| where RemotePort in (443, 8443, 9443)
| where not(ipv4_is_in_any_range(LocalIP, ManagementSubnets))
| extend ApiHintFromCmd = case(
    InitiatingProcessCommandLine has_any ("/openapi","/api/v1","/internal","/sw/api"), "api_path_in_cmd",
    "none"
  )
| summarize
    ConnCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    DistinctAppliances = dcount(RemoteIP),
    Appliances = make_set(RemoteIP, 10),
    SampleCmd = any(InitiatingProcessCommandLine),
    SampleProcess = any(InitiatingProcessFileName)
    by DeviceId, DeviceName, LocalIP, InitiatingProcessAccountName, ApiHintFromCmd
| where InitiatingProcessAccountName !endswith "$"
| order by LastSeen desc
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-20223`, `CVE-2026-20182`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
