# [HIGH] Ubiquiti Patches Critical UniFi OS Vulnerabilities Allowing Remote Privilege Escalation

**Source:** Cyber Security News
**Published:** 2026-05-22
**Article:** https://cybersecuritynews.com/unifi-os-vulnerabilities-privilege-escalation/

## Threat Profile

Home Cyber Security News 
Ubiquiti Patches Critical UniFi OS Vulnerabilities Allowing Remote Privilege Escalation 
By Guru Baran 
May 22, 2026 
Ubiquiti Networks has released urgent security updates to address a series of highly critical vulnerabilities affecting its UniFi OS platform .
These severe flaws could allow unauthenticated, remote attackers to execute arbitrary code, escalate privileges, and severely compromise enterprise network infrastructure.
In total, the hardware vendor patched fi…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-34908`
- **CVE:** `CVE-2026-34909`
- **CVE:** `CVE-2026-34910`
- **CVE:** `CVE-2026-33000`
- **CVE:** `CVE-2026-34911`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1133** — External Remote Services
- **T1021.001** — Remote Desktop Protocol
- **T1021.006** — Windows Remote Management
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable UniFi OS / Network Application present on managed host (UniFi SA-056 CVEs)

`UC_9_5` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-34908","CVE-2026-34909","CVE-2026-34910","CVE-2026-33000","CVE-2026-34911") by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.cvss | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstTime) ctime(lastTime) | sort 0 - cvss
```

**Defender KQL:**
```kql
let UniFiCves = dynamic(["CVE-2026-34908","CVE-2026-34909","CVE-2026-34910","CVE-2026-33000","CVE-2026-34911"]);
let VulnHosts = DeviceTvmSoftwareVulnerabilities
    | where Timestamp > ago(7d)
    | where CveId in (UniFiCves)
    | summarize arg_max(Timestamp, *) by DeviceId, CveId;
let UniFiInventory = DeviceTvmSoftwareInventory
    | where Timestamp > ago(7d)
    | where SoftwareVendor =~ "ubiquiti" or SoftwareName has_any ("unifi","unifi-os","unifi network","unifi controller")
    | summarize arg_max(Timestamp, *) by DeviceId, SoftwareName;
VulnHosts
| join kind=leftouter UniFiInventory on DeviceId
| project Timestamp, DeviceName, DeviceId, CveId, VulnerabilitySeverityLevel, SoftwareVendor, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate, OSPlatform
| order by VulnerabilitySeverityLevel asc, Timestamp desc
```

### [LLM] Internet-facing UniFi management interface exposed (TCP 443/8443/8843/22)

`UC_9_6` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count dc(All_Traffic.src) as src_count values(All_Traffic.src) as sources min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_port IN (443,8443,8843,22) AND All_Traffic.dest_category="unifi" AND NOT (All_Traffic.src IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","100.64.0.0/10")) by All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | where src_count > 0 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let UniFiDevices = DeviceTvmSoftwareInventory
    | where Timestamp > ago(7d)
    | where SoftwareVendor =~ "ubiquiti" or SoftwareName has_any ("unifi","unifi-os")
    | distinct DeviceId, DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("InboundConnectionAccepted","ConnectionInbound")
| where LocalPort in (443, 8443, 8843, 22)
| where RemoteIPType == "Public"
| join kind=inner UniFiDevices on DeviceId
| summarize Hits = count(), DistinctSources = dcount(RemoteIP), Sources = make_set(RemoteIP, 25), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, LocalPort
| order by DistinctSources desc
```

### [LLM] Lateral movement originating from UniFi gateway/controller IP into internal admin assets

`UC_9_7` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count dc(Authentication.dest) as targetCount values(Authentication.dest) as targets values(Authentication.user) as users min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.src_category="unifi_gateway" OR Authentication.src_category="unifi_controller" by Authentication.src Authentication.action | `drop_dm_object_name(Authentication)` | where targetCount >= 1 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let UniFiGatewayIps = dynamic(["<UCG_IP1>","<UDM_IP1>","<UNVR_IP1>"]);
let WindowH = 24h;
let AdminPorts = dynamic([445, 3389, 5985, 5986, 22, 389, 636]);
DeviceLogonEvents
| where Timestamp > ago(WindowH)
| where RemoteIP in (UniFiGatewayIps)
| where LogonType in (3, 10, 7)
| where AccountName !endswith "$"
| summarize Logons = count(), DistinctTargets = dcount(DeviceName), Targets = make_set(DeviceName, 25), Accounts = make_set(AccountName, 10), LogonTypes = make_set(LogonType), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by RemoteIP
| union (
  DeviceNetworkEvents
  | where Timestamp > ago(WindowH)
  | where ActionType in ("InboundConnectionAccepted","ConnectionInbound")
  | where RemoteIP in (UniFiGatewayIps)
  | where LocalPort in (AdminPorts)
  | summarize Logons = count(), DistinctTargets = dcount(DeviceName), Targets = make_set(DeviceName, 25), Accounts = make_set("network-only"), LogonTypes = make_set(LocalPort), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by RemoteIP
)
| where DistinctTargets >= 2 or Logons >= 5
| order by DistinctTargets desc
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
  - CVE(s): `CVE-2026-34908`, `CVE-2026-34909`, `CVE-2026-34910`, `CVE-2026-33000`, `CVE-2026-34911`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
