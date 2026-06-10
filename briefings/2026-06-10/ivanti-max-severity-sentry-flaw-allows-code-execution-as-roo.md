# [HIGH] Ivanti: Max severity Sentry flaw allows code execution as root

**Source:** BleepingComputer
**Published:** 2026-06-10
**Article:** https://www.bleepingcomputer.com/news/security/new-max-severity-ivanti-sentry-flaw-allows-code-execution-as-root/

## Threat Profile

Ivanti: Max severity Sentry flaw allows code execution as root 
By Sergiu Gatlan 
June 10, 2026
02:26 AM
0 
Security software company Ivanti has released patches to address two critical vulnerabilities in its Sentry secure mobile gateway solution, including a maximum-severity flaw that enables remote attackers to execute code with root privileges.
Formerly known as MobileIron Sentry, Ivanti Sentry is a security gateway appliance that secures traffic between back-end corporate systems and remote …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-10520`
- **CVE:** `CVE-2026-10523`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1133** — External Remote Services
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unpatched Ivanti Sentry exposing CVE-2026-10520 / CVE-2026-10523

`UC_28_4` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Vulnerabilities.signature) as signature values(Vulnerabilities.severity) as severity from datamodel=Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-10520","CVE-2026-10523") by Vulnerabilities.dest, Vulnerabilities.cve | `drop_dm_object_name("Vulnerabilities")` | eval product="Ivanti Sentry (MobileIron Sentry)", fixed_in="R10.5.2 / R10.6.2 / R10.7.1" | convert ctime(firstSeen) ctime(lastSeen) | sort 0 - lastSeen
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-10520","CVE-2026-10523")
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, OSPlatform, PublicIP, IsInternetFacing) by DeviceId) on DeviceId
| project Timestamp, DeviceName, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, IsInternetFacing, PublicIP
| sort by IsInternetFacing desc, Timestamp desc
```

### Pre-auth command-injection probes against Ivanti Sentry /mics endpoint (CVE-2026-10520)

`UC_28_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.http_method) as methods values(Web.http_user_agent) as user_agents values(Web.status) as statuses from datamodel=Web where Web.url="*/mics/*" AND (Web.url="*%3B*" OR Web.url="*%7C*" OR Web.url="*%26%26*" OR Web.url="*%60*" OR Web.url="*%24%28*" OR Web.url="*%24%7BIFS%7D*" OR Web.url="*${IFS}*" OR Web.url="*$(*" OR Web.url="*whoami*" OR Web.url="*;id*" OR Web.url="*/bin/sh*" OR Web.url="*/bin/bash*" OR Web.url="*wget *" OR Web.url="*curl *" OR Web.url="*nc *" OR Web.url="*busybox*") by Web.src, Web.dest, Web.url | `drop_dm_object_name("Web")` | convert ctime(firstTime) ctime(lastTime) | sort 0 - lastTime
```

### Anomalous outbound from Ivanti Sentry appliance subnet (post-RCE hunt)

`UC_28_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count earliest(_time) as firstSeen latest(_time) as lastSeen values(All_Traffic.dest_port) as ports values(All_Traffic.app) as apps from datamodel=Network_Traffic where [| inputlookup ivanti_sentry_assets.csv | rename ip as src | fields src] AND All_Traffic.dest_category="external" AND All_Traffic.action="allowed" by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port | `drop_dm_object_name("All_Traffic")` | search NOT [| tstats summariesonly=true count from datamodel=Network_Traffic where earliest=-30d@d latest=-1d@d [| inputlookup ivanti_sentry_assets.csv | rename ip as src | fields src] AND All_Traffic.dest_category="external" by All_Traffic.dest | `drop_dm_object_name("All_Traffic")` | fields dest] | convert ctime(firstSeen) ctime(lastSeen) | sort 0 - firstSeen
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
  - CVE(s): `CVE-2026-10520`, `CVE-2026-10523`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
