# [CRIT] Copy Fail: What You Need to Know About the Most Severe Linux Threat in Years

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-05-05
**Article:** https://unit42.paloaltonetworks.com/cve-2026-31431-copy-fail/

## Threat Profile

Threat Research Center 
High Profile Threats 
Vulnerabilities 
Vulnerabilities 
Copy Fail: What You Need to Know About the Most Severe Linux Threat in Years 
6 min read 
Related Products Cortex Cortex Cloud Cortex XDR Cortex XSIAM Unit 42 Incident Response 
By: Justin Moore 
Published: May 5, 2026 
Categories: High Profile Threats 
Vulnerabilities 
Tags: Containers 
CVE-2026-31431 
Kubernetes 
Linux 
Local privilege escalation 
Page cache 
Vulnerability 
Executive Summary 
On April 29, 2026, res…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-31431`
- **CVE:** `CVE-2026-314331`
- **CVE:** `CVE-2023-33538`
- **CVE:** `CVE-2026-1731`
- **CVE:** `CVE-2026-1281`
- **CVE:** `CVE-2026-1340`
- **CVE:** `CVE-2025-0921`
- **CVE:** `CVE-2025-14847`
- **CVE:** `CVE-2025-23304`
- **CVE:** `CVE-2026-22584`
- **CVE:** `CVE-2025-55182`
- **CVE:** `CVE-2025-66478`
- **CVE:** `CVE-2025-21042`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1105** — Ingress Tool Transfer
- **T1588.005** — Obtain Capabilities: Exploits
- **T1068** — Exploitation for Privilege Escalation
- **T1611** — Escape to Host
- **T1548.003** — Abuse Elevation Control Mechanism: Sudo and Sudo Caching

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Copy Fail (CVE-2026-31431) PoC retrieval from copy.fail/exp

`UC_199_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as commands values(Processes.parent_process_name) as parents values(Processes.process_path) as image_paths from datamodel=Endpoint.Processes where Processes.os=Linux Processes.process_name IN ("curl","wget","python","python2","python3","python3.8","python3.9","python3.10","python3.11","python3.12") Processes.process="*copy.fail*" by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFolderPath has "/" or FolderPath has "/"   // crude Linux scope
| where (FileName in~ ("curl","wget","python","python2","python3","python3.8","python3.9","python3.10","python3.11","python3.12")
         and ProcessCommandLine has "copy.fail")
     or (InitiatingProcessFileName in~ ("curl","wget","python","python2","python3","python3.8","python3.9","python3.10","python3.11","python3.12")
         and InitiatingProcessCommandLine has "copy.fail")
| project Timestamp, DeviceName, AccountName, AccountSid,
          FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] Copy Fail (CVE-2026-31431) - Python interpreter spawning su/sudo/passwd as non-root

`UC_199_6` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as child_cmds values(Processes.parent_process) as parent_cmds values(Processes.process_path) as child_paths values(Processes.parent_process_path) as parent_paths from datamodel=Endpoint.Processes where Processes.os=Linux Processes.parent_process_name IN ("python","python2","python3","python3.6","python3.7","python3.8","python3.9","python3.10","python3.11","python3.12") Processes.process_name IN ("su","sudo","passwd") Processes.user!="root" Processes.user!="0" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName matches regex @"(?i)^python(\d(\.\d+)?)?$"
| where FileName in~ ("su","sudo","passwd")
| where AccountName !in~ ("root")
| where AccountSid != "0"
| project Timestamp, DeviceName, AccountName, AccountSid,
          ChildBin = FileName, ChildCmd = ProcessCommandLine,
          ParentBin = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ParentPath = InitiatingProcessFolderPath,
          GrandParent = InitiatingProcessParentFileName
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

### Article-specific behavioural hunt — Copy Fail: What You Need to Know About the Most Severe Linux Threat in Years

`UC_199_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Copy Fail: What You Need to Know About the Most Severe Linux Threat in Years ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/su*" OR Filesystem.file_path="*/etc/modprobe.d/disable-algif.conf*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Copy Fail: What You Need to Know About the Most Severe Linux Threat in Years
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/su", "/etc/modprobe.d/disable-algif.conf"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-31431`, `CVE-2026-314331`, `CVE-2023-33538`, `CVE-2026-1731`, `CVE-2026-1281`, `CVE-2026-1340`, `CVE-2025-0921`, `CVE-2025-14847` _(+5 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
