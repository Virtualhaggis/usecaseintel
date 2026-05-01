# [CRIT] Critical Wireshark Vulnerabilities Let Attackers Execute Arbitrary Code Via Malformed Packets

**Source:** Cyber Security News
**Published:** 2026-05-01
**Article:** https://cybersecuritynews.com/wireshark-vulnerabilities-code-execution/

## Threat Profile

Home Cyber Security News 
Critical Wireshark Vulnerabilities Let Attackers Execute Arbitrary Code Via Malformed Packets 
By Guru Baran 
May 1, 2026 
Wireshark , the world’s most widely used open-source network protocol analyzer, has released a major security update addressing over 40 vulnerabilities, several of which enable arbitrary code execution through malformed packet injection or malicious capture files.
Organizations and individuals relying on Wireshark for network monitoring, forensics, …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-5402`
- **CVE:** `CVE-2026-5403`
- **CVE:** `CVE-2026-5405`
- **CVE:** `CVE-2026-5656`
- **CVE:** `CVE-2026-5409`
- **CVE:** `CVE-2026-5408`
- **CVE:** `CVE-2026-5406`
- **CVE:** `CVE-2026-5299`
- **CVE:** `CVE-2026-5401`
- **CVE:** `CVE-2026-5404`
- **CVE:** `CVE-2026-5654`
- **CVE:** `CVE-2026-5655`
- **CVE:** `CVE-2026-5657`
- **CVE:** `CVE-2026-6529`
- **CVE:** `CVE-2026-5653`
- **CVE:** `CVE-2026-6530`
- **CVE:** `CVE-2026-6538`
- **CVE:** `CVE-2026-6537`
- **CVE:** `CVE-2026-6532`
- **CVE:** `CVE-2026-6527`
- **CVE:** `CVE-2026-6526`
- **CVE:** `CVE-2026-6525`
- **CVE:** `CVE-2026-6524`
- **CVE:** `CVE-2026-6870`
- **CVE:** `CVE-2026-6869`
- **CVE:** `CVE-2026-6868`
- **CVE:** `CVE-2026-5407`
- **CVE:** `CVE-2026-6536`
- **CVE:** `CVE-2026-6534`
- **CVE:** `CVE-2026-6531`
- **CVE:** `CVE-2026-6523`
- **CVE:** `CVE-2026-6521`
- **CVE:** `CVE-2026-6520`
- **CVE:** `CVE-2026-6519`
- **CVE:** `CVE-2026-6522`
- **CVE:** `CVE-2026-6528`
- **CVE:** `CVE-2026-6535`
- **CVE:** `CVE-2026-6533`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1053.005** — Scheduled Task
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 1m)
| where files > 200
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
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-5402`, `CVE-2026-5403`, `CVE-2026-5405`, `CVE-2026-5656`, `CVE-2026-5409`, `CVE-2026-5408`, `CVE-2026-5406`, `CVE-2026-5299` _(+30 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
