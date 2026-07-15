# [CRIT] Microsoft Patches Record 622 Flaws, Including Two Zero-Days Under Active Attack

**Source:** The Hacker News, BleepingComputer, Cisco Talos
**Published:** 2026-07-14
**Article:** https://thehackernews.com/2026/07/microsoft-patches-record-622-flaws.html

## Threat Profile

Microsoft July 2026 Patch Tuesday fixes massive 570 flaws, 3 zero-days 
By Lawrence Abrams 
July 14, 2026
02:01 PM
0 
Today is Microsoft's July 2026 Patch Tuesday, and with it comes security updates for a record-breaking 570 flaws, including two zero-day vulnerabilities exploited in attacks and one publicly disclosed.
Patch Tuesday addresses 59 "Critical" vulnerabilities, 48 of which are remote code execution, 9 are elevation of privilege, 1 is a security bypass, and 1 is a spoofing.
The approxi…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-56155`
- **CVE:** `CVE-2026-56164`
- **CVE:** `CVE-2026-50661`
- **CVE:** `CVE-2026-48282`
- **CVE:** `CVE-2026-20230`

## MITRE ATT&CK Techniques

- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1068** — Exploitation for Privilege Escalation
- **T1505.003** — Server Software Component: Web Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Exposure hunt: hosts still vulnerable to actively-exploited July 2026 zero-days (AD FS CVE-2026-56155 / SharePoint CVE-2026-56164)

`UC_12_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.signature IN ("CVE-2026-56155","CVE-2026-56164") OR Vulnerabilities.cve IN ("CVE-2026-56155","CVE-2026-56164")) by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.category | `drop_dm_object_name(Vulnerabilities)` | sort - count
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId in ("CVE-2026-56155","CVE-2026-56164")
| summarize LastSeen=max(Timestamp), CVEs=make_set(CveId) by DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate
| order by LastSeen desc
```

### SharePoint IIS worker (w3wp.exe) spawning a command interpreter — post-exploitation of CVE-2026-56164

`UC_12_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="w3wp.exe" AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","cscript.exe","wscript.exe","net.exe","net1.exe","whoami.exe") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where InitiatingProcessCommandLine has "SharePoint"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","cscript.exe","wscript.exe","net.exe","net1.exe","whoami.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
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

### Article-specific behavioural hunt — Microsoft Patches Record 622 Flaws, Including Two Zero-Days Under Active Attack

`UC_12_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft Patches Record 622 Flaws, Including Two Zero-Days Under Active Attack ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("ci.dll","cimfs.sys","ipnathlp.dll","upnp.dll","unionfs.sys","data.dll","http.sys","srvnet.sys","spaceport.sys","usbaudio.sys"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("ci.dll","cimfs.sys","ipnathlp.dll","upnp.dll","unionfs.sys","data.dll","http.sys","srvnet.sys","spaceport.sys","usbaudio.sys"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Microsoft Patches Record 622 Flaws, Including Two Zero-Days Under Active Attack
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("ci.dll", "cimfs.sys", "ipnathlp.dll", "upnp.dll", "unionfs.sys", "data.dll", "http.sys", "srvnet.sys", "spaceport.sys", "usbaudio.sys"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("ci.dll", "cimfs.sys", "ipnathlp.dll", "upnp.dll", "unionfs.sys", "data.dll", "http.sys", "srvnet.sys", "spaceport.sys", "usbaudio.sys"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-56155`, `CVE-2026-56164`, `CVE-2026-50661`, `CVE-2026-48282`, `CVE-2026-20230`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
