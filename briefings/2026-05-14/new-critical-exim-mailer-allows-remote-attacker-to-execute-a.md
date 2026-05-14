# [HIGH] New Critical Exim Mailer Allows Remote Attacker to Execute Arbitrary Code

**Source:** Cyber Security News
**Published:** 2026-05-14
**Article:** https://cybersecuritynews.com/exim-mailer-arbitrary-code-execution/

## Threat Profile

Home Cyber Security News 
New Critical Exim Mailer Allows Remote Attacker to Execute Arbitrary Code 
By Abinaya 
May 14, 2026 
A critical vulnerability in the widely used Exim mail server allows unauthenticated attackers to execute arbitrary code and fully compromise exposed servers.
Federico Kirschbaum, head of the Security Lab at XBOW, discovered and reported the issue, which has been dubbed Dead.Letter.
The vulnerability carries a massive CVSS severity score of 9.8, making it one of the highe…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45185`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1592.002** — Gather Victim Host Information: Software
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1068** — Exploitation for Privilege Escalation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable Exim 4.97–4.99.2 (GnuTLS build) inventory — CVE-2026-45185 Dead.Letter

`UC_32_2` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.cve="CVE-2026-45185" OR (Vulnerabilities.signature="exim*" AND Vulnerabilities.severity="critical")) by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.category | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstSeen) ctime(lastSeen) | sort - lastSeen
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2026-45185"
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform, OSDistribution, OSVersion, IsInternetFacing, MachineGroup) by DeviceId
  ) on DeviceId
| project DeviceName, OSPlatform, OSDistribution, OSVersion, IsInternetFacing,
          SoftwareVendor, SoftwareName, SoftwareVersion,
          VulnerabilitySeverityLevel, RecommendedSecurityUpdate, MachineGroup
| order by IsInternetFacing desc, DeviceName asc
```

### [LLM] Exim mail daemon spawning shell or network LOLBin — CVE-2026-45185 Dead.Letter post-exploit

`UC_32_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("exim","exim4") AND Processes.process_name IN ("sh","bash","dash","zsh","ash","nc","ncat","curl","wget","python","python3","perl","ruby","socat","busybox","awk") by Processes.dest Processes.user Processes.parent_process Processes.parent_process_name Processes.process Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("exim","exim4")
   or InitiatingProcessFolderPath has_any ("/usr/sbin/exim4","/usr/sbin/exim","/usr/exim/bin/exim")
| where FileName in~ ("sh","bash","dash","zsh","ash","nc","ncat","curl","wget","python","python3","perl","ruby","socat","busybox","awk")
| where InitiatingProcessAccountName in~ ("Debian-exim","exim","mail","mailnull","root")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — New Critical Exim Mailer Allows Remote Attacker to Execute Arbitrary Code

`UC_32_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New Critical Exim Mailer Allows Remote Attacker to Execute Arbitrary Code ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New Critical Exim Mailer Allows Remote Attacker to Execute Arbitrary Code
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-45185`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
