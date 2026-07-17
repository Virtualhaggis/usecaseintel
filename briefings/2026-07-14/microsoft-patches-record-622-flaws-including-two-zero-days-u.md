# [CRIT] Microsoft Patches Record 622 Flaws, Including Two Zero-Days Under Active Attack

**Source:** The Hacker News, Cisco Talos
**Published:** 2026-07-14
**Article:** https://thehackernews.com/2026/07/microsoft-patches-record-622-flaws.html

## Threat Profile

Microsoft Patches Record 622 Flaws, Including Two Zero-Days Under Active Attack 
 Swati Khandelwal  Jul 14, 2026 Vulnerability / Enterprise Security 
Microsoft shipped its largest Patch Tuesday on record today, and two of the fixes close holes that attackers are already exploiting. The release covers 622 of Microsoft's own CVEs by its Security Update Guide count, more than triple June's previous high of around 200 .
Those two live bugs are the ones to grab first. Microsoft credits incident res…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-56164`
- **CVE:** `CVE-2026-56155`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1068** — Exploitation for Privilege Escalation
- **T1505.003** — Server Software Component: Web Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Exposure hunt: hosts still vulnerable to actively-exploited July 2026 zero-days (AD FS CVE-2026-56155 / SharePoint CVE-2026-56164)

`UC_59_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

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

`UC_59_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-56164`, `CVE-2026-56155`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
