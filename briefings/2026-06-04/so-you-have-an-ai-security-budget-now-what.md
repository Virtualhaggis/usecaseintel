# [HIGH] So You Have an AI Security Budget. Now what?

**Source:** Snyk
**Published:** 2026-06-04
**Article:** https://snyk.io/blog/ai-security-budget/

## Threat Profile

Snyk Blog In this article
Written by Snyk Team 
June 4, 2026
0 mins read Key takeaways AI security budgets need to evolve from fragmented tool spending into a unified investment in visibility, governance, and control across the full AI lifecycle. 
Organizations should budget for two connected fronts: securing agentic development, where AI agents generate code, use tools, and execute workflows, and securing agentic applications, where agents interact with users, data, APIs, and production systems…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-6514`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1203** — Exploitation for Client Execution
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### mcp-remote OAuth authorization_endpoint RCE (CVE-2025-6514) — node spawning shell

`UC_137_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="node.exe" AND Processes.parent_process="*mcp-remote*" AND (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="cmd.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where InitiatingProcessCommandLine has "mcp-remote"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentCmd  = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd   = ProcessCommandLine,
          SHA256, InitiatingProcessSHA256
| order by Timestamp desc
```

### Vulnerable mcp-remote (CVE-2025-6514) version present on hosts

`UC_137_3` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2025-6514" OR (Vulnerabilities.signature="mcp-remote" AND Vulnerabilities.severity IN ("critical","high")) by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.cve | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstSeen) ctime(lastSeen) | sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId =~ "CVE-2025-6514"
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, OSPlatform, PublicIP, LoggedOnUsers) by DeviceId) on DeviceId
| project DeviceId, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion,
          VulnerabilitySeverityLevel, RecommendedSecurityUpdate, LoggedOnUsers, PublicIP
| order by VulnerabilitySeverityLevel asc, DeviceName asc
```

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-6514`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
