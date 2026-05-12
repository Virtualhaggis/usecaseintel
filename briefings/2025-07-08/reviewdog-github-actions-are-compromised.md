# [MED] reviewdog GitHub Actions are compromised

**Source:** StepSecurity
**Published:** 2025-07-08
**Article:** https://www.stepsecurity.io/blog/reviewdog-github-actions-are-compromised

## Threat Profile

Back to Blog Threat Intel reviewdog GitHub Actions are compromised The supply chain compromise of reviewdog GitHub Actions has been resolved. This post summarizes the incident, how it was discovered, and what you should do to protect your workflows Varun Sharma View LinkedIn March 18, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Introduction We have concluded our investigation into the supply chain attack affecting several …

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `f0d342d24037bb11d26b9bd8496e0808ba32e9ec`
- **SHA1:** `fab6de28ae8bc2a032c9e655d990afa450edb995`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `f0d342d24037bb11d26b9bd8496e0808ba32e9ec`, `fab6de28ae8bc2a032c9e655d990afa450edb995`


## Why this matters

Severity classified as **MED** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
