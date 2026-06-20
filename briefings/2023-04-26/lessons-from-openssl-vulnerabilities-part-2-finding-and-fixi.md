# [CRIT] Lessons from OpenSSL vulnerabilities part 2: Finding and fixing supply chain vulnerabilities

**Source:** Snyk
**Published:** 2023-04-26
**Article:** https://snyk.io/blog/lessons-from-openssl-vulnerabilities-part-2/

## Threat Profile

Snyk Blog In this article
Written by Jamie Smith 
April 26, 2023
0 mins read This supply chain series centers on the lessons learned from OpenSSL and what you need to consider when enhancing your supply chain security. While this series will focus on OpenSSL and relevant libraries, we'll also consider vulnerabilities across the board. In the first installment , we covered everything you need to know about where to look for vulnerable libraries. Let’s dive into part two and discuss how to find — …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-3602`
- **CVE:** `CVE-2022-3786`
- **SHA256:** `ba96f963bbfd429a0839c40603fdd7829eaca58f20adfa0d15e6beae8244bc08`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-3602`, `CVE-2022-3786`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ba96f963bbfd429a0839c40603fdd7829eaca58f20adfa0d15e6beae8244bc08`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
