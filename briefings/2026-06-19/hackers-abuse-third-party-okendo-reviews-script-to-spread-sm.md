# [MED] Hackers Abuse Third-Party Okendo Reviews Script to Spread SmartApeSG Malware Campaign

**Source:** Cyber Security News
**Published:** 2026-06-19
**Article:** https://cybersecuritynews.com/hackers-abuse-third-party-okendo-reviews-script/

## Threat Profile

A newly discovered supply chain attack has put thousands of e-commerce websites at risk after a popular third-party reviews widget was quietly turned into a malware delivery tool. Threat actors behind the SmartApeSG campaign injected malicious JavaScript into the Okendo Reviews widget, a platform trusted by more than 18,000 brands worldwide, to push malware to [&#8230;] The post Hackers Abuse Third-Party Okendo Reviews Script to Spread SmartApeSG Malware Campaign appeared first on Cyber Security…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `wigetticks.com`
- **Domain (defanged):** `wizzleticks.com`
- **Domain (defanged):** `api.wigetticks.com`
- **Domain (defanged):** `api.wizzleticks.com`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol

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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `wigetticks.com`, `wizzleticks.com`, `api.wigetticks.com`, `api.wizzleticks.com`


## Why this matters

Severity classified as **MED** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
