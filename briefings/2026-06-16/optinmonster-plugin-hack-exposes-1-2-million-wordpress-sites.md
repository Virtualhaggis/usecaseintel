# [MED] OptinMonster Plugin Hack Exposes 1.2 Million WordPress Sites to Cyberattack

**Source:** Cyber Security News
**Published:** 2026-06-16
**Article:** https://cybersecuritynews.com/optinmonster-plugin-exposes-wordpress-sites/

## Threat Profile

A large-scale supply chain attack targeting widely used WordPress plugins has exposed more than 1.2 million websites to potential compromise after attackers injected malicious code into legitimate JavaScript files distributed through trusted CDN infrastructure. Security researchers at Sansec discovered an ongoing campaign targeting plugins developed by Awesome Motive, including OptinMonster, TrustPulse, and PushEngage. These plugins [&#8230;] The post OptinMonster Plugin Hack Exposes 1.2 Million…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `84.201.6.54`
- **Domain (defanged):** `tidio.cc`
- **Domain (defanged):** `a.omappapi.com`
- **Domain (defanged):** `a.opmnstr.com`
- **Domain (defanged):** `a.optnmstr.com`
- **Domain (defanged):** `a.trstplse.com`
- **Domain (defanged):** `clientcdn.pushengage.com`

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
  - IP / domain IOC(s): `84.201.6.54`, `tidio.cc`, `a.omappapi.com`, `a.opmnstr.com`, `a.optnmstr.com`, `a.trstplse.com`, `clientcdn.pushengage.com`


## Why this matters

Severity classified as **MED** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
