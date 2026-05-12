# [HIGH] SAST vs SCA: Securing the Code You Write and the Code You Depend On

**Source:** Aikido
**Published:** 2026-01-06
**Article:** https://www.aikido.dev/blog/sast-vs-sca

## Threat Profile

Blog Technical SAST vs SCA: Securing the Code You Write and the Code You Depend On SAST vs SCA: Securing the Code You Write and the Code You Depend On Written by Divine Odazie Published on: Jan 6, 2026 The more code you write, the less secure your application becomes. 
Why? In one word, complexity. 
Modern applications aren’t written from scratch. They are assembled. Developers write custom logic on top of open-source frameworks, libraries, container images, and cloud services. That means securi…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-23343`
- **CVE:** `CVE-2025-9900`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain

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
  - CVE(s): `CVE-2021-23343`, `CVE-2025-9900`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
