# [MED] Solana FakeFix Campaign Uses 25 Malicious npm and PyPI Packages to Steal Developer Secrets

**Source:** Cyber Security News
**Published:** 2026-06-12
**Article:** https://cybersecuritynews.com/solana-fakefix-campaign-uses-25-malicious-npm-and-pypi-packages/

## Threat Profile

A newly discovered supply chain campaign is putting Solana developers at serious risk, with attackers hiding malicious code inside fake developer packages on npm and PyPI. The operation, tracked as &#8220;Solana FakeFix,&#8221; deployed 25 malicious packages designed to steal wallet keys, cloud credentials, SSH keys, and developer secrets the moment a package is installed or [&#8230;] The post Solana FakeFix Campaign Uses 25 Malicious npm and PyPI Packages to Steal Developer Secrets appeared fir…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `77.90.185.225`
- **IPv4 (defanged):** `104.239.66.223`
- **Domain (defanged):** `meet-fr.com`
- **Domain (defanged):** `whiteshopify.replit.app`

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
  - IP / domain IOC(s): `77.90.185.225`, `104.239.66.223`, `meet-fr.com`, `whiteshopify.replit.app`


## Why this matters

Severity classified as **MED** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
