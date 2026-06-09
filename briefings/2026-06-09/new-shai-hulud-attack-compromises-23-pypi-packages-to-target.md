# [HIGH] New Shai-Hulud Attack Compromises 23 PyPI Packages to Target MCP Developers

**Source:** Cyber Security News
**Published:** 2026-06-09
**Article:** https://cybersecuritynews.com/23-pypi-packages-compromised/

## Threat Profile

A new wave of the Shai-Hulud supply chain campaign, adding 23 newly discovered malicious PyPI package-version artifacts to an already alarming operation that previously compromised 37 packages. The broader campaign identified by the Socket Threat Research team, tracked across the Mini Shai-Hulud, Miasma, and Hades threat clusters, now spans 471 total artifacts across npm and PyPI, comprising [&#8230;] The post New Shai-Hulud Attack Compromises 23 PyPI Packages to Target MCP Developers appeared f…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45321`
- **IPv4 (defanged):** `83.142.209.194`
- **Domain (defanged):** `filev2.getsession.org`
- **Domain (defanged):** `getsession.org`
- **Domain (defanged):** `git-tanstack.com`
- **SHA256:** `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
- **SHA256:** `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- **SHA1:** `12ed9a3c1f73617aefdb740480695c04405d7b4b`
- **SHA1:** `e7d582b98ca80690883175470e96f703ef6dc497`
- **MD5:** `833fd59ebe66a4449982c6d18db656b4`
- **MD5:** `b82e54923f7e440664d2d75bd31588ca`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
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
  - CVE(s): `CVE-2026-45321`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `83.142.209.194`, `filev2.getsession.org`, `getsession.org`, `git-tanstack.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`, `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`, `12ed9a3c1f73617aefdb740480695c04405d7b4b`, `e7d582b98ca80690883175470e96f703ef6dc497`, `833fd59ebe66a4449982c6d18db656b4`, `b82e54923f7e440664d2d75bd31588ca`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
