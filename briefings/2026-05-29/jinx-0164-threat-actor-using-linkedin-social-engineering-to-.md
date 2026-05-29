# [HIGH] JINX-0164 Threat Actor Using LinkedIn Social Engineering to Deploy Custom macOS Malware

**Source:** Cyber Security News
**Published:** 2026-05-29
**Article:** https://cybersecuritynews.com/jinx-0164-threat-actor-using-linkedin-social-engineering/

## Threat Profile

A new threat actor tracked as JINX-0164 has been running calculated attacks against cryptocurrency organizations, using LinkedIn profiles to lure developers into downloading custom macOS malware. Active since at least mid-2025, the group has combined social engineering, credential theft, and supply chain sabotage into a seamless operation that puts the entire software development pipeline at [&#8230;] The post JINX-0164 Threat Actor Using LinkedIn Social Engineering to Deploy Custom macOS Malwar…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `89.36.224.5`
- **IPv4 (defanged):** `185.100.85.250`
- **IPv4 (defanged):** `84.32.83.250`
- **IPv4 (defanged):** `153.92.126.84`
- **IPv4 (defanged):** `45.45.217.242`
- **IPv4 (defanged):** `163.172.53.20`
- **IPv4 (defanged):** `208.115.220.17`
- **IPv4 (defanged):** `185.175.59.85`
- **IPv4 (defanged):** `185.100.85.98`
- **Domain (defanged):** `datahub.ink`
- **Domain (defanged):** `cloud-sync.online`
- **Domain (defanged):** `byte-io.us`
- **Domain (defanged):** `apple.driver-store.com`
- **Domain (defanged):** `apple.driver-update.io`
- **Domain (defanged):** `driver-updater.net`
- **Domain (defanged):** `driver-hub.net`
- **Domain (defanged):** `drvstore.com`
- **Domain (defanged):** `bitget-meeting.com`
- **Domain (defanged):** `teamicrosoft.com`
- **Domain (defanged):** `teams.cam`
- **Domain (defanged):** `live.us.org`
- **Domain (defanged):** `us03-slack.online`
- **Domain (defanged):** `live.ong`
- **SHA256:** `0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270`
- **SHA256:** `9c2ce925133a3bf5a924063bbef8df49918d5b7258695c1894cd18c75970157a`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `89.36.224.5`, `185.100.85.250`, `84.32.83.250`, `153.92.126.84`, `45.45.217.242`, `163.172.53.20`, `208.115.220.17`, `185.175.59.85` _(+15 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270`, `9c2ce925133a3bf5a924063bbef8df49918d5b7258695c1894cd18c75970157a`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
