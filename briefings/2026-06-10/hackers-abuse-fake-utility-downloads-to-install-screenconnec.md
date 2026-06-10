# [MED] Hackers Abuse Fake Utility Downloads to Install ScreenConnect and Mine Cryptocurrency

**Source:** Cyber Security News
**Published:** 2026-06-10
**Article:** https://cybersecuritynews.com/hackers-abuse-fake-utility-downloads/

## Threat Profile

Hackers are turning everyday software searches into a trap. A sophisticated cryptojacking campaign is actively targeting users who search for popular PC utilities online, luring them into downloading malware-laced files that secretly mine cryptocurrency using their own GPU. The attackers have built a network of more than 150 fake download sites that closely mimic trusted [&#8230;] The post Hackers Abuse Fake Utility Downloads to Install ScreenConnect and Mine Cryptocurrency appeared first on Cyb…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `193.42.11.108`
- **IPv4 (defanged):** `93.115.10.35`
- **IPv4 (defanged):** `198.23.185.238`
- **IPv4 (defanged):** `2.59.132.106`
- **Domain (defanged):** `direct-download.gleeze.com`
- **Domain (defanged):** `start-download.gleeze.com`
- **Domain (defanged):** `direct-downloads.giize.com`
- **Domain (defanged):** `free-download.giize.com`
- **Domain (defanged):** `directdownload.icu`
- **Domain (defanged):** `minemine.gleeze.com`
- **Domain (defanged):** `gleeze.com`
- **Domain (defanged):** `giize.com`
- **SHA256:** `16562974deec80e41ef57a71a6de8c03ceb393005fb1432f8d9d82c61294ef8c`
- **SHA256:** `1b2555b09ac62164638f47c8272beb6b0f97186e37d3a54cb84c723ff7a2eee5`
- **SHA256:** `062bb28765fbaa11f8cc341fa16e2c7f942a122d929cb41f4a0f755b4429f246`
- **SHA256:** `c7425fbe6c3a4937934215c54027d4b67202d12ab490682fae03498870d66d06`
- **SHA256:** `a460d00ef93c8ce70d32e48e55781af66a53328fc2dde45519be196c265de074`
- **SHA256:** `db2d33c4e6e4a5c2263b56e8303c343305a94dde1fc2968304ba260acbbd9f9f`
- **SHA256:** `cf3f8160eb5a5580e0c35054847e3ac4d01e9fe74fab8bc12bf6e8a40bf696b2`
- **SHA256:** `69077fcf940fc5852fb32beed15636756ebc04ac971b7ed71d36251e7ea70a20`
- **SHA256:** `2ee93ccbcd49ed94c65dcf52e7dcb8f0fa0a443ca24c0e0c7f79152efba657b7`
- **SHA256:** `9ff07c9fafa9c03fdf69e4abf6806aa7c938b5480e7e258f227db0719ecd6386`
- **SHA256:** `7035c2abeb617e828dfda1b119b8544fa9ae15a1d263d18bc5506acaf381f496`
- **SHA256:** `e021662a652ba95c8778b991056696ab3c9b0f60d5e23b1e6cf73c3847db6610`

## MITRE ATT&CK Techniques

- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `193.42.11.108`, `93.115.10.35`, `198.23.185.238`, `2.59.132.106`, `direct-download.gleeze.com`, `start-download.gleeze.com`, `direct-downloads.giize.com`, `free-download.giize.com` _(+4 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `16562974deec80e41ef57a71a6de8c03ceb393005fb1432f8d9d82c61294ef8c`, `1b2555b09ac62164638f47c8272beb6b0f97186e37d3a54cb84c723ff7a2eee5`, `062bb28765fbaa11f8cc341fa16e2c7f942a122d929cb41f4a0f755b4429f246`, `c7425fbe6c3a4937934215c54027d4b67202d12ab490682fae03498870d66d06`, `a460d00ef93c8ce70d32e48e55781af66a53328fc2dde45519be196c265de074`, `db2d33c4e6e4a5c2263b56e8303c343305a94dde1fc2968304ba260acbbd9f9f`, `cf3f8160eb5a5580e0c35054847e3ac4d01e9fe74fab8bc12bf6e8a40bf696b2`, `69077fcf940fc5852fb32beed15636756ebc04ac971b7ed71d36251e7ea70a20` _(+4 more)_


## Why this matters

Severity classified as **MED** based on: IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
