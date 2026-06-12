# [HIGH] Malicious npm Campaign Steals SSH Keys, API Tokens, Cloud Credentials, and Wallet Secrets

**Source:** Cyber Security News
**Published:** 2026-06-12
**Article:** https://cybersecuritynews.com/malicious-npm-campaign-steals-ssh-keys-api-tokens/

## Threat Profile

A fresh wave of supply chain attacks is putting blockchain developers, Web3 teams, and cloud engineers at serious risk. Researchers have uncovered a coordinated campaign involving multiple malicious packages on the npm registry, each designed to quietly steal sensitive secrets the moment a developer installs them. From SSH private keys to cloud credentials, wallet phrases [&#8230;] The post Malicious npm Campaign Steals SSH Keys, API Tokens, Cloud Credentials, and Wallet Secrets appeared first o…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `193.233.201.21`
- **Domain (defanged):** `pastefy.app`
- **SHA256:** `d94a2444268b339dfda2615f7800322fb318e0a484414bb17016cfcd5eb07c44`
- **SHA256:** `6585ca0d3e26c20ced638f46f4a89eea924d411b8753d3fcf434663593c7cf0b`
- **SHA256:** `17bad5ae5b2ac262f5f18854853869840245c344105aa38c7f550ef51d2e5f26`
- **SHA256:** `7269c00a6164fd01dd516e0a72b2bd84c82e78feb552e06964e4992ff0479dda`
- **SHA256:** `e848d73a68e4e8aea00a6257552b5872907dfaf7cce3d94636d7e59d286edeab`
- **SHA256:** `2fa5b0475c3b70a3ba14c6a3938baf441a08b11841493b85e087d1d5e01eba49`
- **SHA256:** `d6abc7003b580472d808b338adef0b28eacc698cd4692f76cb2a91718ab78d88`
- **SHA256:** `bab96257018df49ace8fe8adfadc74cf8327fcf9a9dc8a3a7c9ac8e18881df5f`
- **SHA256:** `d7ec660a2a29c1aabcbe9bff1ef29be9a9fab8c7fe7c40df4772dd2b5bdf9666`
- **SHA256:** `5c50f79038b31aa8a3a68b24d8b783dfbd2e15fff7586c5609e544a717ef7d05`
- **SHA256:** `feabf10c8a9ba2775bb0f7f9d0b20203112b7df8e6d333a44d5a11eae0e38e86`
- **SHA1:** `53b91117db931d3acbbfd15aa8400bb6691e023d`
- **SHA1:** `63154cd9c79f9d14eb9be6c4efc2a778d31646ec`
- **SHA1:** `74d3d5ab6d0fa4c6a5860598231728a6a893ecf7`
- **SHA1:** `fcc8a542aad41e758cf6c18571048890be53808e`
- **SHA1:** `70842cfc27b116d0db2fd7aa33d53a3faf510993`
- **SHA1:** `e1bdcd1a7157f7d047a88ab4573723fe1e861951`

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
  - IP / domain IOC(s): `193.233.201.21`, `pastefy.app`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `d94a2444268b339dfda2615f7800322fb318e0a484414bb17016cfcd5eb07c44`, `6585ca0d3e26c20ced638f46f4a89eea924d411b8753d3fcf434663593c7cf0b`, `17bad5ae5b2ac262f5f18854853869840245c344105aa38c7f550ef51d2e5f26`, `7269c00a6164fd01dd516e0a72b2bd84c82e78feb552e06964e4992ff0479dda`, `e848d73a68e4e8aea00a6257552b5872907dfaf7cce3d94636d7e59d286edeab`, `2fa5b0475c3b70a3ba14c6a3938baf441a08b11841493b85e087d1d5e01eba49`, `d6abc7003b580472d808b338adef0b28eacc698cd4692f76cb2a91718ab78d88`, `bab96257018df49ace8fe8adfadc74cf8327fcf9a9dc8a3a7c9ac8e18881df5f` _(+9 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
