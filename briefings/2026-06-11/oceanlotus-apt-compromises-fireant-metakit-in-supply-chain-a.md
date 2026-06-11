# [HIGH] OceanLotus APT Compromises FireAnt MetaKit in Supply-Chain Attack on Stock Investors

**Source:** Cyber Security News
**Published:** 2026-06-11
**Article:** https://cybersecuritynews.com/oceanlotus-apt-compromises-fireant-metakit/

## Threat Profile

A notorious hacking group has been caught targeting stock investors in Vietnam through a supply chain attack, hijacking a popular investment software platform to deliver a powerful backdoor. The operation, carried out by OceanLotus (also known as APT32), marks a notable shift in the group&#8217;s tactics as it turns focus increasingly toward domestic targets inside [&#8230;] The post OceanLotus APT Compromises FireAnt MetaKit in Supply-Chain Attack on Stock Investors appeared first on Cyber Secu…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `139.162.11.152`
- **IPv4 (defanged):** `142.91.98.77`
- **IPv4 (defanged):** `139.180.128.42`
- **IPv4 (defanged):** `139.99.33.239`
- **IPv4 (defanged):** `166.88.77.186`
- **IPv4 (defanged):** `103.119.47.104`
- **IPv4 (defanged):** `38.60.245.37`
- **IPv4 (defanged):** `194.68.26.241`
- **Domain (defanged):** `financemachinelearning.com`
- **Domain (defanged):** `gatewayrvcenter.com`
- **Domain (defanged):** `coachcybersecurity.com`
- **Domain (defanged):** `mxprodesign.com`
- **Domain (defanged):** `power-sync-services.com`
- **Domain (defanged):** `leadingfilipinoteams.com`
- **SHA1:** `D511B77459673EC42163F19E300FF1D233B6C39F`
- **SHA1:** `59A8553A4F8130F576AB234E0B220BE4D4DA0E98`
- **SHA1:** `9CA1A5C7F79882DB913534C1E62B26BCDCB9F6DD`
- **SHA1:** `A8E2BBBFCB86500322D2367744FA12755AB0C165`
- **SHA1:** `F74F1FEB62B662CDA489FDB2453727824E55ACB9`
- **SHA1:** `F8F8209987CA7F139DE6A62F9E6EE21BD2AE93A9`
- **SHA1:** `19A69F856EFA811C376F68E4FEB0997B4724F8BD`
- **SHA1:** `490194E9BB5128ECA8693AD9E610891C2ED185AF`
- **SHA1:** `51176139B0B2220B802C1578A4994DF68DF5BCD1`
- **SHA1:** `91F042F59BE4BDCB6E5EA21B91DECD731C175B54`
- **SHA1:** `A177ED0BFFEB1EFE1D9D31D72A82EF2625AE646D`
- **SHA1:** `B7B2D2DB544F9EEA74453CDF2B8BEEA58CF07C48`
- **SHA1:** `4AD36AD6C165B5174967020CB1A3358F78D7A283`
- **SHA1:** `57352B3CEEE32216E5AA20BAA848483D7AB5A6FB`
- **SHA1:** `9BC06DF9F932746A05EE728C8B103BD3BA6BF395`
- **SHA1:** `865A1739337D3303B3AB02C5E694C22B79C42B7D`
- **SHA1:** `41CB8CD78B8DB76563E4F972ABE817CEEE9CF9B0`
- **SHA1:** `0037DBB0FEA981D02F6F76DE81EBAEFCB68B7D20`
- **SHA1:** `5D6194BB48FEBB91A10D1462461A012FAFC0918B`
- **SHA1:** `B028E947150764A71DEEF498DE6F8C95ECCCB445`

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
  - IP / domain IOC(s): `139.162.11.152`, `142.91.98.77`, `139.180.128.42`, `139.99.33.239`, `166.88.77.186`, `103.119.47.104`, `38.60.245.37`, `194.68.26.241` _(+6 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `D511B77459673EC42163F19E300FF1D233B6C39F`, `59A8553A4F8130F576AB234E0B220BE4D4DA0E98`, `9CA1A5C7F79882DB913534C1E62B26BCDCB9F6DD`, `A8E2BBBFCB86500322D2367744FA12755AB0C165`, `F74F1FEB62B662CDA489FDB2453727824E55ACB9`, `F8F8209987CA7F139DE6A62F9E6EE21BD2AE93A9`, `19A69F856EFA811C376F68E4FEB0997B4724F8BD`, `490194E9BB5128ECA8693AD9E610891C2ED185AF` _(+12 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
