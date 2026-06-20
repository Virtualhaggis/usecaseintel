# [HIGH] Container images simplified with Ko

**Source:** Snyk
**Published:** 2022-10-10
**Article:** https://snyk.io/blog/container-images-simplified-with-google-ko/

## Threat Profile

Snyk Blog In this article
Written by Eric Smalling 
October 10, 2022
0 mins read In a previous article , I wrote about how — and why — you might want to use the Google Open Source group’s Jib tool to build your Java application container images. Jib builds slim, JVM-based, OCI-compliant images that follow best practice guidelines without the need for a container runtime like Docker, and it removes the need to write and manage Dockerfiles. What if you are building Go applications, though? Well, t…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `eb9735e61e1dec63bd557dd5c61d8789733f2f4456a0d01687816bd0d135a7bc`
- **SHA256:** `ddcabff499d90fdf6850ef0b7addb33db7defe4669f9af1079894e84ad407199`
- **SHA256:** `2ef3c3dc0363ad10e9bf21baa7e78c63ca4df904bcba1fdab3af7732fce3857d`
- **SHA256:** `2a9e2b4fa771d31fe3346a873be845bfc2159695b9f90ca08e950497006ccc2e`
- **SHA256:** `2952e4f69ebf4bea5cc557f73626f95649cb546424fd998481ba690a08d9db7f`
- **SHA256:** `a706af0bb599ee120bd57c0e6abca55f66fd714f9e74706d9c97a583fc79d37e`
- **SHA256:** `3925979ac92afb8cb89fc80438097873daf067195e4d0b9d2fd6f55d6201355c`
- **SHA256:** `7d444debc3cd2d5545e88606dc529fa7ed90b1bb581ff8ac30b0f475b68d4ec0`
- **SHA256:** `5ec5232d47ab0ad088792a191b672fe6ec27db63b19daebd7322ad64a2cd8676`
- **SHA256:** `250c06f7c38e52dc77e5c7586c3e40280dc7ff9bb9007c396e06d96736cf8542`
- **SHA256:** `2d23903e55394a021ba4936cfad8ccbec6998413164416fcae4f6bf888665fce`
- **SHA256:** `1cd0595314a53d179ddaf68761c9f40c4d9d1bcd3f692d1c005938dac2993db6`
- **SHA256:** `70877dcd53d23c66873e8e1e5a2092b46740e699b214a545e386113e5e098d7c`
- **SHA256:** `acf1dce794131205d488ed8fe4818866ebf509a61f4cf60aa07463e2b054d97d`
- **SHA256:** `bd7eb1052cf5b8664890f23683930f07423aba0089150bb818a53e76ef2ebf68`
- **MD5:** `7a204cfb24536a350234d9132276cae7`
- **MD5:** `ea0a77f5cbe6ba6aea599ad83048ae7b`

## MITRE ATT&CK Techniques

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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `eb9735e61e1dec63bd557dd5c61d8789733f2f4456a0d01687816bd0d135a7bc`, `ddcabff499d90fdf6850ef0b7addb33db7defe4669f9af1079894e84ad407199`, `2ef3c3dc0363ad10e9bf21baa7e78c63ca4df904bcba1fdab3af7732fce3857d`, `2a9e2b4fa771d31fe3346a873be845bfc2159695b9f90ca08e950497006ccc2e`, `2952e4f69ebf4bea5cc557f73626f95649cb546424fd998481ba690a08d9db7f`, `a706af0bb599ee120bd57c0e6abca55f66fd714f9e74706d9c97a583fc79d37e`, `3925979ac92afb8cb89fc80438097873daf067195e4d0b9d2fd6f55d6201355c`, `7d444debc3cd2d5545e88606dc529fa7ed90b1bb581ff8ac30b0f475b68d4ec0` _(+9 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
