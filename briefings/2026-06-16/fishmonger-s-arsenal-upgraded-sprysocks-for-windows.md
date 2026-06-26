# [MED] FishMonger’s arsenal upgraded: SprySOCKS for Windows

**Source:** ESET WeLiveSecurity
**Published:** 2026-06-16
**Article:** https://www.welivesecurity.com/en/eset-research/fishmongers-arsenal-upgraded-sprysocks-windows/

## Threat Profile

ESET researchers have discovered two as-yet undocumented Windows variants of SprySOCKS , a previously Linux-only backdoor reportedly used by FishMonger, the group believed to be operated by a Chinese contractor named I‑SOON. While we initially discovered the malware samples on VirusTotal, ESET telemetry shows real activity between 2023 and 2024, with several victims in Honduras, Taiwan, Thailand, and Pakistan, targeting mostly government organizations.
The Windows variants discovered are interna…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-24932`
- **IPv4 (defanged):** `207.148.78.36`
- **IPv4 (defanged):** `207.148.75.122`
- **SHA1:** `955BFC3DCC867256F9F46A606DEB0779FA3416D8`
- **SHA1:** `44DC4A08C5EB0972C8E18B0E01284E06F09006BB`
- **SHA1:** `AB87B29B6F79487C75CA08D102E79001E536F083`
- **SHA1:** `6490B8E4AADE25A3EE2DA9A47F312DB2122470BC`
- **SHA1:** `E7484C24B88A1A2407A8F09D734F9A993670285B`
- **SHA1:** `621D1952839BE4B0A1B0E66E87BCE5062CA368ED`
- **SHA1:** `2457EED2AB28E37741F10914EF929DAD2C8079D4`
- **SHA1:** `D2C706B1EAF662BF0CE124B5032F73ED84BDA24A`
- **SHA1:** `5F3B87CEF56683D9A9E19186E0FD0D8019B559C4`
- **SHA1:** `C793CA31E3F6628B5C8986146953BF66232E9A30`
- **SHA1:** `037DB2445F3D72388CB2CF8510563148E5A184BE`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1095** — Non-Application Layer Protocol
- **T1571** — Non-Standard Port
- **T1014** — Rootkit
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1542.003** — Pre-OS Boot: Bootkit
- **T1553.006** — Subvert Trust Controls: Code Signing Policy Modification

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SprySOCKS (FishMonger/I-SOON) C2 beacon to hardcoded Vultr IPs 207.148.78.36 / 207.148.75.122

`UC_170_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("207.148.78.36","207.148.75.122") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("207.148.78.36", "207.148.75.122")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, Protocol, InitiatingProcessSHA1
| order by Timestamp desc
```

### SprySOCKS WIN_DRV/WIN_PLUS backdoor binary by ESET SHA1 hash

`UC_170_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("955BFC3DCC867256F9F46A606DEB0779FA3416D8","44DC4A08C5EB0972C8E18B0E01284E06F09006BB","AB87B29B6F79487C75CA08D102E79001E536F083","6490B8E4AADE25A3EE2DA9A47F312DB2122470BC","E7484C24B88A1A2407A8F09D734F9A993670285B","621D1952839BE4B0A1B0E66E87BCE5062CA368ED","2457EED2AB28E37741F10914EF929DAD2C8079D4","D2C706B1EAF662BF0CE124B5032F73ED84BDA24A","5F3B87CEF56683D9A9E19186E0FD0D8019B559C4","C793CA31E3F6628B5C8986146953BF66232E9A30","037DB2445F3D72388CB2CF8510563148E5A184BE") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process_hash Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let SprySOCKS = dynamic(["955BFC3DCC867256F9F46A606DEB0779FA3416D8","44DC4A08C5EB0972C8E18B0E01284E06F09006BB","AB87B29B6F79487C75CA08D102E79001E536F083","6490B8E4AADE25A3EE2DA9A47F312DB2122470BC","E7484C24B88A1A2407A8F09D734F9A993670285B","621D1952839BE4B0A1B0E66E87BCE5062CA368ED","2457EED2AB28E37741F10914EF929DAD2C8079D4","D2C706B1EAF662BF0CE124B5032F73ED84BDA24A","5F3B87CEF56683D9A9E19186E0FD0D8019B559C4","C793CA31E3F6628B5C8986146953BF66232E9A30","037DB2445F3D72388CB2CF8510563148E5A184BE"]);
union DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where SHA1 in~ (SprySOCKS) or InitiatingProcessSHA1 in~ (SprySOCKS)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA1, InitiatingProcessCommandLine
| order by Timestamp desc
```

### SprySOCKS WIN_DRV BlackLotus-style Secure Boot downgrade / EFI bootkit (CVE-2023-24932)

`UC_170_5` · phase: **install** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("bootmgfw.efi","bootmgr.efi","bootx64.efi") OR Filesystem.file_path="*\\EFI\\*") AND Filesystem.file_name="*.efi" AND NOT Filesystem.process_name IN ("TiWorker.exe","TrustedInstaller.exe","poqexec.exe","MoUsoCoreWorker.exe","CompatTelRunner.exe","wuauclt.exe") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".efi"
| where FileName in~ ("bootmgfw.efi","bootmgr.efi","bootx64.efi") or FolderPath has @"\EFI\" or FolderPath has "HarddiskVolume"
| where InitiatingProcessFileName !in~ ("TiWorker.exe","TrustedInstaller.exe","poqexec.exe","MoUsoCoreWorker.exe","CompatTelRunner.exe","wuauclt.exe","setup.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-24932`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `207.148.78.36`, `207.148.75.122`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `955BFC3DCC867256F9F46A606DEB0779FA3416D8`, `44DC4A08C5EB0972C8E18B0E01284E06F09006BB`, `AB87B29B6F79487C75CA08D102E79001E536F083`, `6490B8E4AADE25A3EE2DA9A47F312DB2122470BC`, `E7484C24B88A1A2407A8F09D734F9A993670285B`, `621D1952839BE4B0A1B0E66E87BCE5062CA368ED`, `2457EED2AB28E37741F10914EF929DAD2C8079D4`, `D2C706B1EAF662BF0CE124B5032F73ED84BDA24A` _(+3 more)_


## Why this matters

Severity classified as **MED** based on: CVE present, IOCs present, 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
