# [MED] Forgotten UEFI shims undermining Secure Boot

**Source:** ESET WeLiveSecurity
**Published:** 2026-07-14
**Article:** https://www.welivesecurity.com/en/eset-research/forgotten-uefi-shims-undermining-secure-boot/

## Threat Profile

ESET researchers identified 11 old and forgotten UEFI shim bootloaders at versions 0.9 and below that can be used to bypass UEFI Secure Boot on any UEFI-based machine that trusts Microsoft’s Microsoft Corporation UEFI CA 2011 third-party UEFI certificate authority (CA) certificate, regardless of the installed operating system (OS). Reported shims can be exploited to execute untrusted code during system boot, enabling attackers to deploy malicious UEFI bootkits (such as Bootkitty , HybridPetya , …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-8863`
- **CVE:** `CVE-2026-10797`
- **SHA256:** `AE75F0D82BA3DF824FBFC69340CC3B4D66C598373B1AB54CDB6C8BFD83A6B961`
- **SHA256:** `7B2A3F5C96F95BD8086CE54B0825E300F9C8F11FE3401BB631B3215C8DE9EB10`
- **SHA256:** `EB86FA1386FE6E4533B8B938DCC1250616D2F1C14C15E2FCF80834A161018A0A`
- **SHA256:** `FD23D6E57DE6F4E1F9D7118DA1C5F31A8AF6BE5E5D9E8170F9493447268D50C5`
- **SHA256:** `A0DE9333442C1BF9349A460141AE5E80F911955C6506040FA3D021BF6C1AE3E4`
- **SHA256:** `95B6D71FC0C0F8C5E1533A37AEF92CF6B0C961E2CC612A97117FA6759CE5FC06`
- **SHA256:** `236A9CB0D71951C36398A32EB660CE2CD4A52CCFA7CF751CC6A35D9DE549E19B`
- **SHA256:** `5E594C448760A3135B1A3A83E07A4F2E6FBE49414EF2C7CAB1CBA77F284FA63B`
- **SHA256:** `8A964D5F8373948D20A1D4296FB92E545DAD4617A0C810F3B934B53D98AE8963`
- **SHA256:** `410260B1B6F5AF5FBEEB9EA3220658435E876CB3247126EE907A437F312DB373`
- **SHA256:** `96275DFD6282A522B011177EE049296952AC794832091F937FBBF92869028629`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1027** — Obfuscated Files or Information
- **T1542** — Pre-OS Boot
- **T1542.003** — Bootkit

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Exposure to revoked vulnerable UEFI shims (CVE-2026-8863 / CVE-2026-10797)

`UC_166_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.cve IN ("CVE-2026-8863","CVE-2026-10797")) by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.signature | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId in ("CVE-2026-8863","CVE-2026-10797")
| project Timestamp, DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by Timestamp desc
```

### Vulnerable UEFI shim/GRUB bootloader written to the EFI System Partition

`UC_166_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("shimx64.efi","shimia32.efi","grubx64.efi","grubia32.efi","mmx64.efi","mmia32.efi","bootx64.efi","bootia32.efi")) AND Filesystem.file_path="*\\EFI\\*" by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_id | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where FileName in~ ("shimx64.efi","shimia32.efi","grubx64.efi","grubia32.efi","mmx64.efi","mmia32.efi","bootx64.efi","bootia32.efi")
| where FolderPath has @"\EFI\"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### EFI System Partition mounted via mountvol /S (rogue shim staging)

`UC_166_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="mountvol.exe" AND Processes.process="*/S*" by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "mountvol.exe"
| where ProcessCommandLine has "/s"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-8863`, `CVE-2026-10797`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `AE75F0D82BA3DF824FBFC69340CC3B4D66C598373B1AB54CDB6C8BFD83A6B961`, `7B2A3F5C96F95BD8086CE54B0825E300F9C8F11FE3401BB631B3215C8DE9EB10`, `EB86FA1386FE6E4533B8B938DCC1250616D2F1C14C15E2FCF80834A161018A0A`, `FD23D6E57DE6F4E1F9D7118DA1C5F31A8AF6BE5E5D9E8170F9493447268D50C5`, `A0DE9333442C1BF9349A460141AE5E80F911955C6506040FA3D021BF6C1AE3E4`, `95B6D71FC0C0F8C5E1533A37AEF92CF6B0C961E2CC612A97117FA6759CE5FC06`, `236A9CB0D71951C36398A32EB660CE2CD4A52CCFA7CF751CC6A35D9DE549E19B`, `5E594C448760A3135B1A3A83E07A4F2E6FBE49414EF2C7CAB1CBA77F284FA63B` _(+3 more)_


## Why this matters

Severity classified as **MED** based on: CVE present, IOCs present, 5 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
