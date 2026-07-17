# [CRIT] 11 Old Microsoft-Signed Linux UEFI Shims Could Let Attackers Bypass Secure Boot

**Source:** The Hacker News
**Published:** 2026-07-14
**Article:** https://thehackernews.com/2026/07/11-old-microsoft-signed-linux-uefi.html

## Threat Profile

11 Old Microsoft-Signed Linux UEFI Shims Could Let Attackers Bypass Secure Boot 
 Ravie Lakshmanan  Jul 14, 2026 Endpoint Security / Linux 
Cybersecurity researchers have discovered 11 old, Microsoft-signed, Unified Extensible Firmware Interface (UEFI) applications that could be abused to bypass Secure Boot on most systems using the modern firmware standard.
"An attacker exploiting one of these vulnerable applications can execute untrusted code during system boot, enabling deployment of malici…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-8863`
- **CVE:** `CVE-2026-10797`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1542.003** — Pre-OS Boot: Bootkit
- **T1553.006** — Subvert Trust Controls: Code Signing Policy Modification
- **T1542.001** — Pre-OS Boot: System Firmware
- **T1562.001** — Impair Defenses: Disable or Modify Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Revoked Microsoft-signed vulnerable UEFI shim present in estate (CVE-2026-8863 / CVE-2026-10797)

`UC_78_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-8863","CVE-2026-10797") by Vulnerabilities.dest, Vulnerabilities.cve, Vulnerabilities.severity, Vulnerabilities.signature | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-8863", "CVE-2026-10797")
| project DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
```

### Old shim/GRUB EFI binary written to ESP by non-package-manager process (Secure Boot bypass staging)

`UC_78_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.file_name IN ("shimx64.efi","shimaa64.efi","shimia32.efi","mmx64.efi","grubx64.efi","fbx64.efi","bootx64.efi") Endpoint.file_path="*/boot/efi/*" NOT Endpoint.process_name IN ("dpkg","rpm","apt","apt-get","dnf","yum","zypper","fwupd","fwupdmgr","grub-install","grub2-install","shim-install","update-grub") by Endpoint.dest, Endpoint.file_name, Endpoint.file_path, Endpoint.process_name, Endpoint.user | `drop_dm_object_name(Endpoint)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "/boot/efi/" or FolderPath has "/EFI/"
| where FileName in~ ("shimx64.efi","shimaa64.efi","shimia32.efi","mmx64.efi","grubx64.efi","fbx64.efi","bootx64.efi")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","apt","apt-get","dnf","yum","zypper","zypp","fwupd","fwupdmgr","grub-install","grub2-install","shim-install","update-grub","packagekitd")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### MOK/SBAT enforcement disabled via mokutil (Secure Boot validation subversion)

`UC_78_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.process_name="mokutil" (Endpoint.process="*--disable-validation*" OR Endpoint.process="*--set-sbat-policy*" OR Endpoint.process="*--import*" OR Endpoint.process="*--reset*") by Endpoint.dest, Endpoint.user, Endpoint.process_name, Endpoint.process, Endpoint.parent_process_name | `drop_dm_object_name(Endpoint)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "mokutil"
| where ProcessCommandLine has_any ("--disable-validation", "--set-sbat-policy", "--import", "--reset")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

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
  - CVE(s): `CVE-2026-8863`, `CVE-2026-10797`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
