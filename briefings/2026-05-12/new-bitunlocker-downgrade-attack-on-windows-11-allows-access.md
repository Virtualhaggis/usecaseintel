# [CRIT] New BitUnlocker Downgrade Attack on Windows 11 Allows Access to Encrypted Disks in 5 Minutes

**Source:** Cyber Security News
**Published:** 2026-05-12
**Article:** https://cybersecuritynews.com/bitunlocker-downgrade-attack-on-windows-11/

## Threat Profile

Home Cyber Security 
New BitUnlocker Downgrade Attack on Windows 11 Allows Access to Encrypted Disks in 5 Minutes 
By Guru Baran 
May 12, 2026 
A new tool, BitUnlocker, reveals a practical downgrade attack against Microsoft’s BitLocker encryption, allowing attackers with physical access to decrypt protected volumes on patched Windows 11 machines in under 5 minutes by exploiting a crucial gap between patching and certificate revocation.
The attack is rooted in CVE-2025-48804, one of four critical…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-48804`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1542.003** — Pre-OS Boot: Bootkit
- **T1600** — Weaken Encryption
- **T1195.003** — Supply Chain Compromise: Compromise Hardware Supply Chain
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1112** — Modify Registry

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Windows boot manager vulnerable to BitUnlocker / CVE-2025-48804 (PCA 2011 signed)

`UC_16_4` · phase: **weapon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) AS firstTime max(_time) AS lastTime FROM datamodel=Vulnerabilities.Vulnerabilities WHERE Vulnerabilities.cve="CVE-2025-48804" BY Vulnerabilities.dest Vulnerabilities.user Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.cve Vulnerabilities.cvss Vulnerabilities.category | `drop_dm_object_name(Vulnerabilities)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | eval mitigation="Deploy KB5025885 + migrate boot manager signing to Windows UEFI CA 2023; enable TPM+PIN pre-boot auth"
```

**Defender KQL:**
```kql
// Hunts devices reporting CVE-2025-48804 (BitUnlocker / WinRE SDI boot-manager downgrade)
DeviceTvmSoftwareVulnerabilities
| where CveId =~ "CVE-2025-48804"
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform, OSVersion, OSBuild, JoinType, IsAzureADJoined, IsInternetFacing, MachineGroup, LoggedOnUsers) by DeviceId
  ) on DeviceId
| project Timestamp, DeviceName, DeviceId, OSPlatform, OSVersion, OSBuild,
          SoftwareVendor, SoftwareName, SoftwareVersion,
          VulnerabilitySeverityLevel, RecommendedSecurityUpdate, RecommendedSecurityUpdateId,
          IsAzureADJoined, IsInternetFacing, MachineGroup, JoinType
| order by VulnerabilitySeverityLevel asc, DeviceName asc
```

### [LLM] BitLocker startup PIN policy disabled (TPM-only) — BitUnlocker precondition

`UC_16_5` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) AS firstTime max(_time) AS lastTime FROM datamodel=Endpoint.Registry WHERE (Registry.registry_path="*\\SOFTWARE\\Policies\\Microsoft\\FVE\\*") AND (Registry.registry_value_name IN ("UseAdvancedStartup","UseTPMPIN","UseTPMKeyPIN")) AND (Registry.registry_value_data IN ("0","0x0","0x00000000","DWORD (0x00000000)")) BY Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name Registry.process_guid | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | eval impact="BitLocker drops to TPM-only — vulnerable to BitUnlocker CVE-2025-48804 physical-access decryption"
```

**Defender KQL:**
```kql
// BitLocker FVE policy downgraded to TPM-only (BitUnlocker / CVE-2025-48804 precondition)
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\SOFTWARE\Policies\Microsoft\FVE"
| where RegistryValueName in~ ("UseAdvancedStartup","UseTPMPIN","UseTPMKeyPIN")
| where RegistryValueData in ("0","0x0","0x00000000")
| extend Downgrade = case(
    RegistryValueName =~ "UseAdvancedStartup" and RegistryValueData in ("0","0x0","0x00000000"), "Pre-boot auth not required (TPM-only path enabled)",
    RegistryValueName has_any ("UseTPMPIN","UseTPMKeyPIN") and RegistryValueData in ("0","0x0","0x00000000"), "Startup PIN blocked — TPM-only enforced",
    "Other FVE policy weakening")
| project Timestamp, DeviceName, DeviceId,
          RegistryKey, RegistryValueName, RegistryValueData, PreviousRegistryValueData,
          Downgrade,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessAccountDomain,
          InitiatingProcessFolderPath, InitiatingProcessIntegrityLevel,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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
  - CVE(s): `CVE-2025-48804`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
