# [HIGH] New Cisco DoS flaw requires manual reboot to revive devices

**Source:** BleepingComputer
**Published:** 2026-05-06
**Article:** https://www.bleepingcomputer.com/news/security/new-cisco-dos-flaw-requires-manual-reboot-to-revive-devices/

## Threat Profile

New Cisco DoS flaw requires manual reboot to revive devices 
By Sergiu Gatlan 
May 6, 2026
02:06 PM
0 
Cisco released security updates to fix a Crosswork Network Controller (CNC) and Network Services Orchestrator (NSO) denial-of-service (DoS) vulnerability that requires manually rebooting targeted systems for recovery.
Large enterprises and service providers leverage the CNC software suite to simplify multivendor network management and operations handling with automation, while the NSO orchestra…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-20188`
- **CVE:** `CVE-2025-20362`
- **CVE:** `CVE-2025-20333`
- **CVE:** `CVE-2022-20653`
- **CVE:** `CVE-2024-20401`
- **CVE:** `CVE-2025-20115`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1499.002** — Endpoint Denial of Service: Service Exhaustion Flood

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Exposure: Cisco CNC <=7.1 and NSO <=6.4.1.2 vulnerable to CVE-2026-20188 unauth DoS

`UC_21_1` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities where (Vulnerabilities.cve="CVE-2026-20188") OR (Vulnerabilities.signature="*Crosswork Network Controller*" OR Vulnerabilities.signature="*Network Services Orchestrator*" OR Vulnerabilities.signature="*Cisco NSO*") by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.category Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| eval product=case(match(signature,"(?i)crosswork"),"CNC", match(signature,"(?i)nso|network services orchestrator"),"NSO", true(),"Other")
| eval recommendation=case(product="CNC","Migrate CNC to 7.2 or later", product="NSO","Upgrade NSO to 6.4.1.3 or 6.5+", true(),"Apply Cisco PSIRT advisory for CVE-2026-20188")
| table firstSeen lastSeen dest product signature severity cve recommendation count
| sort - severity dest
```

**Defender KQL:**
```kql
// Path 1: CVE indexed by Defender TVM
let _byCve = DeviceTvmSoftwareVulnerabilities
    | where CveId =~ "CVE-2026-20188"
    | project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, Source = "TVM-CVE";
// Path 2: version-aware fallback against the software inventory
// Vulnerable per Cisco advisory: CNC 7.1 and earlier; NSO 6.3 and earlier; NSO 6.4 prior to 6.4.1.3
let _byInventory = DeviceTvmSoftwareInventory
    | where SoftwareVendor has "cisco"
    | where SoftwareName has_any ("crosswork network controller", "network services orchestrator", "crosswork", "nso")
    | extend _parts = split(SoftwareVersion, ".")
    | extend Major = toint(_parts[0]), Minor = toint(_parts[1]), Patch = toint(_parts[2]), Build = toint(_parts[3])
    | extend IsCnc = SoftwareName has "crosswork"
    | extend IsNso = SoftwareName has_any ("network services orchestrator", "nso")
    | extend Vulnerable = case(
        IsCnc and (Major < 7 or (Major == 7 and Minor <= 1)), true,
        IsNso and (Major < 6 or (Major == 6 and Minor <= 3)), true,
        IsNso and Major == 6 and Minor == 4 and (Patch < 1 or (Patch == 1 and Build < 3)), true,
        false)
    | where Vulnerable
    | extend RecommendedSecurityUpdate = iff(IsCnc, "Migrate to CNC 7.2+", "Upgrade NSO to 6.4.1.3 or 6.5+")
    | extend VulnerabilitySeverityLevel = "High", Source = "InventoryVersionMatch"
    | project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, Source;
union _byCve, _byInventory
| summarize arg_max(Timestamp, *) by DeviceName, SoftwareName, SoftwareVersion
| order by SoftwareName asc, SoftwareVersion asc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-20188`, `CVE-2025-20362`, `CVE-2025-20333`, `CVE-2022-20653`, `CVE-2024-20401`, `CVE-2025-20115`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
