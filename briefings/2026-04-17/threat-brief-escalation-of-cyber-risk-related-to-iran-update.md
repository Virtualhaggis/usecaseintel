<!-- curated:true -->
# [CRIT] Threat Brief: Escalation of Cyber Risk Related to Iran (Updated April 17)

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-04-17
**Article:** https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Unit 42's living threat brief on the **Iran-aligned threat-actor cluster** — combining state-aligned APT crews (APT35 / Charming Kitten, MuddyWater, APT34 / OilRig, Fox Kitten, Pioneer Kitten), ideologically-aligned hacktivist groups (CyberAv3ngers, Predatory Sparrow), and Iran-adjacent ransomware affiliates. The brief tracks **infrastructure, lure themes, and CVEs** in active use across this ecosystem.

Why this is operationally significant for SOCs **regardless of geography**:
- Iran-aligned crews routinely target **regional Middle East assets** but their **infrastructure is global** — phishing pages hosted on commodity providers, C2 on `*.sbs` / `*.life` / `*.top` cheap-TLD throwaways.
- Lookalike-domain TTPs (e.g., `bankofamerica.com.oidscreen.gorequestlocale.emiratesbankgroup[.]info`) are **transferable** — same patterns hit US/UK financial users.
- The CVEs in scope (CVE-2023-33538 — Tenda router command injection, CVE-2025-55182 — Meta React Server Components) are **opportunistically exploited** by anyone, not just Iran-aligned actors.

The article's **33 high-fidelity domain IOCs** are immediately operational — paste into your DNS / proxy / EDR network filters today.

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-33538`
- **CVE:** `CVE-2025-55182`
- **33 defanged domain IOCs** — see `intel/iocs.csv` (filter `sources=Unit 42 (Palo Alto)`) or the IOC-driven hunts section below.

## MITRE ATT&CK (analyst-validated)

- **T1566.001 / T1566.002** — Spearphishing Attachment / Link
- **T1583.001** — Acquire Infrastructure: Domains (lookalike TLDs `.sbs`, `.life`, `.top`)
- **T1190** — Exploit Public-Facing Application
- **T1078** — Valid Accounts
- **T1556** — Modify Authentication Process
- **T1003.001** — OS Credential Dumping: LSASS
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1485** — Data Destruction (the wiper / hacktivism component)
- **T1071.001** — Application Layer Protocol: Web Protocols

## Recommended SOC actions (priority-ordered)

1. **Add the 33 domains to your DNS / proxy block list immediately.** Single highest-leverage action.
2. **Hunt 90 days of DNS / proxy logs** for any of these domains. A single resolve / connection deserves an IR case.
3. **Patch CVE-2023-33538 (Tenda)** and CVE-2025-55182 (React Server Components) if you have exposure. KEV-grade priority.
4. **Audit lookalike-domain monitoring.** The `bankofamerica.*.emiratesbankgroup.info` / `appleid.apple.*.emiratesbankgroup.info` patterns are **multi-tenant phishing infrastructure** — your customers / brand are likely on a similar list.
5. **Brief financial-services and energy-sector users** on the regional targeting (Middle East utilities, Saudi banking, Emirates posts/police impersonation lures).
6. **Block cheap-TLD families at egress** (`.sbs`, `.life`, `.top`, `.icu`, `.cyou`) for non-business use — heavily abused for short-lived phishing.

## Splunk SPL — DNS / web hits to Unit 42 Iran IOCs (wildcard-friendly)

```spl
| tstats `summariesonly` count
    from datamodel=Network_Resolution.DNS
    where (DNS.query="*.drproxy.pro" OR DNS.query="*.emiratesbankgroup.info"
        OR DNS.query="*.sapb-aramco.com" OR DNS.query="*.0111etisalat.com"
        OR DNS.query="*.irancell.courses" OR DNS.query="*.azmtrust.com"
        OR DNS.query="*.tollbillba.life" OR DNS.query="*.traz.top"
        OR DNS.query="*.saudidigtalbank.com" OR DNS.query="*.filehost36.sbs"
        OR DNS.query="*.racunari-bl.com")
    by DNS.src, DNS.query, DNS.answer
| `drop_dm_object_name(DNS)`
| sort - count
```

## Splunk SPL — cheap-TLD egress baseline

```spl
| tstats `summariesonly` count
    from datamodel=Network_Resolution.DNS
    where (DNS.query="*.sbs" OR DNS.query="*.life" OR DNS.query="*.top"
        OR DNS.query="*.icu" OR DNS.query="*.cyou" OR DNS.query="*.gdn")
    by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| stats sum(count) AS queries, dc(query) AS unique_queries by src
| where queries > 5
| sort - queries
```

## Defender KQL — DNS / network to Unit 42 Iran IOCs

```kql
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteUrl has_any (
    "drproxy.pro","emiratesbankgroup.info","sapb-aramco.com","0111etisalat.com",
    "irancell.courses","azmtrust.com","tollbillba.life","traz.top",
    "saudidigtalbank.com","filehost36.sbs","racunari-bl.com",
    "ae-finesquery.com","ae-payapp.com","gov-tollbillba.life")
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — vuln exposure (CVE-2023-33538, CVE-2025-55182)

```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in~ ("CVE-2023-33538","CVE-2025-55182")
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
```

## Defender KQL — cheap-TLD egress

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType in ("DnsQuery","ConnectionSuccess")
| extend tld = extract(@"\.([a-z]+)$", 1, tolower(RemoteUrl))
| where tld in ("sbs","life","top","icu","cyou","gdn")
| summarize queries = count(),
            distinctDomains = dcount(RemoteUrl),
            firstSeen = min(Timestamp), lastSeen = max(Timestamp)
            by DeviceName, tld
| where queries > 5
| order by queries desc
```

## IOC-driven hunts (use shared templates)

Standard IOC-substitution hunts — canonical SPL / KQL in [`_TEMPLATES.md`](../_TEMPLATES.md).

- **Asset exposure** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-33538`, `CVE-2025-55182`
- **Network connections to article domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - 33 defanged domains — pull from `intel/iocs.csv` (sources contains `Unit 42`).

## Why this matters for your SOC

Unit 42's brief is **the most operationally-actionable Iran-aligned threat report in 2026** because it consolidates infrastructure across the entire Iran-aligned ecosystem — APT, hacktivist, ransomware. The 33 domains are vendor-attributed and ready to block.

The **broader operational lesson** is: regional-targeting reports often have **techniques, lures, and infrastructure patterns that travel**. The lookalike-domain phishing pattern (`bankofamerica.com.<n>.emiratesbankgroup.info`) is the canonical 2026 financial-phishing shape regardless of which country the operator targets first. The cheap-TLD burner-domain pattern is universal. The CVE-2023-33538 / CVE-2025-55182 exposures aren't Iran-specific — they're "exploited because they exist."

Block the 33 domains today. Baseline cheap-TLD egress. Track the brief — Unit 42 updates this living document, so re-pull the IOC list weekly.
