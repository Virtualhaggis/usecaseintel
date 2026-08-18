# [MED] French tax authority data breach affects 678,000 individuals

**Source:** BleepingComputer
**Published:** 2026-08-17
**Article:** https://www.bleepingcomputer.com/news/security/french-tax-authority-data-breach-affects-678-000-individuals/

## Threat Profile

French tax authority data breach affects 678,000 individuals 
By Sergiu Gatlan 
August 17, 2026
06:09 AM
0 
The French Ministry of the Economy and Finance has disclosed a data breach after an attacker accessed the General Directorate of Public Finances (DGFiP) systems and stole data belonging to 678,000 individuals.
This incident was discovered after a threat actor using the "ZeroBytes" handle claimed the attack and listed a stolen database for sale on August 12 on the PwnForums hacking forum.
"…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `apexappliexi.dgfp.finances.gouv.fr`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1213** — Data from Information Repositories
- **T1119** — Automated Collection
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Bulk cadastral record enumeration/scraping from DGFiP SPDC portal (apexappliext.dgfip.finances.gouv.fr)

`UC_24_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as TotalRequests dc(Web.url) as DistinctRecords values(Web.http_user_agent) as UserAgents min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.dest="apexappliext.dgfip.finances.gouv.fr" OR Web.site="apexappliext.dgfip.finances.gouv.fr") (Web.status=200 OR Web.status=206) by _time span=1h Web.src Web.user
| `drop_dm_object_name(Web)`
| where DistinctRecords > 200
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| sort - DistinctRecords
```

### Stolen DGFiP SPDC account used from multiple source IPs (valid-account + MFA-bypass access)

`UC_24_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(Web.src) as DistinctSourceIPs values(Web.src) as SourceIPs count as Requests min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.dest="apexappliext.dgfip.finances.gouv.fr" OR Web.site="apexappliext.dgfip.finances.gouv.fr") Web.user=* by _time span=24h Web.user
| `drop_dm_object_name(Web)`
| where DistinctSourceIPs >= 3
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - DistinctSourceIPs
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `apexappliexi.dgfp.finances.gouv.fr`


## Why this matters

Severity classified as **MED** based on: IOCs present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
