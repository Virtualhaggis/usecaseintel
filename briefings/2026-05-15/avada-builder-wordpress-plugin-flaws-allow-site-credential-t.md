# [HIGH] Avada Builder WordPress plugin flaws allow site credential theft

**Source:** BleepingComputer
**Published:** 2026-05-15
**Article:** https://www.bleepingcomputer.com/news/security/avada-builder-wordpress-plugin-flaws-allow-site-credential-theft/

## Threat Profile

Avada Builder WordPress plugin flaws allow site credential theft 
By Bill Toulas 
May 15, 2026
11:56 AM
0 
Two vulnerabilities in the Avada Builder plugin for WordPress, with an estimated one million active installations, allow hackers to read arbitrary files and extract sensitive information from the database.
One of the flaws is tracked as CVE-2026-4782 and can be exploited in all versions of the plugin through 3.15.2 by an authenticated users with at least subscriber-level access to read the …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-4782`
- **CVE:** `CVE-2026-4798`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1083** — File and Directory Discovery
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1505.003** — Server Software Component: Web Shell
- **T1212** — Exploitation for Credential Access

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Avada Builder CVE-2026-4782 arbitrary file read via fusion_section_separator custom_svg parameter

`UC_8_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.uri_path) as uri_path values(Web.uri_query) as uri_query values(Web.http_user_agent) as user_agent values(Web.status) as status from datamodel=Web where (Web.uri_query="*custom_svg=*" OR Web.uri_query="*custom_svg%3D*" OR Web.url="*custom_svg=*") AND (Web.uri_query="*wp-config*" OR Web.uri_query="*etc/passwd*" OR Web.uri_query="*etc%2Fpasswd*" OR Web.uri_query="*.htaccess*" OR Web.uri_query="*..%2F*" OR Web.uri_query="*..%5C*" OR Web.uri_query="*..\/*" OR Web.uri_query="*php://filter*" OR Web.uri_query="*php%3A%2F%2Ffilter*") by Web.src Web.dest Web.user Web.http_method Web.uri_path | `drop_dm_object_name(Web)` | rename src as src_ip dest as host
```

### [LLM] Avada Builder CVE-2026-4798 unauthenticated time-based SQL injection via product_order ORDER BY

`UC_8_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.uri_path) as uri_path values(Web.uri_query) as uri_query values(Web.http_user_agent) as user_agent values(Web.status) as status values(Web.bytes_out) as bytes_out from datamodel=Web where (Web.uri_query="*product_order=*" OR Web.uri_query="*product_order%3D*" OR Web.url="*product_order=*") AND (Web.uri_query="*SLEEP(*" OR Web.uri_query="*SLEEP%28*" OR Web.uri_query="*BENCHMARK(*" OR Web.uri_query="*BENCHMARK%28*" OR Web.uri_query="*pg_sleep*" OR Web.uri_query="*WAITFOR*DELAY*" OR Web.uri_query="*WAITFOR%20DELAY*" OR Web.uri_query="*UNION*SELECT*" OR Web.uri_query="*UNION%20SELECT*" OR Web.uri_query="*information_schema*" OR Web.uri_query="*0x73656c656374*") by Web.src Web.dest Web.user Web.http_method Web.uri_path | `drop_dm_object_name(Web)` | rename src as src_ip dest as host | eval cve="CVE-2026-4798"
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-4782`, `CVE-2026-4798`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
