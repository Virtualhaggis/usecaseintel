# [HIGH] Hacker uses DeepSeek AI to autonomously attack vulnerable servers

**Source:** BleepingComputer
**Published:** 2026-07-31
**Article:** https://www.bleepingcomputer.com/news/security/hacker-uses-deepseek-ai-to-autonomously-attack-vulnerable-servers/

## Threat Profile

Hacker uses DeepSeek AI to autonomously attack vulnerable servers 
By Lawrence Abrams 
July 31, 2026
01:35 PM
0 
A Chinese-speaking threat actor is using the DeepSeek AI model and the open-source Hermes Agent to conduct autonomous cyberattacks on exposed servers with limited human involvement.
The activity was discovered by Palo Alto Networks' Unit 42 researchers after Hermes accidentally created a web server from its home directory, exposing the attacker's environment, including API keys, explo…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33017`
- **CVE:** `CVE-2026-21858`
- **CVE:** `CVE-2025-68613`
- **CVE:** `CVE-2026-3055`
- **CVE:** `CVE-2026-39987`
- **CVE:** `CVE-2026-34486`
- **CVE:** `CVE-2026-33824`
- **Domain (defanged):** `code.newcli.com`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1212** — Exploitation for Credential Access

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### CVE-2026-3055 NetScaler SAML IdP memory-overread scrape (rapid /saml/login loop)

`UC_15_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as request_count, values(Web.url) as urls, min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where Web.url="*/saml/login*" (Web.dest_port=443 OR Web.dest_port=80) by Web.src, Web.dest, Web.http_user_agent, _time span=10m
| `drop_dm_object_name(Web)`
| where request_count > 50
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - request_count
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33017`, `CVE-2026-21858`, `CVE-2025-68613`, `CVE-2026-3055`, `CVE-2026-39987`, `CVE-2026-34486`, `CVE-2026-33824`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `code.newcli.com`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
