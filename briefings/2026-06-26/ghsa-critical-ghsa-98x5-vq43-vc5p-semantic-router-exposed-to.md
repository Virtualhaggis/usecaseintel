# [CRIT] [GHSA / CRITICAL] GHSA-98x5-vq43-vc5p: semantic-router exposed to compromised litellm wheel (CVE-2026-42208) via unbounded transitive pin

**Source:** GitHub Security Advisories
**Published:** 2026-06-26
**Article:** https://github.com/advisories/GHSA-98x5-vq43-vc5p

## Threat Profile

semantic-router exposed to compromised litellm wheel (CVE-2026-42208) via unbounded transitive pin

## Impact
semantic-router versions 0.1.8 through 0.1.14 declare `litellm>=1.61.3` with no upper bound. During the window in which `litellm==1.82.8` was the latest release on PyPI, a fresh install of any affected semantic-router version could resolve to that compromised wheel.

The malicious `litellm==1.82.8` wheel ships a `litellm_init.pth` file that executes on Python interpreter startup — no imp…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-42208`
- **Domain (defanged):** `models.litellm.cloud`
- **Domain (defanged):** `checkmarx.zone`
- **SHA256:** `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238`
- **SHA256:** `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b`
- **SHA256:** `6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1546.016** — Event Triggered Execution: Installer Packages
- **T1567** — Exfiltration Over Web Service
- **T1041** — Exfiltration Over C2 Channel
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Malicious litellm_init.pth startup hook dropped in site-packages (CVE-2026-42208)

`UC_271_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="litellm_init.pth" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.action Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where like(file_path,"%site-packages%") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "litellm_init.pth"
| where FolderPath has "site-packages"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### litellm supply-chain exfil beacon to models.litellm.cloud (CVE-2026-42208)

`UC_271_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="models.litellm.cloud" OR DNS.query="*.litellm.cloud" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "models.litellm.cloud"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-42208`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `models.litellm.cloud`, `checkmarx.zone`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238`, `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b`, `6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
