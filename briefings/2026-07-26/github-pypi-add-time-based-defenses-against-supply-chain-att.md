# [HIGH] GitHub, PyPI add time-based defenses against supply chain attacks

**Source:** BleepingComputer
**Published:** 2026-07-26
**Article:** https://www.bleepingcomputer.com/news/security/github-pypi-add-time-absed-defenses-against-supply-chain-attacks/

## Threat Profile

GitHub, PyPI add time-absed defenses against supply chain attacks 
By Bill Toulas 
July 26, 2026
10:13 AM
0 
GitHub and PyPI (Python Package Index) have introduced a time-based mechanism in the Dependabot dependency management tool to protect against supply-chain attacks and to limit their impact.
Specifically, Dependabot comes with a default three-day cooldown setting, while PyPI will reject new files uploaded to releases older than 14 days.
The measure comes after the two development ecosystem…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `npmjs.help`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1566.002** — Phishing: Spearphishing Link
- **T1656** — Impersonation
- **T1598.003** — Phishing for Information: Spearphishing Link

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Phishing email from npm-lookalike domain npmjs.help

`UC_14_2` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
let win = 30d;
let bad = dynamic(["npmjs.help"]);
EmailEvents
| where Timestamp > ago(win)
| where SenderFromDomain in~ (bad) or SenderMailFromDomain in~ (bad)
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, ThreatTypes
| union (
    EmailUrlInfo
    | where Timestamp > ago(win)
    | where UrlDomain in~ (bad)
    | project Timestamp, NetworkMessageId, Url, UrlDomain
)
| order by Timestamp desc
```

### Endpoint DNS/HTTP connection to npm-phish portal npmjs.help

`UC_14_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest LIKE "%npmjs.help%" OR All_Traffic.url LIKE "%npmjs.help%" by All_Traffic.src All_Traffic.dest All_Traffic.url All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "npmjs.help"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `npmjs.help`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
