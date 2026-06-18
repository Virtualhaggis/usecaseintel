# [MED] Hackers Abuse PowerShell, VBScript, and BAT Files to Deliver Xctdoor Backdoor

**Source:** Cyber Security News
**Published:** 2026-06-18
**Article:** https://cybersecuritynews.com/hackers-abuse-powershell-deliver-xctdoor-backdoor/

## Threat Profile

A new wave of cyberattacks is targeting corporate employees through files that look exactly like legitimate job documents. Hackers are distributing malicious LNK files disguised as resumes, and the moment a victim opens one, the infection quietly begins. The attack is sophisticated enough to fool cautious users, since the file shows a believable resume while [&#8230;] The post Hackers Abuse PowerShell, VBScript, and BAT Files to Deliver Xctdoor Backdoor appeared first on Cyber Security News .

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `195.50.242.110`
- **Domain (defanged):** `beebeep.info`
- **Domain (defanged):** `www.jikji.pe.kr`
- **MD5:** `235e02eba12286e74e886b6c99e46fb7`
- **MD5:** `396bee51c7485c3a0d3b044a9ceb6487`
- **MD5:** `ab8675b4943bc25a51da66565cfc8ac8`
- **MD5:** `f24627f46ec64cae7a6fa9ee312c43d7`
- **MD5:** `6928fab25ac1255fbd8d6c1046653919`
- **MD5:** `9a580aaaa3e79b6f19a2c70e89b016e3`
- **MD5:** `a42ae44761ce3294ce0775fe384d97b6`
- **MD5:** `d852c3d06ef63ea6c6a21b0d1cdf14d4`
- **MD5:** `2e325935b2d1d0a82e63ff2876482956`
- **MD5:** `4f5e5a392b8a3e0cb32320ed1e8d0604`
- **MD5:** `54d5be3a4eb0e31c0ba7cb88f0a8e720`
- **MD5:** `b43a7dcfe53a981831ae763a9a5450fd`
- **MD5:** `e554b1be8bab11e979c75e2c2453bc6a`
- **MD5:** `41d5d25de0ca0fdc54c24c484f9f8f55`
- **MD5:** `b96b98dede8a64373b539f94042bdb41`
- **MD5:** `375f1cc32b6493662a78720c7d905bc3`
- **MD5:** `d938201644aac3421df7a3128aa88a53`
- **MD5:** `d787a33d76552019becfef0a4af78a11`
- **MD5:** `09a5069c9cc87af39bbb6356af2c1a36`
- **MD5:** `ad96a8f22faab8b9c361cfccc381cd28`
- **MD5:** `9bbde4484821335d98b41b44f93276e8`
- **MD5:** `11465d02b0d7231730f3c4202b0400b8`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `195.50.242.110`, `beebeep.info`, `www.jikji.pe.kr`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `235e02eba12286e74e886b6c99e46fb7`, `396bee51c7485c3a0d3b044a9ceb6487`, `ab8675b4943bc25a51da66565cfc8ac8`, `f24627f46ec64cae7a6fa9ee312c43d7`, `6928fab25ac1255fbd8d6c1046653919`, `9a580aaaa3e79b6f19a2c70e89b016e3`, `a42ae44761ce3294ce0775fe384d97b6`, `d852c3d06ef63ea6c6a21b0d1cdf14d4` _(+14 more)_


## Why this matters

Severity classified as **MED** based on: IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
