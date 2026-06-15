# [LOW] Hackers Abuse LNK Files, PowerShell, and Python Loader to Deploy NarwhalRAT

**Source:** Cyber Security News
**Published:** 2026-06-15
**Article:** https://cybersecuritynews.com/powershell-and-python-loader-to-deploy-narwhalrat/

## Threat Profile

A sophisticated malware campaign is quietly targeting Korean users through a well-crafted chain of deception. Threat actors are using innocent-looking shortcut files, built-in Windows tools, and a compiled Python payload to plant a remote access trojan called NarwhalRAT on victim machines. The attack stands out for how cleverly it blends into normal system activity, making [&#8230;] The post Hackers Abuse LNK Files, PowerShell, and Python Loader to Deploy NarwhalRAT appeared first on Cyber Secur…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `daehoat.com`
- **Domain (defanged):** `novel21.co.kr`
- **Domain (defanged):** `fe01.co.kr`
- **Domain (defanged):** `webhostingkorea.com`

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
  - IP / domain IOC(s): `daehoat.com`, `novel21.co.kr`, `fe01.co.kr`, `webhostingkorea.com`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
