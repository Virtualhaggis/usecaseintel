# [MED] ErrTraffic MaaS Uses Fake reCAPTCHA and Cloudflare Turnstile Lures to Execute PowerShell Commands

**Source:** Cyber Security News
**Published:** 2026-06-17
**Article:** https://cybersecuritynews.com/errtraffic-maas-uses-fake-recaptcha-and-cloudflare-turnstile-lures/

## Threat Profile

A new and rapidly growing cybercrime tool called ErrTraffic is making waves across the threat landscape, targeting internet users through cleverly disguised verification screens. The framework tricks victims into running malicious PowerShell commands on their own machines, all while believing they are simply completing a routine security check. It first appeared in late 2025 and [&#8230;] The post ErrTraffic MaaS Uses Fake reCAPTCHA and Cloudflare Turnstile Lures to Execute PowerShell Commands a…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `96.178.187.175`
- **IPv4 (defanged):** `96.181.156.219`
- **IPv4 (defanged):** `172.59.242.93`
- **IPv4 (defanged):** `68.60.174.238`
- **Domain (defanged):** `webanalytics-cdn.sbs`
- **Domain (defanged):** `llc-image-ico.click`
- **Domain (defanged):** `antigravity.study`
- **Domain (defanged):** `chatgpt-web.vip`

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
  - IP / domain IOC(s): `96.178.187.175`, `96.181.156.219`, `172.59.242.93`, `68.60.174.238`, `webanalytics-cdn.sbs`, `llc-image-ico.click`, `antigravity.study`, `chatgpt-web.vip`


## Why this matters

Severity classified as **MED** based on: IOCs present, 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
