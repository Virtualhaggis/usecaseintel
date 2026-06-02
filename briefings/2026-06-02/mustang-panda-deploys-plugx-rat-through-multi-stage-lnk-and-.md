# [MED] Mustang Panda Deploys PlugX RAT Through Multi-Stage LNK and PowerShell Attack Chain

**Source:** Cyber Security News
**Published:** 2026-06-02
**Article:** https://cybersecuritynews.com/mustang-panda-deploys-plugx-rat/

## Threat Profile

A well-known Chinese state-sponsored threat group called Mustang Panda has been caught running a sophisticated cyberattack campaign using its signature remote access tool, PlugX. The group used a cleverly disguised fake browser update to trick users into downloading a multi-stage malware loader that quietly installed itself on victim systems and began communicating with a remote [&#8230;] The post Mustang Panda Deploys PlugX RAT Through Multi-Stage LNK and PowerShell Attack Chain appeared first …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `45.251.243.210`
- **Domain (defanged):** `fruitbrat.com`
- **Domain (defanged):** `dalerocks.com`
- **Domain (defanged):** `coastallasercompany.com`
- **SHA256:** `79af67ed343bc45b6a19e4836ebb83f1130243ff98f48465f9a7a807ba4bfa91`
- **SHA256:** `106f46375d8497d353c22c98f72ab15a9bb87beba4585d5a492fd11edc288b0b`
- **SHA256:** `8421e7995778faf1f2a902fb2c51d85ae39481f443b7b3186068d5c33c472d99`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
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

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.251.243.210`, `fruitbrat.com`, `dalerocks.com`, `coastallasercompany.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `79af67ed343bc45b6a19e4836ebb83f1130243ff98f48465f9a7a807ba4bfa91`, `106f46375d8497d353c22c98f72ab15a9bb87beba4585d5a492fd11edc288b0b`, `8421e7995778faf1f2a902fb2c51d85ae39481f443b7b3186068d5c33c472d99`


## Why this matters

Severity classified as **MED** based on: IOCs present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
