# [LOW] UNC3753 Uses Screen-Sharing Sessions and RMM Tools to Exfiltrate Sensitive Legal Data

**Source:** Cyber Security News
**Published:** 2026-06-17
**Article:** https://cybersecuritynews.com/unc3753-uses-screen-sharing-sessions-and-rmm-tools/

## Threat Profile

A sophisticated cybercriminal group has been quietly targeting law firms and professional services organizations across the United States since the beginning of 2026. The campaign is financially motivated and relies heavily on deception rather than technical exploits. Victims are manipulated into handing over access to their own systems, and by the time they realize what [&#8230;] The post UNC3753 Uses Screen-Sharing Sessions and RMM Tools to Exfiltrate Sensitive Legal Data appeared first on Cyb…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `192.236.147.131`
- **IPv4 (defanged):** `192.236.147.138`
- **IPv4 (defanged):** `193.141.60.212`
- **IPv4 (defanged):** `192.236.154.158`
- **IPv4 (defanged):** `192.236.146.173`
- **IPv4 (defanged):** `174.169.162.62`
- **IPv4 (defanged):** `64.94.84.97`
- **Domain (defanged):** `business-data-leaks.com`

## MITRE ATT&CK Techniques

- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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
  - IP / domain IOC(s): `192.236.147.131`, `192.236.147.138`, `193.141.60.212`, `192.236.154.158`, `192.236.146.173`, `174.169.162.62`, `64.94.84.97`, `business-data-leaks.com`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
