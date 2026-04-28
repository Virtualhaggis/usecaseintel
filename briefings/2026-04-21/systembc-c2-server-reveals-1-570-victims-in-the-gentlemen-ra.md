<!-- curated:true -->
# [HIGH] SystemBC C2 Server Reveals 1,570+ Victims in The Gentlemen Ransomware Operation

**Source:** The Hacker News
**Published:** 2026-04-21
**Article:** https://thehackernews.com/2026/04/systembc-c2-server-reveals-1570-victims.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Researchers infiltrated a **SystemBC** C2 server and discovered 1,570+ active victims tied to **"The Gentlemen"** ransomware operation. SystemBC is a long-standing modular SOCKS5 proxy / backdoor that has been used by *many* ransomware affiliates as a tunnel for lateral movement and exfiltration — Conti, Ryuk, Egregor, BlackCat have all leveraged it historically.

The 1,570 number is a **lower bound on currently-compromised organisations**, not victims of public extortion. If your environment isn't on a public leak site, that doesn't mean you're not in the data — SystemBC is the foothold, the encryption/extortion comes later.

## Indicators of Compromise

- _Article mentions a C2 server but does not publish IOCs in the RSS summary._
- Look for SystemBC IOC drops from the originating researcher report; cross-reference at `urlhaus.abuse.ch` and `threatfox.abuse.ch` for `tag:SystemBC`.

## MITRE ATT&CK (analyst-validated)

- **T1090.002** — External Proxy (SystemBC's core function — outbound SOCKS5 to attacker infra)
- **T1071.001** — Web Protocols (HTTP/HTTPS C2 channel)
- **T1547.001** — Registry Run Keys (typical SystemBC persistence)
- **T1059.001** — PowerShell (often the loader)
- **T1486** — Data Encrypted for Impact (the eventual ransomware step)
- **T1003.001** — LSASS Memory (the credential-theft step before lateral movement)
- **T1021.002** — SMB/Windows Admin Shares (lateral movement vector)

## Recommended SOC actions (priority-ordered)

1. **Hunt for SystemBC behaviour on your fleet.** SystemBC is well-fingerprinted: known unusual outbound SOCKS5, specific service-creation patterns, and characteristic registry persistence keys. Run the queries below.
2. **Pull a fresh SystemBC IOC list from threatfox/urlhaus** and load into your `inputlookup` / Defender custom indicators. (URL in our `intel/iocs.csv` or pull from abuse.ch directly.)
3. **Audit any service installs in last 14 days** with `binPath` pointing at `\Users\`, `\AppData\`, `\ProgramData\` — SystemBC's typical install location.
4. **If a hit lands, treat as ransomware-in-progress.** SystemBC by itself isn't impact; it's the precursor. Your detection-to-encryption window may be hours.

## Splunk SPL — SystemBC service-install pattern

```spl
| tstats `summariesonly` count min(_time) AS firstTime max(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="sc.exe" AND Processes.process="*create*"
      AND (Processes.process="*\\Users\\*" OR Processes.process="*\\AppData\\*"
        OR Processes.process="*\\ProgramData\\*" OR Processes.process="*\\Temp\\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
```

## Splunk SPL — Registry Run-key persistence (SystemBC favourite)

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Registry
    where Registry.registry_path IN (
        "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
        "*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*")
      AND (Registry.registry_value_data="*\\AppData\\*"
        OR Registry.registry_value_data="*\\Users\\Public\\*"
        OR Registry.registry_value_data="*\\ProgramData\\*"
        OR Registry.registry_value_data="*.exe*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_name,
       Registry.registry_value_data, Registry.user
| `drop_dm_object_name(Registry)`
```

## Defender KQL — SOCKS5-style outbound to non-standard ports

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| where RemotePort in (1080, 4145, 9050, 9150)
   or (RemotePort > 10000 and RemotePort < 65535)
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe",
                                          "slack.exe","teams.exe","zoom.exe","outlook.exe")
| summarize sessions = count(), bytes_out = sum(InitiatingProcessId)
    by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where sessions > 5
| order by sessions desc
```

## Defender KQL — known-bad SOCKS5 destinations (paste in IOCs as they're released)

```kql
let bad = dynamic(["1.2.3.4","5.6.7.8"]);  // <-- paste fresh SystemBC IPs from threatfox here
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (bad)
| project Timestamp, DeviceName, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

SystemBC has been around since 2018 and **continues to be repurposed by every major ransomware crew**. The 1,570-victim count means there's a non-trivial probability your environment is on the list and just hasn't been encrypted yet. Catching SystemBC during the *proxy/staging* phase (typically 2-7 days before encryption) is the difference between an incident response and a disaster. The hunts above target the structural patterns SystemBC uses — they'll catch the family even when specific IPs/hashes change.
