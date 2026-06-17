# [HIGH] Microsoft working on Defender patch for RoguePlanet zero-day

**Source:** BleepingComputer
**Published:** 2026-06-17
**Article:** https://www.bleepingcomputer.com/news/microsoft/microsoft-working-on-defender-patch-for-rogueplanet-zero-day/

## Threat Profile

Microsoft working on Defender patch for RoguePlanet zero-day 
By Sergiu Gatlan 
June 17, 2026
04:32 AM
0 
Microsoft confirmed that it's working on a security patch for a Defender zero-day vulnerability named "RoguePlanet," disclosed one week ago.
The security researcher who published a RoguePlanet exploit during the June 2026 Patch Tuesday (known as Nightmare Eclipse) said it affects fully patched Windows 10 and Windows 11 devices and allows attackers to spawn command prompts with SYSTEM privile…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-50656`
- **CVE:** `CVE-2026-33825`
- **CVE:** `CVE-2026-45498`
- **CVE:** `CVE-2026-45585`
- **CVE:** `CVE-2026-45586`
- **CVE:** `CVE-2020-17103`
- **Domain (defanged):** `projectnightcrawler.dev`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1068** — Exploitation for Privilege Escalation
- **T1211** — Exploitation for Defense Evasion
- **T1588.005** — Obtain Capabilities: Exploits
- **T1583.001** — Acquire Infrastructure: Domains

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Microsoft Defender Engine (MsMpEng) spawning interactive shell - RoguePlanet CVE-2026-50656

`UC_14_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE Processes.parent_process_name IN ("MsMpEng.exe","MpCmdRun.exe","NisSrv.exe") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","conhost.exe") BY Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_integrity_level | `drop_dm_object_name(Processes)` | where process_integrity_level="system" OR user="SYSTEM" OR user="NT AUTHORITY\\SYSTEM" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("MsMpEng.exe","MpCmdRun.exe","NisSrv.exe","MsMpEngCP.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","conhost.exe")
| where ProcessIntegrityLevel =~ "System" or AccountName =~ "system"
| project Timestamp, DeviceName, AccountName, AccountDomain,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          ProcessIntegrityLevel, SHA256
| order by Timestamp desc
```

### Endpoint DNS / web access to Nightmare Eclipse exploit-hosting domain projectnightcrawler.dev

`UC_14_3` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Network_Resolution.DNS WHERE (DNS.query="projectnightcrawler.dev" OR DNS.query="*.projectnightcrawler.dev") BY DNS.src DNS.query DNS.answer DNS.record_type | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
(
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has "projectnightcrawler.dev"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              RemoteUrl, RemoteIP, RemotePort, Source="NetworkEvent"
),
(
    DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | where AdditionalFields has "projectnightcrawler.dev"
    | project Timestamp, DeviceName, AccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              RemoteUrl=tostring(parse_json(AdditionalFields).query),
              RemoteIP="", RemotePort=int(0), Source="DnsQuery"
)
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-50656`, `CVE-2026-33825`, `CVE-2026-45498`, `CVE-2026-45585`, `CVE-2026-45586`, `CVE-2020-17103`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `projectnightcrawler.dev`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
