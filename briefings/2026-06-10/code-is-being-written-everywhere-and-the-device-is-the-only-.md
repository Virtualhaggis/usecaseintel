# [HIGH] Code is being written everywhere, and the device is the only constant

**Source:** Aikido
**Published:** 2026-06-10
**Article:** https://www.aikido.dev/blog/code-is-written-everywhere

## Threat Profile

Blog News Code is being written everywhere, and the device is the only constant Code is being written everywhere, and the device is the only constant Written by Nicholas Thomson Published on: Jun 10, 2026 This post is based on Mackenzie's conversation with James Hawkins on The Secure Disclosure podcast . Listen to the full episode or watch below. 
PostHog's engineering team is merging roughly as many pull requests through Slack as through their code editor. As James Hawkins, co-founder and co-CE…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `142.11.206.73`
- **IPv4 (defanged):** `45.32.150.251`
- **IPv4 (defanged):** `45.32.151.157`
- **IPv4 (defanged):** `70.34.242.255`
- **Domain (defanged):** `giftshop.club`
- **Domain (defanged):** `sfrclak.com`
- **SHA1:** `2553649f2322049666871cea80a5d0d6adc700ca`
- **SHA1:** `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71`
- **SHA1:** `07d889e2dadce6f3910dcbc253317d28ca61c766`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1204.002** — User Execution: Malicious File
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1567** — Exfiltration Over Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Malicious 'postmark-mcp' MCP package or known supply-chain payload written to developer device

`UC_192_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\node_modules\\postmark-mcp\\*" OR Filesystem.file_hash IN ("2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_id | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let badHashes = dynamic(["2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\node_modules\postmark-mcp" or SHA1 in~ (badHashes)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA1,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Exfil/C2 callout to postmark-mcp BCC domain giftshop.club

`UC_192_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*giftshop.club*" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "giftshop.club"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### GlassWorm C2 / ZOMBI payload beacon to known Vultr infrastructure

`UC_192_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("45.32.150.251","217.69.3.218","45.32.151.157","142.11.206.73","70.34.242.255") by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let c2 = dynamic(["45.32.150.251","217.69.3.218","45.32.151.157","142.11.206.73","70.34.242.255"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (c2) or RemoteUrl has "get_zombi_payload"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
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
  - IP / domain IOC(s): `142.11.206.73`, `45.32.150.251`, `45.32.151.157`, `70.34.242.255`, `giftshop.club`, `sfrclak.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `2553649f2322049666871cea80a5d0d6adc700ca`, `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71`, `07d889e2dadce6f3910dcbc253317d28ca61c766`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
