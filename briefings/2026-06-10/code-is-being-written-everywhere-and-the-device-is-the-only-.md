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
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1102** — Web Service
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms
- **T1204.002** — User Execution: Malicious File
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1546.016** — Event Triggered Execution: Installer Packages

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Dev tooling beaconing to postmark-mcp / GlassWorm campaign infrastructure (giftshop.club, sfrclak.com)

`UC_160_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("142.11.206.73","45.32.150.251","45.32.151.157","70.34.242.255") OR All_Traffic.dest_host IN ("giftshop.club","sfrclak.com") OR All_Traffic.dest_host="*.giftshop.club" OR All_Traffic.dest_host="*.sfrclak.com") by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query IN ("giftshop.club","sfrclak.com") OR DNS.query="*.giftshop.club" OR DNS.query="*.sfrclak.com") by DNS.src DNS.query host | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) ]
```

**Defender KQL:**
```kql
let BadIPs = dynamic(["142.11.206.73","45.32.150.251","45.32.151.157","70.34.242.255"]);
let BadDomains = dynamic(["giftshop.club","sfrclak.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (BadIPs) or RemoteUrl has_any (BadDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### VS Code / Cursor / node reaching Solana blockchain RPC endpoints (GlassWorm C2 channel)

`UC_160_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*solana.com" OR DNS.query="*helius.xyz" OR DNS.query="*solscan.io" OR DNS.query="*solana-rpc.com" OR DNS.query="*genesysgo.net") by host DNS.src DNS.query | `drop_dm_object_name(DNS)` | join host [ | tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process_name IN ("Code.exe","Cursor.exe","node.exe","npm.exe","npx.exe","Code - Insiders.exe","WindsurfNext.exe")) by host Processes.process_name Processes.user | `drop_dm_object_name(Processes)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let SolanaDomains = dynamic(["solana.com","mainnet-beta.solana.com","api.mainnet-beta.solana.com","api.devnet.solana.com","api.testnet.solana.com","helius.xyz","helius-rpc.com","solscan.io","solana-rpc.com","genesysgo.net","quicknode.com"]);
let DevTools = dynamic(["Code.exe","Cursor.exe","node.exe","npm.exe","npx.exe","Code - Insiders.exe","WindsurfNext.exe","electron.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (DevTools)
| where RemoteUrl has_any (SolanaDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### Execution or file write of known GlassWorm / postmark-mcp sample SHA1 hashes

`UC_160_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_sha1 IN ("2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766") by host Processes.user Processes.process_name Processes.process_path Processes.process_sha1 Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766") by host Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) ]
```

**Defender KQL:**
```kql
let BadSHA1 = dynamic(["2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766"]);
union isfuzzy=true
  (DeviceProcessEvents
   | where Timestamp > ago(90d)
   | where SHA1 in (BadSHA1) or InitiatingProcessSHA1 in (BadSHA1)
   | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessSHA1, ProcessCommandLine, IndicatorType="ProcessExec"),
  (DeviceFileEvents
   | where Timestamp > ago(90d)
   | where SHA1 in (BadSHA1)
   | project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine, IndicatorType="FileWrite")
| order by Timestamp desc
```

### npm / node postinstall hook spawning network-capable LOLBin (supply-chain post-install execution)

`UC_160_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","npm.exe","npm-cli.js","yarn.exe","pnpm.exe","npx.exe")) AND (Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe","mshta.exe")) by host Processes.user Processes.parent_process Processes.process Processes.process_name Processes.parent_process_name Processes.process_path | `drop_dm_object_name(Processes)` | where match(process, "(?i)(downloadstring|invoke-webrequest|invoke-restmethod|iex|iwr|http://|https://|curl\s|wget\s|-encodedcommand|certutil.*urlcache|bitsadmin.*transfer)") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe","npx.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe","mshta.exe")
| where ProcessCommandLine has_any ("DownloadString","Invoke-WebRequest","Invoke-RestMethod","IEX","iwr","http://","https://","curl ","wget ","-EncodedCommand","-enc ","urlcache","bitsadmin /transfer","BITSADMIN")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
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

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
