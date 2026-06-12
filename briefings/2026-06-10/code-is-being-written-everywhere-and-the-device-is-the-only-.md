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
- **T1568** — Dynamic Resolution
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1071.003** — Application Layer Protocol: Mail Protocols
- **T1567** — Exfiltration Over Web Service
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Beaconing from developer endpoint to known TeamPCP/GlassWorm IOC infrastructure

`UC_43_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("142.11.206.73","45.32.150.251","45.32.151.157","70.34.242.255") OR All_Traffic.dest IN ("giftshop.club","sfrclak.com","*.giftshop.club","*.sfrclak.com")) by host All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats summariesonly=t count from datamodel=Network_Resolution.DNS where DNS.query IN ("giftshop.club","sfrclak.com","*.giftshop.club","*.sfrclak.com") by host DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)`]
```

**Defender KQL:**
```kql
let IOC_IPs = dynamic(["142.11.206.73","45.32.150.251","45.32.151.157","70.34.242.255"]);
let IOC_Domains = dynamic(["giftshop.club","sfrclak.com"]);
union isfuzzy=true
  (DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP in (IOC_IPs) or RemoteUrl has_any (IOC_Domains)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Source="DeviceNetworkEvents"),
  (DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | where RemoteUrl has_any (IOC_Domains) or AdditionalFields has_any (IOC_IPs)
    | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort=int(null), Source="DeviceEvents-Dns")
| order by Timestamp desc
```

### NPM/Yarn/PNPM postinstall hook spawning credential-access tools

`UC_43_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("npm.exe","yarn.exe","pnpm.exe","node.exe","npx.exe","corepack.exe") AND (Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe","bash.exe","sh.exe") OR Processes.process IN ("*\\.aws\\credentials*","*\\.ssh\\id_*","*\\.npmrc*","*\\.docker\\config.json*","*kube\\config*","*aws s3*","*aws iam*","*aws sts*","*Invoke-WebRequest*","*DownloadString*","*GITHUB_TOKEN*","*NPM_TOKEN*")) by host Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("npm.exe","yarn.exe","pnpm.exe","node.exe","npx.exe","corepack.exe")
| where (FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe","bash.exe","sh.exe"))
   or ProcessCommandLine has_any (@"\.aws\credentials", @"\.ssh\id_", @"\.npmrc", @"\.docker\config.json", @"kube\config", "aws s3 ", "aws iam ", "aws sts ", "Invoke-WebRequest", "DownloadString", "GITHUB_TOKEN", "NPM_TOKEN", "gh auth token")
| where AccountName !endswith "$"
| where InitiatingProcessParentFileName !in~ ("explorer.exe")
| project Timestamp, DeviceName, AccountName, ParentImage=InitiatingProcessFolderPath, ParentCmd=InitiatingProcessCommandLine, ChildImage=FolderPath, ChildCmd=ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Malicious MCP server / node process opening outbound SMTP to non-corporate mail relay

`UC_43_5` · phase: **exfil** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ips from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("node.exe","node") AND All_Traffic.dest_port IN (25,465,587,2525,993,995) AND NOT (All_Traffic.dest_ip IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12") OR All_Traffic.dest IN ("smtp.corp.local","mail-relay-01.corp.local")) by host All_Traffic.user All_Traffic.app All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | where count > 0 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CorpMailRelays = dynamic(["smtp.corp.local","mail-relay-01.corp.local","outbound.protection.outlook.com","smtp.office365.com"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where RemotePort in (25, 465, 587, 2525, 993, 995)
| where RemoteIPType == "Public"
| where not (RemoteUrl has_any (CorpMailRelays))
| where InitiatingProcessAccountName !endswith "$"
| summarize Connections=count(), DistinctRemotes=dcount(RemoteIP), Remotes=make_set(RemoteIP, 20), Urls=make_set(RemoteUrl, 20), SampleCmd=any(InitiatingProcessCommandLine) by DeviceName, AccountName=InitiatingProcessAccountName, RemotePort, bin(Timestamp, 1h)
| where Connections > 0
| order by Timestamp desc
```

### Known SHA1 IOC from Aikido June-2026 supply chain advisory observed on endpoint

`UC_43_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766") by host Processes.user Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats summariesonly=t count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766") by host Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
let IOC_SHA1 = dynamic(["2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766"]);
union isfuzzy=true
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA1 in~ (IOC_SHA1)
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1, Cmdline=ProcessCommandLine, Source="DeviceProcessEvents"),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA1 in~ (IOC_SHA1)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA1, Cmdline=InitiatingProcessCommandLine, Source="DeviceFileEvents"),
  (DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA1 in~ (IOC_SHA1)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA1, Cmdline=InitiatingProcessCommandLine, Source="DeviceImageLoadEvents")
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
