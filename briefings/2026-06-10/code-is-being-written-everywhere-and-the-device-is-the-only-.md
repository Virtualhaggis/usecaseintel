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
- **T1552.001** — Credentials In Files
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1071.003** — Application Layer Protocol: Mail Protocols
- **T1176** — Browser Extensions
- **T1547.013** — XDG Autostart Entries
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Developer credential file access by npm/yarn/pnpm postinstall hook

`UC_115_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.action IN ("read","create","modify") (Filesystem.file_path="*\\.aws\\credentials*" OR Filesystem.file_path="*\\.npmrc*" OR Filesystem.file_path="*\\.ssh\\id_rsa*" OR Filesystem.file_path="*\\.ssh\\id_ed25519*" OR Filesystem.file_path="*\\.docker\\config.json*" OR Filesystem.file_path="*\\.kube\\config*" OR Filesystem.file_path="*\\.netrc*") (Filesystem.process_name IN ("node.exe","npm.exe","yarn.exe","pnpm.exe") OR Filesystem.parent_process_name IN ("node.exe","npm.exe","yarn.exe","pnpm.exe")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.parent_process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let CredPaths = dynamic([@"\.aws\credentials", @"\.npmrc", @"\.ssh\id_rsa", @"\.ssh\id_ed25519", @"\.docker\config.json", @"\.kube\config", @"\.netrc", @"\.gnupg"]);
let PkgMgrs = dynamic(["node.exe","npm.exe","yarn.exe","pnpm.exe"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (CredPaths)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe") or InitiatingProcessParentFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe")
| where not(InitiatingProcessAccountName endswith "$")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FolderPath, FileName, ActionType
| order by Timestamp desc
```

### Node.js process establishing outbound SMTP/submission traffic post-npm-install

`UC_115_4` · phase: **exfil** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (25,465,587,2525) (All_Traffic.app IN ("node.exe","npm.exe","yarn.exe","pnpm.exe") OR All_Traffic.process_name IN ("node.exe","npm.exe","yarn.exe","pnpm.exe")) NOT (All_Traffic.dest_ip="10.0.0.0/8" OR All_Traffic.dest_ip="172.16.0.0/12" OR All_Traffic.dest_ip="192.168.0.0/16") by All_Traffic.src All_Traffic.user All_Traffic.app | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (25, 465, 587, 2525)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe") or InitiatingProcessParentFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe")
| where not(InitiatingProcessAccountName endswith "$")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### VS Code extension directory write followed by external beacon

`UC_115_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.action=create (Filesystem.file_path="*\\.vscode\\extensions\\*" OR Filesystem.file_path="*\\.vscode-insiders\\extensions\\*" OR Filesystem.file_path="*\\.vscode-server\\extensions\\*" OR Filesystem.file_path="*\\.cursor\\extensions\\*") (Filesystem.file_name="*.js" OR Filesystem.file_name="*.node" OR Filesystem.file_name="*.dll" OR Filesystem.file_name="*.exe" OR Filesystem.file_name="package.json") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | join type=inner dest [| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_category!=internal by All_Traffic.src All_Traffic.dest_ip All_Traffic.app | rename All_Traffic.src as dest All_Traffic.dest_ip as remote_ip All_Traffic.app as net_proc | `drop_dm_object_name(All_Traffic)`]
```

**Defender KQL:**
```kql
let ExtPaths = dynamic([@"\.vscode\extensions\", @"\.vscode-insiders\extensions\", @"\.vscode-server\extensions\", @"\.cursor\extensions\"]);
let ExtDrops = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FolderPath has_any (ExtPaths)
    | where ActionType in ("FileCreated","FileModified")
    | where FileName endswith ".js" or FileName endswith ".node" or FileName endswith ".dll" or FileName endswith ".exe" or FileName == "package.json"
    | project DropTime=Timestamp, DeviceId, DeviceName, ExtFolder=FolderPath, DroppedFile=FileName, Dropper=InitiatingProcessFileName, DropperCmd=InitiatingProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where InitiatingProcessFolderPath has_any (ExtPaths) or InitiatingProcessParentFileName in~ ("code.exe","code - insiders.exe","cursor.exe")
| join kind=inner ExtDrops on DeviceId
| where Timestamp between (DropTime .. DropTime + 30m)
| project DropTime, BeaconTime=Timestamp, DeviceName, ExtFolder, DroppedFile, Dropper, DropperCmd, BeaconProcess=InitiatingProcessFileName, BeaconCmd=InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by BeaconTime desc
```

### Developer endpoint contacting article-listed supply-chain C2 IPs or domains

`UC_115_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("142.11.206.73","45.32.150.251","45.32.151.157","70.34.242.255") by All_Traffic.src All_Traffic.user All_Traffic.dest_ip | `drop_dm_object_name(All_Traffic)` | append [| tstats summariesonly=true count from datamodel=Network_Resolution.DNS where (DNS.query IN ("giftshop.club","sfrclak.com") OR DNS.query="*.giftshop.club" OR DNS.query="*.sfrclak.com") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)`] | append [| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766") by Filesystem.dest Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
let C2Ips = dynamic(["142.11.206.73","45.32.150.251","45.32.151.157","70.34.242.255"]);
let C2Domains = dynamic(["giftshop.club","sfrclak.com"]);
let BadHashes = dynamic(["2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766"]);
union
  (DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP in (C2Ips) or RemoteUrl has_any (C2Domains)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Process=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Source="Network"),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA1 in (BadHashes)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Process=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine, RemoteIP="", RemoteUrl=FolderPath, RemotePort=int(0), Source=strcat("FileHash:",SHA1))
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
