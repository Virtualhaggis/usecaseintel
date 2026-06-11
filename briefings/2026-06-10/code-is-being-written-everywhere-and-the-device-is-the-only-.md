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
- **T1059.007** — JavaScript
- **T1567** — Exfiltration Over Web Service
- **T1071.003** — Mail Protocols
- **T1020** — Automated Exfiltration
- **T1176** — Browser Extensions
- **T1554** — Compromise Host Software Binary
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1568** — Dynamic Resolution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Postmark-MCP supply-chain backdoor: npm install of postmark-mcp package

`UC_39_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*node_modules*postmark-mcp*") AND (Filesystem.process_name="npm.exe" OR Filesystem.process_name="node.exe" OR Filesystem.process_name="yarn.exe" OR Filesystem.process_name="pnpm.exe" OR Filesystem.process_name="npx.exe" OR Filesystem.process_name="bun.exe") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\node_modules\postmark-mcp" or FolderPath has "/node_modules/postmark-mcp"
| where InitiatingProcessFileName in~ ("npm.exe","npm.cmd","node.exe","yarn.exe","yarn.cmd","pnpm.exe","npx.exe","npx.cmd","bun.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Postmark-MCP exfiltration: BCC mail or DNS lookup for giftshop.club

`UC_39_4` · phase: **exfil** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*giftshop.club*" by DNS.src DNS.query DNS.answer DNS.process_name | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=true count from datamodel=Email.All_Email where (All_Email.recipient="*@giftshop.club" OR All_Email.bcc="*@giftshop.club" OR All_Email.src_user="*@giftshop.club") by All_Email.src_user All_Email.recipient All_Email.subject | `drop_dm_object_name(All_Email)`] | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
union
  (EmailEvents
   | where Timestamp > ago(30d)
   | where RecipientEmailAddress endswith "@giftshop.club" or SenderFromAddress endswith "@giftshop.club" or SenderMailFromAddress endswith "@giftshop.club"
   | extend Signal = "EmailEvents", Detail = strcat("sender=", SenderFromAddress, " recipient=", RecipientEmailAddress, " subject=", Subject)
   | project Timestamp, Signal, Detail, NetworkMessageId, EmailDirection, DeliveryAction),
  (DeviceNetworkEvents
   | where Timestamp > ago(30d)
   | where RemoteUrl has "giftshop.club" or AdditionalFields has "giftshop.club"
   | extend Signal = "DeviceNetworkEvents", Detail = strcat("url=", RemoteUrl, " ip=", RemoteIP, " proc=", InitiatingProcessFileName)
   | project Timestamp, Signal, Detail, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort)
| order by Timestamp desc
```

### GlassWorm: install of known Open VSX extensions (otoboss / federicanc / oigotm / twilkbilk / crotoapp)

`UC_39_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.vscode\\extensions\\otoboss.autoimport-extension*" OR Filesystem.file_path="*\\.vscode\\extensions\\federicanc.dotenv-syntax-highlighting*" OR Filesystem.file_path="*\\.vscode\\extensions\\oigotm.my-command-palette-extension*" OR Filesystem.file_path="*\\.vscode\\extensions\\twilkbilk.color-highlight-css*" OR Filesystem.file_path="*\\.vscode\\extensions\\crotoapp.vscode-xml-extension*" OR Filesystem.file_path="*/.vscode/extensions/otoboss.autoimport-extension*" OR Filesystem.file_path="*/.vscode/extensions/federicanc.dotenv-syntax-highlighting*" OR Filesystem.file_path="*/.vscode/extensions/oigotm.my-command-palette-extension*" OR Filesystem.file_path="*/.vscode/extensions/twilkbilk.color-highlight-css*" OR Filesystem.file_path="*/.vscode/extensions/crotoapp.vscode-xml-extension*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let glasswormExtensions = dynamic(["otoboss.autoimport-extension","federicanc.dotenv-syntax-highlighting","oigotm.my-command-palette-extension","twilkbilk.color-highlight-css","crotoapp.vscode-xml-extension"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\.vscode\extensions\" or FolderPath has "/.vscode/extensions/" or FolderPath has @"\.vscode-server\extensions\" or FolderPath has "/.vscode-server/extensions/"
| extend ExtDir = tolower(extract(@"[\\/]\.?vscode(?:-server)?[\\/]extensions[\\/]([^\\/]+?)(?:-\d+\.\d+\.\d+)?[\\/]", 1, FolderPath))
| where isnotempty(ExtDir)
| where ExtDir in~ (glasswormExtensions) or ExtDir has_any (glasswormExtensions)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, SHA256, ExtDir, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### GlassWorm C2 beacon to Vultr-hosted infrastructure (45.32.150.251 / 45.32.151.157 / 70.34.242.255)

`UC_39_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_ports values(All_Traffic.app) as apps values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest in ("45.32.150.251","45.32.151.157","70.34.242.255") AND All_Traffic.src_category!="perimeter_scanner" by All_Traffic.src All_Traffic.dest All_Traffic.user All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let glasswormC2 = dynamic(["45.32.150.251","45.32.151.157","70.34.242.255"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (glasswormC2)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","InboundConnectionAccepted")
| where InitiatingProcessAccountName !endswith "$"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Connections=count(),
           Ports=make_set(RemotePort, 16), Processes=make_set(InitiatingProcessFileName, 16),
           Cmds=make_set(InitiatingProcessCommandLine, 8)
           by DeviceName, RemoteIP, InitiatingProcessAccountName
| order by FirstSeen desc
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

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
