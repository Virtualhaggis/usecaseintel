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
- **T1204.002** — Malicious File
- **T1546.016** — Installer Packages
- **T1071.001** — Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1552.001** — Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1528** — Steal Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Installation of Aikido-flagged malicious npm packages on developer endpoints

`UC_11_3` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("npm.exe","npm-cli.js","yarn.exe","pnpm.exe","node.exe") (Processes.process="*axios@0.30.4*" OR Processes.process="*axios@1.14.1*" OR Processes.process="*postmark-mcp@1.0.16*" OR Processes.process="*postmark-mcp@1.0.17*" OR Processes.process="*postmark-mcp@1.0.18*" OR Processes.process="*plain-crypto-js@4.2.1*" OR Processes.process="*@bitwarden/cli@2026.4.0*") by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let BadSpecs = dynamic(["axios@0.30.4","axios@1.14.1","postmark-mcp@1.0.16","postmark-mcp@1.0.17","postmark-mcp@1.0.18","plain-crypto-js@4.2.1","@bitwarden/cli@2026.4.0"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm.exe","yarn.exe","pnpm.exe","node.exe")
   or InitiatingProcessFileName in~ ("npm.exe","yarn.exe","pnpm.exe","node.exe")
| where ProcessCommandLine has_any (BadSpecs) or InitiatingProcessCommandLine has_any (BadSpecs)
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### npm postinstall hook spawning a shell interpreter on a developer device

`UC_11_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node.exe","npm.exe","yarn.exe","pnpm.exe") (Processes.parent_process="*postinstall*" OR Processes.parent_process="*preinstall*" OR Processes.parent_process="*install.js*" OR Processes.parent_process="*install.cjs*" OR Processes.parent_process="*node_modules*") Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wscript.exe","cscript.exe","mshta.exe","curl.exe","certutil.exe") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe")
| where InitiatingProcessCommandLine has_any ("postinstall","preinstall","install.js","install.cjs","node_modules\\.bin")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wscript.exe","cscript.exe","mshta.exe","curl.exe","certutil.exe","bitsadmin.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
  ParentImage = InitiatingProcessFolderPath,
  ParentCmd   = InitiatingProcessCommandLine,
  ChildImage  = FolderPath,
  ChildCmd    = ProcessCommandLine,
  SHA256
| order by Timestamp desc
```

### Execution of binaries matching Aikido article SHA1 hashes

`UC_11_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let BadHashes = dynamic(["2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766"]);
union
  (DeviceProcessEvents
   | where Timestamp > ago(90d)
   | where SHA1 in (BadHashes) or InitiatingProcessSHA1 in (BadHashes)
   | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1, ProcessCommandLine, InitiatingProcessFileName, Source="Process"),
  (DeviceFileEvents
   | where Timestamp > ago(90d)
   | where SHA1 in (BadHashes)
   | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA1, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, Source="File")
| order by Timestamp desc
```

### Developer-host beacon to GlassWorm / TeamPCP C2 infrastructure

`UC_11_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("142.11.206.73","45.32.150.251","45.32.151.157","70.34.242.255") OR All_Traffic.dest IN ("giftshop.club","sfrclak.com") OR All_Traffic.url="*giftshop.club*" OR All_Traffic.url="*sfrclak.com*" by All_Traffic.src All_Traffic.src_user All_Traffic.dest_ip All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let BadIPs = dynamic(["142.11.206.73","45.32.150.251","45.32.151.157","70.34.242.255"]);
let BadDomains = dynamic(["giftshop.club","sfrclak.com"]);
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteIP in (BadIPs)
   or RemoteUrl has_any (BadDomains)
| extend Suspect_NodeOrIDE = InitiatingProcessFileName in~ ("node.exe","npm.exe","Code.exe","electron.exe","chrome.exe","msedge.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName, RemoteIP, RemoteUrl, RemotePort, Suspect_NodeOrIDE
| order by Timestamp desc
```

### Postinstall-driven read of cloud credentials and SSH keys from developer home

`UC_11_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("node.exe","npm.exe","yarn.exe","pnpm.exe") (Filesystem.file_path="*\\.aws\\credentials*" OR Filesystem.file_path="*\\.aws\\config*" OR Filesystem.file_path="*\\.ssh\\id_*" OR Filesystem.file_path="*\\.npmrc*" OR Filesystem.file_path="*\\.kube\\config*" OR Filesystem.file_path="*\\Bitwarden*\\data.json*" OR Filesystem.file_name=".env") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
   or ActionType has "Open"
| where (FolderPath has_any (@"\.aws\credentials", @"\.aws\config", @"\.ssh\", @"\.npmrc", @"\.kube\config", @"Bitwarden\data.json", @"@bitwarden\")
     or FileName in~ ("credentials","id_rsa","id_ed25519","id_ecdsa",".npmrc","kubeconfig","data.json",".env"))
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe")
| where InitiatingProcessParentFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe","Code.exe","electron.exe")
   or InitiatingProcessCommandLine has_any ("postinstall","preinstall","node_modules","install.js")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, FolderPath, FileName, ActionType,
  InitiatingProcessFileName, InitiatingProcessCommandLine,
  InitiatingProcessParentFileName, InitiatingProcessAccountName, SHA256
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

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
