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
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1048.003** — Exfiltration Over Alternative Protocol: Unencrypted Non-C2
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1102.002** — Web Service: Bidirectional Communication
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms
- **T1554** — Compromise Host Software Binary

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Malicious postmark-mcp npm package install or egress to giftshop.club C2

`UC_150_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.exe","npm","yarn.exe","yarn","pnpm.exe","pnpm","npx.exe","npx","node.exe","node")) AND Processes.process="*postmark-mcp*" by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as query from datamodel=Network_Resolution where DNS.query="*giftshop.club" by DNS.src DNS.query | `drop_dm_object_name(DNS)` ] | sort - firstTime
```

**Defender KQL:**
```kql
// postmark-mcp install signal or giftshop.club egress
let Window = 14d;
let Installs = DeviceProcessEvents
    | where Timestamp > ago(Window)
    | where InitiatingProcessFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe","cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh")
        or FileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe")
    | where ProcessCommandLine has "postmark-mcp"
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, Signal="npm_install_postmark_mcp";
let Egress = DeviceNetworkEvents
    | where Timestamp > ago(Window)
    | where RemoteUrl has "giftshop.club" or RemoteUrl endswith ".giftshop.club"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              FileName=InitiatingProcessFileName,
              ProcessCommandLine=InitiatingProcessCommandLine,
              InitiatingProcessFileName, RemoteUrl, RemoteIP, Signal="giftshop_club_egress";
let Files = DeviceFileEvents
    | where Timestamp > ago(Window)
    | where FolderPath has @"\node_modules\postmark-mcp\" or FolderPath has "/node_modules/postmark-mcp/"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              FileName=InitiatingProcessFileName,
              ProcessCommandLine=InitiatingProcessCommandLine,
              InitiatingProcessFileName, FolderPath, Signal="postmark_mcp_node_modules_write";
union Installs, Egress, Files
| where AccountName !endswith "$"
| order by Timestamp desc
```

### Postmark-MCP backdoor BCC exfil — outbound email to *@giftshop.club

`UC_150_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Email.src_user) as sender values(All_Email.subject) as subjects values(All_Email.message_id) as message_ids from datamodel=Email where All_Email.recipient="*@giftshop.club" OR All_Email.recipient="phan@giftshop.club" by All_Email.src All_Email.recipient | `drop_dm_object_name(All_Email)` | sort - firstTime
```

**Defender KQL:**
```kql
// Postmark-MCP exfil — outgoing mail BCC'd to attacker-controlled giftshop.club
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection in ("Outbound","Intra-org")
| where RecipientEmailAddress endswith "@giftshop.club"
| project Timestamp, NetworkMessageId, InternetMessageId,
          SenderMailFromAddress, SenderFromAddress, SenderFromDomain,
          RecipientEmailAddress, Subject, EmailDirection, DeliveryAction,
          ConnectorsUsed=Connectors
| order by Timestamp desc
```

### npm/pnpm/yarn postinstall hook reads developer cloud credentials

`UC_150_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("node.exe","node","npm.exe","npm","yarn.exe","yarn","pnpm.exe","pnpm","npx.exe","npx") AND (Filesystem.file_path="*\\.aws\\credentials*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*\\.ssh\\id_*" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*\\.npmrc*" OR Filesystem.file_path="*/.npmrc*" OR Filesystem.file_path="*\\.kube\\config*" OR Filesystem.file_path="*/.kube/config*" OR Filesystem.file_path="*\\gh\\hosts.yml*" OR Filesystem.file_path="*/gh/hosts.yml*") by Filesystem.dest Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)` | sort - firstTime
```

**Defender KQL:**
```kql
// Article scenario: dependency postinstall hook touching dev credentials
let Window = 7d;
let CredPaths = dynamic([
    @"\.aws\credentials", "/.aws/credentials",
    @"\.aws\config", "/.aws/config",
    @"\.ssh\id_rsa", "/.ssh/id_rsa",
    @"\.ssh\id_ed25519", "/.ssh/id_ed25519",
    @"\.npmrc", "/.npmrc",
    @"\.kube\config", "/.kube/config",
    @"\AppData\Roaming\gh\hosts.yml", "/.config/gh/hosts.yml",
    @"\.gitconfig", "/.gitconfig",
    @"\AppData\Local\Git Credential Manager\"
]);
DeviceFileEvents
| where Timestamp > ago(Window)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
    or ActionType startswith "FileAccessed"
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe","npx.exe","node","npm","yarn","pnpm","npx")
| extend PathLower = tolower(FolderPath)
| where PathLower has_any (CredPaths)
| where InitiatingProcessAccountName !endswith "$"
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(Window)
    | where ProcessCommandLine has_any ("postinstall","preinstall","prepare","install","npm-cli.js install","yarn install","pnpm install","npm ci")
    | project Timestamp, DeviceId, InstallCmd=ProcessCommandLine, InstallParent=InitiatingProcessFileName
  ) on DeviceId
| where isnotempty(InstallCmd) or InitiatingProcessParentFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe")
| project Timestamp, DeviceName,
          User=InitiatingProcessAccountName,
          Reader=InitiatingProcessFileName,
          ReaderCmd=InitiatingProcessCommandLine,
          GrandParent=InitiatingProcessParentFileName,
          FolderPath, FileName, InstallCmd
| order by Timestamp desc
```

### GlassWorm — VS Code Code.exe spawning child with Solana RPC or Open VSX egress

`UC_150_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as query values(DNS.src) as src from datamodel=Network_Resolution where DNS.query IN ("api.mainnet-beta.solana.com","*.solana.com","open-vsx.org","*.open-vsx.org") by DNS.src DNS.query | `drop_dm_object_name(DNS)` | join type=inner src [ | tstats `summariesonly` values(Processes.process_name) as processes values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where Processes.process_name IN ("Code.exe","code","Code - Insiders.exe") by Processes.dest | rename Processes.dest as src | `drop_dm_object_name(Processes)` ] | sort - firstTime
```

**Defender KQL:**
```kql
// GlassWorm C2 — VS Code or its extension host reaching Solana RPC / Open VSX abuse paths
let Window = 7d;
let C2Domains = dynamic(["api.mainnet-beta.solana.com","solana.com","open-vsx.org","openvsxorg.blob.core.windows.net"]);
DeviceNetworkEvents
| where Timestamp > ago(Window)
| where InitiatingProcessFileName in~ ("Code.exe","Code - Insiders.exe","code","node.exe")
| where (InitiatingProcessParentFileName in~ ("Code.exe","Code - Insiders.exe","code") or InitiatingProcessFileName in~ ("Code.exe","Code - Insiders.exe"))
| where RemoteUrl has_any (C2Domains) or RemoteUrl endswith ".solana.com"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
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
