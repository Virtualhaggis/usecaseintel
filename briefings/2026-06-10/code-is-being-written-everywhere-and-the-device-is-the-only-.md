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
- **T1567** — Exfiltration Over Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1554** — Compromise Host Software Binary
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1176** — Browser Extensions
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Supply Chain
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### postmark-mcp backdoor C2 egress to giftshop.club / sfrclak.com

`UC_120_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(DNS.query) as queries, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="giftshop.club" OR DNS.query="*.giftshop.club" OR DNS.query="sfrclak.com" OR DNS.query="*.sfrclak.com") by DNS.src, DNS.dest, DNS.query | `drop_dm_object_name(DNS)` | convert ctime(firstTime), ctime(lastTime) | append [ | tstats summariesonly=t count, values(Web.url) as urls, min(_time) as firstTime from datamodel=Web.Web where (Web.dest="giftshop.club" OR Web.dest="*.giftshop.club" OR Web.dest="sfrclak.com" OR Web.dest="*.sfrclak.com" OR Web.url="*giftshop.club*" OR Web.url="*sfrclak.com*") by Web.src, Web.user, Web.dest, Web.http_user_agent | `drop_dm_object_name(Web)` ]
```

**Defender KQL:**
```kql
let BadDomains = dynamic(["giftshop.club","sfrclak.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl endswith "giftshop.club" or RemoteUrl endswith "sfrclak.com" or RemoteUrl has_any (BadDomains))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### GlassWorm VS Code / OpenVSX extension drops os.node / darwin.node native modules

`UC_120_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(Filesystem.file_path) as file_paths, values(Filesystem.process_name) as procs, min(_time) as firstTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="os.node" OR Filesystem.file_name="darwin.node") AND (Filesystem.file_path="*\\.vscode\\extensions\\*" OR Filesystem.file_path="*\\.vscode-server\\extensions\\*" OR Filesystem.file_path="*\\.openvsx\\*" OR Filesystem.file_path="*/.vscode/extensions/*" OR Filesystem.file_path="*/.openvsx/*") AND Filesystem.action="created" by Filesystem.dest, Filesystem.user, Filesystem.file_name, Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime)
```

**Defender KQL:**
```kql
let KnownBadHashes = dynamic(["2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName in~ ("os.node","darwin.node")
      or SHA1 in~ (KnownBadHashes)
| where FolderPath has_any (@"\.vscode\extensions\", @"\.vscode-server\extensions\", @"\.openvsx\", "/.vscode/extensions/", "/.openvsx/")
      or SHA1 in~ (KnownBadHashes)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA1, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### npm/yarn/pnpm postinstall hook touches credential files and beacons outbound

`UC_120_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(Processes.process) as cmdlines, values(Processes.parent_process) as parents, min(_time) as procTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="npm.exe" OR Processes.parent_process_name="npm-cli.js" OR Processes.parent_process_name="pnpm.exe" OR Processes.parent_process_name="yarn.exe") AND (Processes.parent_process="*postinstall*" OR Processes.parent_process="*npm install*" OR Processes.parent_process="*pnpm install*" OR Processes.parent_process="*yarn add*") AND (Processes.process="*aws/credentials*" OR Processes.process="*aws_access_key*" OR Processes.process="*.ssh/id_*" OR Processes.process="*.npmrc*" OR Processes.process="*_authToken*" OR Processes.process="*GITHUB_TOKEN*" OR Processes.process="*NPM_TOKEN*" OR Processes.process="*kubectl config*" OR Processes.process="*gcloud auth*" OR Processes.process="*az account get-access-token*") by Processes.dest, Processes.user, Processes.process_name, Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(procTime)
```

**Defender KQL:**
```kql
let RegistryDomains = dynamic(["registry.npmjs.org","registry.yarnpkg.com","npm.pkg.github.com","pypi.org","files.pythonhosted.org","objects.githubusercontent.com"]);
let CredKeywords = dynamic([@".aws\credentials",@".aws\config",@".ssh\id_rsa",@".ssh\id_ed25519",@".npmrc","_authToken","GITHUB_TOKEN","NPM_TOKEN","aws_access_key","kubectl config","gcloud auth","az account get-access-token","/.aws/credentials","/.ssh/id_"]);
let InstallContext = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("node.exe","npm.exe","npm-cli.js","pnpm.exe","yarn.exe","node")
         or InitiatingProcessCommandLine has_any ("npm install","npm i ","pnpm install","yarn install","yarn add","postinstall","npm run-script preinstall","npm run-script postinstall")
    | project InstallTime=Timestamp, DeviceId, DeviceName, AccountName,
              InstallParentCmd=InitiatingProcessCommandLine, InstallChildPid=ProcessId,
              InstallChildFile=FileName, InstallChildCmd=ProcessCommandLine;
let CredTouch = InstallContext
    | where InstallChildCmd has_any (CredKeywords);
let NetEgress = InstallContext
    | join kind=inner (
        DeviceNetworkEvents
        | where Timestamp > ago(7d)
        | where RemoteIPType == "Public"
        | where not(RemoteUrl has_any (RegistryDomains))
        | project NetTime=Timestamp, DeviceId, NetProcId=InitiatingProcessId, RemoteUrl, RemoteIP, RemotePort
      ) on DeviceId
    | where NetProcId == InstallChildPid
    | where NetTime between (InstallTime .. InstallTime + 120s);
union CredTouch, NetEgress
| project InstallTime, DeviceName, AccountName, InstallParentCmd, InstallChildFile, InstallChildCmd, RemoteUrl, RemoteIP
| order by InstallTime desc
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

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
