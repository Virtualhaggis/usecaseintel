# [CRIT] [GHSA / CRITICAL] GHSA-jpvj-wpmj-h7rv: Supply chain compromise via malicious @cap-js/openapi

**Source:** GitHub Security Advisories
**Published:** 2026-06-04
**Article:** https://github.com/advisories/GHSA-jpvj-wpmj-h7rv

## Threat Profile

Supply chain compromise via malicious @cap-js/openapi

### Impact

On May 19, 2026, a compromised version of @cap-js/openapi@1.4.1 was published.
The malicious packages harvested credentials and attempted self-propagation.
If a compromised version was installed, all credentials accessible on that machine (npm tokens, cloud provider credentials, SSH keys, GitHub PATs) should be considered compromised.

### Patches

Upgrade to @cap-js/openapi >= 1.4.2
If the compromised version was ever installed,…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `t.m-kosche.com`
- **SHA256:** `7c24b4d9a8f448832f3752d7f67dcdbf1b7f0f41e10bf633efa175e627144e8b`
- **SHA1:** `d78c25443ec4a0d7f0a85776461f3b1163132537`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1059.007** — JavaScript
- **T1546.016** — Installer Packages
- **T1204.002** — User Execution: Malicious File
- **T1552.001** — Credentials in Files
- **T1552.004** — Private Keys
- **T1528** — Steal Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Mini Shai-Hulud npm worm exfiltration to t.m-kosche.com OpenTelemetry endpoint

`UC_145_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.dest) as dns_server from datamodel=Network_Resolution.DNS where DNS.query="*t.m-kosche.com*" by DNS.query DNS.src | `drop_dm_object_name("DNS")` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as port from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_hostname="*t.m-kosche.com*" OR All_Traffic.url="*t.m-kosche.com*" by All_Traffic.dest_hostname All_Traffic.url] | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src from datamodel=Web where Web.url="*t.m-kosche.com*" OR Web.url="*/api/public/otel/v1/traces*" by Web.url Web.user] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Mini Shai-Hulud TeamPCP exfil endpoint
let exfilHost = "t.m-kosche.com";
let exfilPath = "/api/public/otel/v1/traces";
union isfuzzy=true
(DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has exfilHost or RemoteUrl has exfilPath
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            InitiatingProcessFolderPath, RemoteIP, RemoteUrl, RemotePort,
            Source="DeviceNetworkEvents"),
(DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType in ("DnsQueryResponse","ConnectionSuccess","NetworkConnectionEvents")
  | where RemoteUrl has exfilHost or AdditionalFields has exfilHost
  | project Timestamp, DeviceName, AccountName,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            InitiatingProcessFolderPath, RemoteIP, RemoteUrl, RemotePort,
            Source="DeviceEvents")
| order by Timestamp desc
```

### Bun runtime spawned by npm/node preinstall hook (TeamPCP setup.mjs loader)

`UC_145_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where (Processes.process_name IN ("bun.exe","bun")) AND (Processes.parent_process_name IN ("npm.exe","npm-cli.js","node.exe","node","yarn.exe","yarn","pnpm.exe","pnpm","npx.exe","npx") OR Processes.parent_process="*preinstall*" OR Processes.parent_process="*setup.mjs*" OR Processes.process="*setup.mjs*" OR Processes.process="*execution.js*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// TeamPCP Mini Shai-Hulud: Bun spawned from npm preinstall
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "bun.exe" or FileName =~ "bun"
| where (InitiatingProcessFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe","npm-cli.js","node","npm","yarn","pnpm","npx"))
   or InitiatingProcessCommandLine has_any ("preinstall","setup.mjs","execution.js")
   or ProcessCommandLine has_any ("setup.mjs","execution.js")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Mini Shai-Hulud payload SHA256 on disk (7c24b4d9...e627144e8b)

`UC_145_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name values(Filesystem.process_name) as written_by from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("7c24b4d9a8f448832f3752d7f67dcdbf1b7f0f41e10bf633efa175e627144e8b","d78c25443ec4a0d7f0a85776461f3b1163132537") by Filesystem.dest | `drop_dm_object_name(Filesystem)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where Processes.process_hash IN ("7c24b4d9a8f448832f3752d7f67dcdbf1b7f0f41e10bf633efa175e627144e8b","d78c25443ec4a0d7f0a85776461f3b1163132537") by Processes.dest Processes.user] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Mini Shai-Hulud payload hash IOCs from GHSA-jpvj-wpmj-h7rv
let badSha256 = dynamic(["7c24b4d9a8f448832f3752d7f67dcdbf1b7f0f41e10bf633efa175e627144e8b"]);
let badSha1 = dynamic(["d78c25443ec4a0d7f0a85776461f3b1163132537"]);
union isfuzzy=true
(DeviceFileEvents
  | where Timestamp > ago(60d)
  | where SHA256 in (badSha256) or SHA1 in (badSha1)
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
            FileName, FolderPath, SHA256, SHA1,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            FileOriginUrl, FileOriginIP, Source="DeviceFileEvents"),
(DeviceProcessEvents
  | where Timestamp > ago(60d)
  | where SHA256 in (badSha256) or SHA1 in (badSha1) or InitiatingProcessSHA256 in (badSha256) or InitiatingProcessSHA1 in (badSha1)
  | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, SHA1,
            ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine,
            FileOriginUrl="", FileOriginIP="", Source="DeviceProcessEvents"),
(DeviceImageLoadEvents
  | where Timestamp > ago(60d)
  | where SHA256 in (badSha256) or SHA1 in (badSha1)
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
            FileName, FolderPath, SHA256, SHA1,
            InitiatingProcessFileName=InitiatingProcessFileName, InitiatingProcessCommandLine=InitiatingProcessCommandLine,
            FileOriginUrl="", FileOriginIP="", Source="DeviceImageLoadEvents")
| order by Timestamp desc
```

### Cloud/SSH/npm credential file access by Node or Bun during npm install

`UC_145_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("node.exe","node","bun.exe","bun","npm.exe","npm","yarn.exe","pnpm.exe") AND (Filesystem.file_path="*\\.aws\\credentials*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*\\.aws\\config*" OR Filesystem.file_path="*/.aws/config*" OR Filesystem.file_path="*\\.npmrc*" OR Filesystem.file_path="*/.npmrc*" OR Filesystem.file_path="*\\.ssh\\id_*" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*\\.config\\gh\\hosts.yml*" OR Filesystem.file_path="*/.config/gh/hosts.yml*" OR Filesystem.file_path="*\\.kube\\config*" OR Filesystem.file_path="*/.kube/config*" OR Filesystem.file_path="*\\.docker\\config.json*" OR Filesystem.file_path="*/.docker/config.json*" OR Filesystem.file_path="*.vault-token*" OR Filesystem.file_path="*GITHUB_TOKEN*" OR Filesystem.file_path="*NPM_TOKEN*") by Filesystem.dest Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where mvcount(paths) >= 3 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Mini Shai-Hulud credential harvest: node/bun touching multiple secret stores during install
let credPaths = dynamic([
  @"\.aws\credentials", @"/.aws/credentials",
  @"\.aws\config", @"/.aws/config",
  @"\.npmrc", @"/.npmrc",
  @"\.ssh\id_", @"/.ssh/id_",
  @"\.ssh\known_hosts", @"/.ssh/known_hosts",
  @"\.config\gh\hosts.yml", @"/.config/gh/hosts.yml",
  @"\.kube\config", @"/.kube/config",
  @"\.docker\config.json", @"/.docker/config.json",
  @".vault-token",
  @"\AppData\Roaming\gcloud\credentials.db", @"/.config/gcloud/credentials.db",
  @"\.azure\msal_token_cache", @"/.azure/msal_token_cache"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileOpenInfo","FileCreated","FileRenamed","FileModified")
| where InitiatingProcessFileName in~ ("node.exe","node","bun.exe","bun","npm.exe","npm","yarn.exe","pnpm.exe")
| where InitiatingProcessCommandLine has_any ("install","preinstall","setup.mjs","execution.js","npm ci","npm i ")
   or InitiatingProcessParentFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe")
| where FolderPath has_any (credPaths) or FileName has_any (credPaths)
| summarize HitCount = count(), PathsTouched = make_set(FolderPath, 50), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
  by DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| where HitCount >= 3
| order by LastSeen desc
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
  - IP / domain IOC(s): `t.m-kosche.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `7c24b4d9a8f448832f3752d7f67dcdbf1b7f0f41e10bf633efa175e627144e8b`, `d78c25443ec4a0d7f0a85776461f3b1163132537`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
