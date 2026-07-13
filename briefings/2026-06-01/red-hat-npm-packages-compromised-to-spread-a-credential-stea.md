# [CRIT] Red Hat npm Packages Compromised to Spread a Credential-Stealing Worm

**Source:** Aikido
**Published:** 2026-06-01
**Article:** https://www.aikido.dev/blog/red-hat-npm-packages-compromised-credential-stealing-worm

## Threat Profile

Blog Vulnerabilities & Threats Red Hat npm Packages Compromised to Spread a Credential-Stealing Worm Red Hat npm Packages Compromised to Spread a Credential-Stealing Worm Written by Ilyas Makari Published on: Jun 1, 2026 On June 1, 2026, we detected multiple official packages from the @redhat-cloud-services scope on npm were compromised with a credential-stealing worm. Over 30 packages seem to be affected. The malware appears similar to the Mini Shai-Hulud malware that was recently open-sourced …

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655`
- **SHA256:** `b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546** — Event Triggered Execution
- **T1552.001** — Credentials In Files
- **T1552.004** — Private Keys
- **T1552.005** — Cloud Instance Metadata API
- **T1528** — Steal Application Access Token
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Miasma worm index.js SHA256 IOC hit (Mini Shai-Hulud variant)

`UC_328_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash in ("7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655","b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash in ("7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655","b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)]
```

**Defender KQL:**
```kql
let MiasmaHashes = dynamic(["7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655","b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966"]);
union
(DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 in (MiasmaHashes) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, Source = "DeviceFileEvents"),
(DeviceProcessEvents | where Timestamp > ago(30d) | where SHA256 in (MiasmaHashes) or InitiatingProcessSHA256 in (MiasmaHashes) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessSHA256, ProcessCommandLine, Source = "DeviceProcessEvents"),
(DeviceImageLoadEvents | where Timestamp > ago(30d) | where SHA256 in (MiasmaHashes) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, Source = "DeviceImageLoadEvents")
| order by Timestamp desc
```

### npm preinstall hook spawns node index.js under @redhat-cloud-services package path

`UC_328_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("npm.cmd","npm.exe","npm","yarn","yarn.cmd","pnpm","pnpm.cmd","npx","npx.cmd","corepack.exe","corepack") AND Processes.process_name IN ("node.exe","node") AND (Processes.process="*index.js*" AND (Processes.process="*@redhat-cloud-services*" OR Processes.parent_process="*@redhat-cloud-services*")) by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_path Processes.process_hash
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("node.exe","node")
| where InitiatingProcessFileName in~ ("npm.cmd","npm.exe","npm","yarn","yarn.cmd","pnpm","pnpm.cmd","npx","npx.cmd","corepack.exe","corepack")
| where ProcessCommandLine has "index.js"
| where ProcessCommandLine has "@redhat-cloud-services" or InitiatingProcessCommandLine has "@redhat-cloud-services" or InitiatingProcessFolderPath has "@redhat-cloud-services" or FolderPath has "@redhat-cloud-services"
| project Timestamp, DeviceName, AccountName, ParentImage = InitiatingProcessFolderPath, ParentCmd = InitiatingProcessCommandLine, ChildImage = FolderPath, ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### node child of npm/yarn/pnpm reading cloud and CI credential files (Miasma sweep)

`UC_328_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count dc(Filesystem.file_path) as path_count values(Filesystem.file_path) as paths values(Filesystem.process_path) as procs from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("node.exe","node") AND (Filesystem.file_path="*\\.aws\\credentials*" OR Filesystem.file_path="*\\.aws\\config*" OR Filesystem.file_path="*\\.ssh\\id_*" OR Filesystem.file_path="*\\.npmrc*" OR Filesystem.file_path="*\\.docker\\config.json*" OR Filesystem.file_path="*\\.kube\\config*" OR Filesystem.file_path="*\\kubeconfig*" OR Filesystem.file_path="*\\.config\\gcloud*" OR Filesystem.file_path="*\\.azure\\*" OR Filesystem.file_path="*\\.gnupg\\*" OR Filesystem.file_path="*\\.env*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*/.aws/config*" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.npmrc*" OR Filesystem.file_path="*/.docker/config.json*" OR Filesystem.file_path="*/.kube/config*" OR Filesystem.file_path="*/kubeconfig*" OR Filesystem.file_path="*/.config/gcloud*" OR Filesystem.file_path="*/.azure/*" OR Filesystem.file_path="*/.gnupg/*" OR Filesystem.file_path="*/.env*") by Filesystem.dest Filesystem.user Filesystem.process_id _time span=10m
| `drop_dm_object_name(Filesystem)`
| where path_count >= 3
```

**Defender KQL:**
```kql
let CredPaths = dynamic([@"\.aws\credentials", @"\.aws\config", @"\.ssh\id_", @"\.npmrc", @"\.docker\config.json", @"\.kube\config", "kubeconfig", @"\.config\gcloud", @"\.azure\", @"\.gnupg\", @"\.env", "/.aws/credentials", "/.aws/config", "/.ssh/id_", "/.npmrc", "/.docker/config.json", "/.kube/config", "/.config/gcloud", "/.azure/", "/.gnupg/", "/.env"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where InitiatingProcessParentFileName in~ ("npm.cmd","npm.exe","npm","yarn","yarn.cmd","pnpm","pnpm.cmd","npx","npx.cmd","corepack.exe","corepack","bash","sh","zsh","runner.worker","Runner.Worker")
| where ActionType in ("FileCreated","FileModified","FileOpened","FileAccessed")
| extend MatchedPath = tostring(array_iff(CredPaths, FolderPath has_any (CredPaths) or strcat(FolderPath, FileName) has_any (CredPaths)))
| where FolderPath has_any (CredPaths) or strcat(FolderPath, "\\", FileName) has_any (CredPaths)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), DistinctPaths = dcount(strcat(FolderPath, FileName)), SamplePaths = make_set(strcat(FolderPath, FileName), 20), ParentCmd = any(InitiatingProcessCommandLine) by DeviceName, InitiatingProcessAccountName, InitiatingProcessId, bin(Timestamp, 10m)
| where DistinctPaths >= 3
| order by FirstSeen desc
```

### node child of npm install initiating outbound network to non-registry destination

`UC_328_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app IN ("node.exe","node") OR All_Traffic.process_name IN ("node.exe","node")) AND All_Traffic.dest_port IN (80,443,8080,8443) AND All_Traffic.transport="tcp" by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.process_name All_Traffic.dest All_Traffic.dest_port _time
| `drop_dm_object_name(All_Traffic)`
| where NOT match(dest, "(?i)(^|\.)(registry\.npmjs\.org|registry\.yarnpkg\.com|registry\.npmmirror\.com|github\.com|githubusercontent\.com|githubapp\.com|objects\.githubusercontent\.com|nodejs\.org|repo\.maven\.apache\.org|pypi\.org)$")
| join type=inner src [| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.process_name IN ("node.exe","node") AND Processes.parent_process_name IN ("npm.cmd","npm.exe","npm","yarn","yarn.cmd","pnpm","pnpm.cmd","npx","npx.cmd","corepack.exe","corepack") by Processes.dest Processes.parent_process Processes.process _time | rename Processes.dest as src, Processes.parent_process as parent_cmd, Processes.process as node_cmd, _time as node_start | eval node_end = node_start + 600]
| where _time >= node_start AND _time <= node_end
| table _time src user node_cmd parent_cmd dest dest_port
```

**Defender KQL:**
```kql
let NpmNodeProcs = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("node.exe","node")
    | where InitiatingProcessFileName in~ ("npm.cmd","npm.exe","npm","yarn","yarn.cmd","pnpm","pnpm.cmd","npx","npx.cmd","corepack.exe","corepack")
    | project NodeStart = Timestamp, DeviceId, NodePid = ProcessId, NodeCmd = ProcessCommandLine, ParentCmd = InitiatingProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where RemoteIPType == "Public"
| where isnotempty(RemoteUrl)
| where not(RemoteUrl endswith "registry.npmjs.org"
        or RemoteUrl endswith "registry.yarnpkg.com"
        or RemoteUrl endswith "registry.npmmirror.com"
        or RemoteUrl endswith "github.com"
        or RemoteUrl endswith "githubusercontent.com"
        or RemoteUrl endswith "githubapp.com"
        or RemoteUrl endswith "objects.githubusercontent.com"
        or RemoteUrl endswith "nodejs.org"
        or RemoteUrl endswith "pypi.org"
        or RemoteUrl endswith "repo.maven.apache.org")
| join kind=inner NpmNodeProcs on $left.DeviceId == $right.DeviceId, $left.InitiatingProcessId == $right.NodePid
| where Timestamp between (NodeStart .. NodeStart + 10m)
| project Timestamp, DeviceName, InitiatingProcessAccountName, NodeCmd, ParentCmd, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Install or update of @redhat-cloud-services npm package post-2026-06-01 (IOC version watchlist)

`UC_328_10` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.file_path="*node_modules*@redhat-cloud-services*" AND Filesystem.action IN ("created","modified","write") AND _time >= relative_time(now(), "@d-5d") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| eval pkg = mvindex(split(file_path, "@redhat-cloud-services"), 1)
| eval pkg = mvindex(split(pkg, "\\"), 1)
| eval pkg = if(isnull(pkg) OR pkg="", mvindex(split(file_path, "@redhat-cloud-services/"), 1), pkg)
| eval pkg = mvindex(split(pkg, "/"), 0)
| convert ctime(firstTime) ctime(lastTime)
| stats count values(paths) as paths min(firstTime) as firstTime max(lastTime) as lastTime by dest user pkg
```

**Defender KQL:**
```kql
let IOCPackages = dynamic(["chrome","compliance-client","config-manager-client","entitlements-client","eslint-config-redhat-cloud-services","frontend-components","frontend-components-advisor-components","frontend-components-config","frontend-components-config-utilities","frontend-components-notifications","frontend-components-remediations","frontend-components-testing","frontend-components-translations","frontend-components-utilities","hcc-feo-mcp","hcc-kessel-mcp","hcc-pf-mcp","host-inventory-client","insights-client","integrations-client","javascript-clients-shared","notifications-client","patch-client","quickstarts-client","rbac-client","remediations-client","rule-components","sources-client","tsc-transform-imports","types","vulnerabilities-client"]);
DeviceFileEvents
| where Timestamp >= datetime(2026-06-01T00:00:00Z)
| where FolderPath has "node_modules" and FolderPath has "@redhat-cloud-services"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| extend Pkg = extract(@"(?i)@redhat-cloud-services[\\/]([^\\/]+)", 1, FolderPath)
| where Pkg in~ (IOCPackages) or isempty(Pkg) == false
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), FileCount = count(), SampleFiles = make_set(strcat(FolderPath, "\\", FileName), 10) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, Pkg
| order by FirstSeen desc
```

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### Article-specific behavioural hunt — Red Hat npm Packages Compromised to Spread a Credential-Stealing Worm

`UC_328_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Red Hat npm Packages Compromised to Spread a Credential-Stealing Worm ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Red Hat npm Packages Compromised to Spread a Credential-Stealing Worm
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655`, `b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
