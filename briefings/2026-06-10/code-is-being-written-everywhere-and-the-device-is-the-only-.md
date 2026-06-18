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
- **T1567** — Exfiltration Over Web Service
- **T1059** — Command and Scripting Interpreter
- **T1546.016** — Installer Packages
- **T1176** — Browser Extensions
- **T1505.005** — Server Software Component: IDE Extensions
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1552.001** — Credentials In Files
- **T1552.004** — Private Keys
- **T1555** — Credentials from Password Stores

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### DNS or network egress to giftshop.club (postmark-mcp exfil channel)

`UC_117_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where DNS.query IN ("giftshop.club","*.giftshop.club","sfrclak.com","*.sfrclak.com") by DNS.src DNS.query DNS.dest | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest IN ("142.11.206.73","45.32.150.251","45.32.151.157","70.34.242.255") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let BadDomains = dynamic(["giftshop.club","sfrclak.com"]);
let BadIPs = dynamic(["142.11.206.73","45.32.150.251","45.32.151.157","70.34.242.255"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (BadIPs)
    or RemoteUrl has_any (BadDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### Postinstall hook from freshly-installed npm package spawning network / shell child

`UC_117_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe","bun.exe") AND (Processes.parent_process has "postinstall" OR Processes.parent_process has "run-script" OR Processes.parent_process has "lifecycle") AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","curl.exe","certutil.exe","bitsadmin.exe","bash.exe","sh.exe") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe","bun.exe")
| where InitiatingProcessCommandLine has_any ("postinstall","preinstall","install","run-script","lifecycle")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","curl.exe","certutil.exe","bitsadmin.exe","bash.exe","sh.exe","node.exe")
    or ProcessCommandLine has_any ("curl ","wget ","Invoke-WebRequest","DownloadString","IEX ","base64 -d","FromBase64String","-EncodedCommand")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### VS Code / IDE marketplace extension install (Glassworm-style)

`UC_117_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.vscode\\extensions\\*" OR Filesystem.file_path="*\\.vscode-insiders\\extensions\\*" OR Filesystem.file_path="*\\Cursor\\User\\extensions\\*" OR Filesystem.file_path="*\\.windsurf\\extensions\\*" OR Filesystem.file_path="*\\JetBrains\\*\\plugins\\*" OR Filesystem.file_name="*.vsix") AND Filesystem.action="created" by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FolderPath has_any (@"\.vscode\extensions\", @"\.vscode-insiders\extensions\", @"\Cursor\User\extensions\", @"\.windsurf\extensions\", @"\JetBrains\")
    or FileName endswith ".vsix"
| where FileName endswith ".js" or FileName endswith ".vsix" or FileName endswith "package.json" or FileName endswith ".node" or FileName endswith ".dll" or FileName endswith ".exe"
| where InitiatingProcessFileName !in~ ("msiexec.exe","trustedinstaller.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### Anomalous git push / branch-protection bypass by developer endpoint

`UC_117_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="git.exe" AND (Processes.process has "push --force" OR Processes.process has "push -f " OR Processes.process has "push --delete" OR Processes.process has "branch -D ") by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | eval hour=strftime(firstTime,"%H") | where (hour<"07" OR hour>"20") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "git.exe"
| where ProcessCommandLine has_any ("push --force","push -f ","push --delete","branch -D ","reset --hard origin/main","reset --hard origin/master")
| extend Hour = datetime_part("hour", Timestamp)
| where Hour < 7 or Hour > 20
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

### Developer credential file access by non-developer process

`UC_117_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.ssh\\id_*" OR Filesystem.file_path="*\\.ssh\\config" OR Filesystem.file_name=".npmrc" OR Filesystem.file_name=".git-credentials" OR Filesystem.file_name="credentials" OR Filesystem.file_path="*\\.aws\\credentials" OR Filesystem.file_path="*\\.docker\\config.json" OR Filesystem.file_path="*\\.kube\\config") AND NOT (Filesystem.process_name IN ("ssh.exe","git.exe","npm.exe","node.exe","aws.exe","kubectl.exe","docker.exe","code.exe","explorer.exe")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CredPaths = dynamic([@"\.ssh\id_",@"\.ssh\config",@"\.npmrc",@"\.git-credentials",@"\.aws\credentials",@"\.docker\config.json",@"\.kube\config",@"\AppData\Roaming\gh\hosts.yml",@"\AppData\Roaming\GitHub CLI\"]);
let AllowedReaders = dynamic(["ssh.exe","git.exe","npm.exe","node.exe","aws.exe","kubectl.exe","docker.exe","code.exe","explorer.exe","gh.exe","plink.exe","openssh.exe","sshd.exe"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath has_any (CredPaths) or FileName in~ (".npmrc",".git-credentials","credentials","id_rsa","id_ed25519")
| where InitiatingProcessFileName !in~ (AllowedReaders)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FolderPath, FileName
| order by Timestamp desc
```

### MCP server / AI-agent process making egress to non-allowlisted host

`UC_117_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.app="node.exe" OR All_Traffic.app="python.exe" OR All_Traffic.app="npx.exe") AND All_Traffic.dest_port IN (80,443,8080,8443) AND NOT (All_Traffic.dest IN ("registry.npmjs.org","pypi.org","files.pythonhosted.org","api.openai.com","api.anthropic.com")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
let McpHosts = dynamic(["node.exe","npx.exe","python.exe","pythonw.exe","bun.exe","deno.exe"]);
let KnownGood = dynamic(["registry.npmjs.org","pypi.org","files.pythonhosted.org","api.openai.com","api.anthropic.com","api.github.com","objects.githubusercontent.com"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (McpHosts)
| where InitiatingProcessCommandLine has_any ("mcp","@modelcontextprotocol","stdio","--server","server.js","server.py")
| where RemoteIPType == "Public"
| where not(RemoteUrl has_any (KnownGood))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
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

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
