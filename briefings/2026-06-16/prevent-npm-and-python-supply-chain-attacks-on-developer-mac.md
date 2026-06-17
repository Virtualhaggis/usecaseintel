# [HIGH] Prevent npm and Python Supply Chain Attacks on Developer Machines with Package Configs

**Source:** StepSecurity
**Published:** 2026-06-16
**Article:** https://www.stepsecurity.io/blog/prevent-npm-and-python-supply-chain-attacks-on-developer-machines-with-package-configs

## Threat Profile

Back to Blog Product Prevent npm and Python Supply Chain Attacks on Developer Machines with Package Configs npm and Python supply chain attacks run on developer machines and steal secrets. See how Package Configs audits registry, cooldown, and auth across your fleet Swarit Pandey View LinkedIn June 16, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Over the past few months, a wave of supply chain attacks has hit the npm and P…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1552.001** — Credentials In Files
- **T1528** — Steal Application Access Token
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Install of TeamPCP Miasma/Hades-compromised npm or PyPI package versions

`UC_1_1` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\node_modules\\ensmallen\\*" OR Filesystem.file_path="*\\node_modules\\mflux-streamlit\\*" OR Filesystem.file_path="*\\node_modules\\embiggen\\*" OR Filesystem.file_path="*\\node_modules\\gpsea\\*" OR Filesystem.file_path="*\\node_modules\\pyphetools\\*" OR Filesystem.file_path="*\\node_modules\\nhmpy\\*" OR Filesystem.file_path="*\\node_modules\\ppkt2synergy\\*" OR Filesystem.file_path="*/site-packages/ensmallen*" OR Filesystem.file_path="*/site-packages/embiggen*" OR Filesystem.file_path="*/site-packages/gpsea*" OR Filesystem.file_path="*/site-packages/pyphetools*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let pkgs = dynamic(["ensmallen","mflux-streamlit","embiggen","gpsea","pyphetools","nhmpy","ppkt2synergy"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType == "FileCreated"
| where FolderPath has_any (@"\node_modules\", "/site-packages/")
| where FileName =~ "package.json" or FileName endswith ".dist-info" or FileName =~ "PKG-INFO" or FileName =~ "METADATA"
| where FolderPath has_any (pkgs)
| extend MatchedPkg = tostring(pkgs[array_index_of(pkgs, extract(@"(?i)(?:node_modules[\\/]|site-packages[\\/])([a-z0-9_\-]+)", 1, FolderPath))])
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, MatchedPkg
| order by Timestamp desc
```

### Package-manager install descendant reads .npmrc / pip.conf credentials

`UC_1_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN (".npmrc",".yarnrc",".yarnrc.yml","bunfig.toml",".pypirc","pip.conf")) by Filesystem.dest Filesystem.user Filesystem.process_path Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | search process_path IN ("*\\node.exe","*\\python.exe","*\\python3","*\\pip*","*\\npm*","*\\yarn*","*\\pnpm*","*\\bun*","*/node","*/python*","*/pip*") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let creds = dynamic([".npmrc",".yarnrc",".yarnrc.yml","bunfig.toml",".pypirc","pip.conf"]);
let pmParents = dynamic(["npm.exe","npm-cli.js","pnpm.exe","yarn.exe","bun.exe","node.exe","pip.exe","pip3.exe","python.exe","python3.exe","npm","pip","node","python","python3"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ (creds)
| where InitiatingProcessFileName in~ (pmParents) or InitiatingProcessParentFileName in~ (pmParents)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, ActionType
| order by Timestamp desc
```

### Post-install node or python child process beaconing to non-registry public destination

`UC_1_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("node.exe","python.exe","python3.exe","python3","node") AND All_Traffic.dest_category="external" by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | search NOT (dest IN ("registry.npmjs.org","registry.yarnpkg.com","pypi.org","files.pythonhosted.org","npm.pkg.github.com")) | search NOT (dest="*.internal" OR dest="*.corp") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let pmAncestors = dynamic(["npm.exe","pnpm.exe","yarn.exe","bun.exe","pip.exe","pip3.exe","npm","pip"]);
let allowedRegistries = dynamic(["registry.npmjs.org","registry.yarnpkg.com","pypi.org","files.pythonhosted.org","npm.pkg.github.com"]);
let installers = DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where InitiatingProcessFileName in~ (pmAncestors) or InitiatingProcessParentFileName in~ (pmAncestors)
    | where FileName in~ ("node.exe","python.exe","python3.exe","node","python","python3")
    | project InstallTime = Timestamp, DeviceId, InstallerPid = ProcessId, InstallerName = FileName, InstallerCmd = ProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("node.exe","python.exe","python3.exe","node","python","python3")
| where not (RemoteUrl has_any (allowedRegistries))
| join kind=inner installers on $left.DeviceId == $right.DeviceId, $left.InitiatingProcessId == $right.InstallerPid
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, InstallTime, InstallerCmd
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


## Why this matters

Severity classified as **HIGH** based on: 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
