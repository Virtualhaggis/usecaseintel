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
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1176** — Browser Extensions
- **T1547.013** — Boot or Logon Autostart Execution: XDG Autostart Entries
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1555** — Credentials from Password Stores
- **T1071.003** — Application Layer Protocol: Mail Protocols
- **T1048.003** — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound C2 from process tree of npm/yarn install within 3 minutes

`UC_116_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t min(_time) as install_time values(Processes.process) as install_cmd values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","npm.exe","npm.cmd","yarn.exe","yarn.cmd","pnpm.exe","pnpm.cmd") OR Processes.process IN ("*npm install*","*npm ci*","*yarn add*","*pnpm install*","*pnpm add*")) by Processes.dest
| `drop_dm_object_name(Processes)`
| join type=inner dest [
    | tstats summariesonly=t min(_time) as net_time values(All_Traffic.dest_ip) as remote_ip values(All_Traffic.dest_port) as remote_port values(All_Traffic.app) as net_proc from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("node.exe","npm.exe","yarn.exe","pnpm.exe","sh.exe","cmd.exe","powershell.exe","python.exe") NOT All_Traffic.dest IN ("registry.npmjs.org","registry.yarnpkg.com","github.com","*.githubusercontent.com","pypi.org","files.pythonhosted.org") by All_Traffic.dest
    | `drop_dm_object_name(All_Traffic)`
  ]
| where net_time >= install_time AND net_time <= (install_time + 180)
| table dest user install_cmd net_proc remote_ip remote_port install_time net_time
```

**Defender KQL:**
```kql
let WindowSec = 180;
let InstallProcs = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where (InitiatingProcessFileName in~ ("node.exe","npm.exe","npm.cmd","yarn.exe","yarn.cmd","pnpm.exe","pnpm.cmd")
          or ProcessCommandLine has_any ("npm install","npm ci","yarn add","pnpm install","pnpm add"))
    | project InstallTime = Timestamp, DeviceId, DeviceName, AccountName,
              InstallCmd = ProcessCommandLine,
              InstallChild = FileName;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","npm.cmd","yarn.exe","yarn.cmd","pnpm.exe","sh.exe","cmd.exe","powershell.exe","pwsh.exe","python.exe","python3.exe")
| where not (RemoteUrl has_any ("registry.npmjs.org","registry.yarnpkg.com","github.com","githubusercontent.com","pypi.org","files.pythonhosted.org","objects.githubusercontent.com"))
| join kind=inner InstallProcs on DeviceId
| where Timestamp between (InstallTime .. InstallTime + WindowSec * 1s)
| project NetworkTime = Timestamp, DeviceName, AccountName, InstallCmd,
          NetProc = InitiatingProcessFileName,
          NetCmd = InitiatingProcessCommandLine,
          RemoteIP, RemoteUrl, RemotePort
| order by NetworkTime desc
```

### VS Code extension directory mutated by non-VS Code process (Glassworm shape)

`UC_116_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as first_seen values(Filesystem.file_name) as files values(Filesystem.process_name) as writer from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\.vscode\\extensions\\*" Filesystem.process_name!="Code.exe" Filesystem.process_name!="code.exe" Filesystem.process_name!="Code - Insiders.exe" Filesystem.process_name!="msiexec.exe" Filesystem.process_name!="explorer.exe" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| where match(file_path, "\\.(js|json|vsix|node|dll|exe|sh|ps1)$")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has @"\.vscode\extensions\" or FolderPath has @"/.vscode/extensions/" or FolderPath has @"\.vscode-server\extensions\"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("code.exe","code - insiders.exe","code-insiders.exe","codium.exe","cursor.exe","msiexec.exe","explorer.exe","updater.exe","squirreltemp.exe","setup.exe")
| where InitiatingProcessAccountName !endswith "$"
| where FileName endswith ".js" or FileName endswith ".json" or FileName endswith ".vsix" or FileName endswith ".node" or FileName endswith ".dll" or FileName endswith ".exe" or FileName endswith ".sh" or FileName endswith ".ps1"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          Writer = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          WriterParent = InitiatingProcessParentFileName,
          FolderPath, FileName, SHA256
| order by Timestamp desc
```

### Developer-credential file read by non-IDE / non-CLI process

`UC_116_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as first_seen values(Filesystem.file_name) as files values(Filesystem.process_name) as reader from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.npmrc" OR Filesystem.file_path="*\\.aws\\credentials" OR Filesystem.file_path="*\\.ssh\\id_*" OR Filesystem.file_path="*\\.kube\\config" OR Filesystem.file_path="*\\.docker\\config.json" OR Filesystem.file_path="*\\.netrc" OR Filesystem.file_path="*\\AppData\\Roaming\\gh\\hosts.yml" OR Filesystem.file_path="*\\.config\\gh\\hosts.yml") Filesystem.process_name!="Code.exe" Filesystem.process_name!="code.exe" Filesystem.process_name!="git.exe" Filesystem.process_name!="ssh.exe" Filesystem.process_name!="ssh-agent.exe" Filesystem.process_name!="gh.exe" Filesystem.process_name!="aws.exe" Filesystem.process_name!="kubectl.exe" Filesystem.process_name!="docker.exe" Filesystem.process_name!="explorer.exe" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let CredFiles = dynamic([".npmrc",".aws\\credentials",".ssh\\id_rsa",".ssh\\id_ed25519",".ssh\\id_ecdsa",".kube\\config",".docker\\config.json",".netrc","gh\\hosts.yml"]);
let LegitReaders = dynamic(["code.exe","code - insiders.exe","code-insiders.exe","cursor.exe","git.exe","ssh.exe","ssh-agent.exe","sshd.exe","gh.exe","aws.exe","kubectl.exe","docker.exe","docker-desktop.exe","explorer.exe","backup.exe","onedrive.exe","pwsh.exe","powershell.exe","cmd.exe","bash.exe","node.exe","npm.exe","yarn.exe","pnpm.exe","helm.exe"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated" or ActionType == "FileModified" or ActionType startswith "FileOpen"
| where FolderPath has_any (CredFiles) or FileName in~ (".npmrc","credentials","id_rsa","id_ed25519","id_ecdsa","config","hosts.yml",".netrc")
| where FolderPath has_any ("\\Users\\","\\home\\")
| where InitiatingProcessFileName !in~ (LegitReaders)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          Reader = InitiatingProcessFileName,
          ReaderCmd = InitiatingProcessCommandLine,
          ReaderParent = InitiatingProcessParentFileName,
          FolderPath, FileName
| order by Timestamp desc
```

### Newly-installed npm/pip package spawns SMTP / mail-protocol outbound

`UC_116_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as first_seen values(All_Traffic.dest) as dest values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.process) as cmd from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("node.exe","npm.exe","yarn.exe","pnpm.exe","python.exe","python3.exe","pip.exe") All_Traffic.dest_port IN (25,465,587,2525,143,993,110,995) by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","npm.cmd","yarn.exe","yarn.cmd","pnpm.exe","python.exe","python3.exe","pip.exe","pip3.exe")
| where RemotePort in (25, 465, 587, 2525, 143, 993, 110, 995)
| where RemoteIPType == "Public"
| extend MailProto = case(RemotePort in (25,2525), "SMTP",
                          RemotePort == 465, "SMTPS",
                          RemotePort == 587, "Submission",
                          RemotePort in (143,993), "IMAP",
                          RemotePort in (110,995), "POP3", "Other")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          Proc = InitiatingProcessFileName,
          Cmd = InitiatingProcessCommandLine,
          ParentProc = InitiatingProcessParentFileName,
          RemoteIP, RemoteUrl, RemotePort, MailProto
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

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
