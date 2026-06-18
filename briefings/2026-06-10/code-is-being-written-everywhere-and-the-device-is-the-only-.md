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
- **T1568** — Dynamic Resolution
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1071.003** — Application Layer Protocol: Mail Protocols
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1546.016** — Event Triggered Execution: Installer Packages
- **T1176** — Browser Extensions
- **T1059** — Command and Scripting Interpreter
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Developer endpoint contacting Glassworm/TeamPCP supply-chain campaign C2 (IOC match)

`UC_114_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as ports values(All_Traffic.app) as proc from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest in ("142.11.206.73","45.32.150.251","45.32.151.157","70.34.242.255") OR All_Traffic.dest_host="giftshop.club" OR All_Traffic.dest_host="sfrclak.com" OR All_Traffic.dest_host="*.giftshop.club" OR All_Traffic.dest_host="*.sfrclak.com") by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_host | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | append [| tstats summariesonly=true count from datamodel=Network_Resolution.DNS where (DNS.query="giftshop.club" OR DNS.query="sfrclak.com" OR DNS.query="*.giftshop.club" OR DNS.query="*.sfrclak.com") by DNS.src, DNS.query | `drop_dm_object_name(DNS)`]
```

**Defender KQL:**
```kql
let IOC_IPs = dynamic(["142.11.206.73","45.32.150.251","45.32.151.157","70.34.242.255"]);
let IOC_Domains = dynamic(["giftshop.club","sfrclak.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (IOC_IPs)
   or RemoteUrl has_any (IOC_Domains)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Node child of npm install making first-seen outbound to SMTP / cloud mail API or unusual host

`UC_114_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="npm.exe" OR Processes.parent_process_name="yarn.exe" OR Processes.parent_process_name="pnpm.exe" OR Processes.parent_process_name="npx.exe" OR Processes.parent_process_name="npm-cli.js") AND Processes.process_name="node.exe" by Processes.dest, Processes.user, Processes.process_id, Processes.process, Processes.parent_process | `drop_dm_object_name(Processes)` | rename process_id as src_process_id | join type=inner dest src_process_id [| tstats summariesonly=true count values(All_Traffic.dest) as remote_ip values(All_Traffic.dest_port) as remote_port values(All_Traffic.dest_host) as remote_host from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_port IN (25,465,587,2525) OR All_Traffic.dest_host IN ("smtp.sendgrid.net","api.mailgun.net","api.postmarkapp.com","smtp.gmail.com","smtp.office365.com")) AND NOT (All_Traffic.dest_host IN ("registry.npmjs.org","registry.yarnpkg.com","github.com","objects.githubusercontent.com","raw.githubusercontent.com")) by All_Traffic.src, All_Traffic.src_process_id | `drop_dm_object_name(All_Traffic)`] | where firstTime > relative_time(now(),"-24h")
```

**Defender KQL:**
```kql
let RecentHours = 24h;
let BaselineDays = 30d;
let AllowedHosts = dynamic(["registry.npmjs.org","registry.yarnpkg.com","github.com","objects.githubusercontent.com","raw.githubusercontent.com","nodejs.org"]);
let SmtpPorts = dynamic([25,465,587,2525]);
let MailApiHosts = dynamic(["sendgrid.net","mailgun.net","postmarkapp.com","smtp.gmail.com","smtp.office365.com","api.resend.com","api.mailchimp.com"]);
let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(BaselineDays) .. ago(RecentHours))
    | where InitiatingProcessFileName =~ "node.exe"
    | summarize by DeviceId, RemoteIP;
DeviceNetworkEvents
| where Timestamp > ago(RecentHours)
| where InitiatingProcessFileName =~ "node.exe"
| where InitiatingProcessParentFileName in~ ("npm.exe","yarn.exe","pnpm.exe","npx.exe","node.exe")
| where RemoteIPType == "Public"
| where RemotePort in (SmtpPorts) or RemoteUrl has_any (MailApiHosts)
| where not (RemoteUrl has_any (AllowedHosts))
| join kind=leftanti Baseline on DeviceId, RemoteIP
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessParentFileName, InitiatingProcessCommandLine,
          RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### npm postinstall hook spawning credential-harvest child process within 60s of package install

`UC_114_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.ssh\\id_*" OR Filesystem.file_path="*\\.aws\\credentials" OR Filesystem.file_path="*\\.npmrc" OR Filesystem.file_path="*\\.docker\\config.json" OR Filesystem.file_path="*\\.kube\\config" OR Filesystem.file_path="*\\AppData\\Roaming\\gh\\hosts.yml" OR Filesystem.file_path="*\\Library\\Application Support\\Google\\Chrome\\*\\Login Data") AND (Filesystem.process_name="node.exe" OR Filesystem.process_name="node" OR Filesystem.process_name="sh" OR Filesystem.process_name="bash.exe") by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.process_name, Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | join type=inner process_guid [| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.parent_process_name="npm.exe" OR Processes.parent_process_name="yarn.exe" OR Processes.parent_process_name="pnpm.exe") by Processes.dest, Processes.process_guid, Processes.parent_process | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
let CredentialPaths = dynamic([
    @"\.ssh\id_",
    @"\.ssh\config",
    @"\.aws\credentials",
    @"\.aws\config",
    @"\.npmrc",
    @"\.docker\config.json",
    @"\.kube\config",
    @"\AppData\Roaming\gh\hosts.yml",
    @"\AppData\Local\Google\Chrome\User Data\Default\Login Data",
    @"\Library\Application Support\Google\Chrome",
    @"\.config\gh\hosts.yml",
    @"\.gitconfig"
  ]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed","FileAccessed")
   or ActionType == "FileOpenedForRead"
| where FolderPath has_any (CredentialPaths)
| where InitiatingProcessFileName in~ ("node.exe","node","sh","bash.exe","cmd.exe","powershell.exe","pwsh.exe")
| where InitiatingProcessParentFileName in~ ("npm.exe","yarn.exe","pnpm.exe","npx.exe","node.exe")
   or InitiatingProcessCommandLine has_any ("postinstall","preinstall","install.js")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### VS Code extension host writing executable and spawning it from extension directory (Glassworm pattern)

`UC_114_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as writeTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.vscode\\extensions\\*" OR Filesystem.file_path="*\\Code\\User\\globalStorage\\*") AND (Filesystem.file_name="*.exe" OR Filesystem.file_name="*.dll" OR Filesystem.file_name="*.ps1" OR Filesystem.file_name="*.bat" OR Filesystem.file_name="*.scr") AND (Filesystem.process_name="Code.exe" OR Filesystem.process_name="node.exe") by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name | `drop_dm_object_name(Filesystem)` | join type=inner dest [| tstats summariesonly=true count min(_time) as execTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="Code.exe" OR Processes.parent_process_path="*\\.vscode\\*") AND Processes.process_path="*\\.vscode\\extensions\\*" by Processes.dest, Processes.process_path, Processes.process | `drop_dm_object_name(Processes)`] | eval delta=execTime-writeTime | where delta>=0 AND delta<600
```

**Defender KQL:**
```kql
let WriteWindow = 10m;
let ExtensionWrites = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("FileCreated","FileModified")
    | where FolderPath has_any (@"\.vscode\extensions\", @"\Code\User\globalStorage\")
    | where FileName endswith ".exe" or FileName endswith ".dll"
         or FileName endswith ".ps1" or FileName endswith ".bat"
         or FileName endswith ".scr" or FileName endswith ".vbs"
    | where InitiatingProcessFileName in~ ("Code.exe","node.exe")
    | project WriteTime=Timestamp, DeviceId, DeviceName,
              WrittenPath=strcat(FolderPath, FileName),
              InitiatingProcessAccountName, SHA256;
ExtensionWrites
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FolderPath has @"\.vscode\extensions\"
       or InitiatingProcessFolderPath has @"\.vscode\extensions\"
    | project ExecTime=Timestamp, DeviceId, DeviceName,
              ExecutedPath=strcat(FolderPath, FileName),
              ProcessCommandLine, InitiatingProcessFileName
  ) on DeviceId
| where ExecTime between (WriteTime .. WriteTime + WriteWindow)
| where ExecutedPath =~ WrittenPath
| project WriteTime, ExecTime, DeviceName,
          InitiatingProcessAccountName,
          DroppedPath=WrittenPath, SHA256,
          ProcessCommandLine, SpawnedBy=InitiatingProcessFileName
| order by WriteTime desc
```

### Known Glassworm/TeamPCP malicious file hash written to developer endpoint

`UC_114_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
(`endpoint_index`) (sha1="2553649f2322049666871cea80a5d0d6adc700ca" OR sha1="d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71" OR sha1="07d889e2dadce6f3910dcbc253317d28ca61c766") | stats earliest(_time) as firstSeen latest(_time) as lastSeen values(file_path) as paths values(user) as users values(process_name) as procs by host, sha1 | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
let IOC_SHA1 = dynamic(["2553649f2322049666871cea80a5d0d6adc700ca","d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71","07d889e2dadce6f3910dcbc253317d28ca61c766"]);
union isfuzzy=true
  (DeviceFileEvents
   | where Timestamp > ago(90d)
   | where SHA1 in (IOC_SHA1)
   | project Timestamp, Source="FileEvent", DeviceName, AccountName=InitiatingProcessAccountName,
             FolderPath, FileName, SHA1, SHA256,
             InitiatingProcessFileName, InitiatingProcessCommandLine,
             FileOriginUrl),
  (DeviceProcessEvents
   | where Timestamp > ago(90d)
   | where SHA1 in (IOC_SHA1) or InitiatingProcessSHA1 in (IOC_SHA1)
   | project Timestamp, Source="ProcessEvent", DeviceName, AccountName,
             FolderPath, FileName, SHA1, SHA256,
             InitiatingProcessFileName, InitiatingProcessCommandLine,
             FileOriginUrl="")
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

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
