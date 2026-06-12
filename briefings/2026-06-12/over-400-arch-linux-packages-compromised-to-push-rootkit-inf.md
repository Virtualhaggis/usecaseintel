# [HIGH] Over 400 Arch Linux packages compromised to push rootkit, infostealer

**Source:** BleepingComputer
**Published:** 2026-06-12
**Article:** https://www.bleepingcomputer.com/news/security/over-400-arch-linux-packages-compromised-to-push-rootkit-infostealer/

## Threat Profile

Over 400 Arch Linux packages compromised to push rootkit, infostealer 
By Bill Toulas 
June 12, 2026
01:03 PM
0 
More than 400 packages in the Arch User Repository (AUR) are distributing a Linux rootkit and infostealer malware targeting credentials and access tokens.
A report from the open-source intelligence community Independent Federated Intelligence Network (IFIN) notes that a new maintainer is spoofing a trusted publisher on the AUR platform to push infected packages.
The Arch Linux distrib…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion`
- **Domain (defanged):** `temp.sh`
- **SHA256:** `6144D433F8A0316869877B5F834C801251BBB936E5F1577C5680878C7443C98B`
- **MD5:** `42B59FDBE1B72895B2951412222EBF40`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1204.002** — User Execution: Malicious File
- **T1068** — Exploitation for Privilege Escalation
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1555** — Credentials from Password Stores
- **T1567.002** — Exfiltration to Cloud Storage
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090.003** — Proxy: Multi-hop Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Atomic Arch — pacman/makepkg post-install spawning npm install of atomic-lockfile

`UC_10_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("makepkg","pacman","bash","sh","zsh") AND Processes.process_name IN ("npm","node","pnpm","yarn","npx") AND Processes.process="*atomic-lockfile*" by host Processes.parent_process_name Processes.process_name Processes.process Processes.user | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("makepkg","pacman","bash","sh","zsh")
| where FileName has_any ("npm","node","pnpm","yarn","npx")
| where ProcessCommandLine has "atomic-lockfile"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Atomic Arch — ELF payload 'deps' written or executed under build/cache directories after AUR install

`UC_10_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_hash="6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b" OR Filesystem.file_hash="42b59fdbe1b72895b2951412222ebf40" OR (Filesystem.file_name="deps" AND (Filesystem.file_path="*/.cache/*" OR Filesystem.file_path="*/.npm/*" OR Filesystem.file_path="*/build/*" OR Filesystem.file_path="/tmp/*" OR Filesystem.file_path="*/node_modules/*"))) by host Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where SHA256 == "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
   or MD5 == "42b59fdbe1b72895b2951412222ebf40"
   or (FileName == "deps" and FolderPath has_any ("/.cache/", "/.npm/", "/build/", "/tmp/", "/node_modules/"))
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, MD5, FileSize, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Atomic Arch rootkit — eBPF program load by AUR-build-chain descendant

`UC_10_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process="*BPF_PROG_LOAD*" OR Processes.process="*bpf(*" OR Processes.process="*sys_bpf*" OR Processes.process="*CAP_BPF*") AND Processes.parent_process_name IN ("pacman","makepkg","npm","node","sh","bash","deps") AND NOT Processes.process_name IN ("systemd","kubelet","cilium-agent","bpftool","containerd","dockerd") by host Processes.process_name Processes.parent_process_name Processes.process Processes.user | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("BpfProgramLoaded","SyscallAudit","EBPFActivity")
   or AdditionalFields has_any ("BPF_PROG_LOAD","sys_bpf","CAP_BPF","type=BPF")
| where InitiatingProcessFileName !in~ ("systemd","systemd-bpf","kubelet","cilium-agent","bpftool","containerd","dockerd","falcon-sensor","runc")
| where InitiatingProcessParentFileName has_any ("pacman","makepkg","npm","node","sh","bash")
   or InitiatingProcessFileName == "deps"
   or InitiatingProcessCommandLine has_any ("atomic-lockfile","/deps")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessFolderPath, AdditionalFields
| order by Timestamp desc
```

### Atomic Arch infostealer — bulk reads of SSH/npmrc/Vault/browser-cookie files by non-shell process

`UC_10_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count dc(Filesystem.file_path) as distinct_paths values(Filesystem.file_path) as file_paths values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.vault-token" OR Filesystem.file_path="*/.config/Slack/*" OR Filesystem.file_path="*/.config/discord/*" OR Filesystem.file_path="*/Microsoft/Teams/*" OR Filesystem.file_path="*/cookies.sqlite" OR Filesystem.file_path="*/Login Data") AND NOT Filesystem.process_name IN ("ssh","sshd","ssh-agent","scp","sftp","gpg-agent","git","firefox","chrome","chromium","brave","slack","teams","discord","keepassxc","gnome-keyring-d") by host Filesystem.process_name Filesystem.user bin(_time,5m) | `drop_dm_object_name(Filesystem)` | where distinct_paths >= 4
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRead","FileOpened","FileAccessed","FileModified")
| where FolderPath has_any ("/.ssh/", "/.npmrc", "/.docker/config.json", "/.vault-token", "/.config/Slack/", "/.config/discord/", "/.config/Microsoft/Teams/", "/.mozilla/firefox/", "/snap/firefox", "/.config/google-chrome/", "/.config/chromium/")
   or FileName in~ ("id_rsa","id_ed25519","id_ecdsa","cookies.sqlite","Cookies","Login Data",".vault-token",".npmrc")
| where InitiatingProcessFileName !in~ ("sshd","ssh","scp","sftp","ssh-agent","gpg-agent","git","firefox","chrome","chromium","brave","slack","teams","discord","keepassxc","gnome-keyring-d","systemd","systemd-user","cron","tar","rsync","backup")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), DistinctPaths=dcount(FolderPath), SamplePaths=make_set(FolderPath, 20), SampleFiles=make_set(FileName, 20) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessParentFileName
| where DistinctPaths >= 4
| order by FirstSeen desc
```

### Atomic Arch — DNS resolution and HTTP POST to temp.sh from non-browser developer workstation process

`UC_10_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.bytes_out) as bytes_out values(Web.http_method) as http_method values(Web.user) as user from datamodel=Web.Web where (Web.url="*temp.sh*" OR Web.dest="temp.sh" OR Web.site="temp.sh") AND NOT Web.app IN ("firefox","chrome","chromium","brave","safari","msedge") by host Web.app Web.url Web.http_method Web.user | `drop_dm_object_name(Web)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "temp.sh" or RemoteUrl endswith ".temp.sh"
| where InitiatingProcessFileName !in~ ("chrome","firefox","msedge","safari","brave","chromium","opera")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemoteUrl, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Atomic Arch — Tor client spawn or .onion endpoint contact from AUR-installing developer host

`UC_10_11` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name IN ("tor","tor.real","torify","torsocks","obfs4proxy") OR Processes.process="*olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid*" OR Processes.process="*.onion*") by host Processes.process_name Processes.parent_process_name Processes.process Processes.user | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
let TorProcs = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName in~ ("tor","tor.real","torify","torsocks","obfs4proxy","snowflake-client")
       or ProcessCommandLine has_any (".onion","olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid","SocksPort","HiddenServiceDir")
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, SHA256, Source="Process";
let OnionDNS = DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemoteUrl has ".onion" or RemoteUrl has "olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid"
    | project Timestamp, DeviceName, AccountName, FileName=InitiatingProcessFileName, FolderPath=InitiatingProcessFolderPath, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, SHA256=InitiatingProcessSHA256, Source="Network";
union TorProcs, OnionDNS
| order by Timestamp desc
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

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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
  - IP / domain IOC(s): `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion`, `temp.sh`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `6144D433F8A0316869877B5F834C801251BBB936E5F1577C5680878C7443C98B`, `42B59FDBE1B72895B2951412222EBF40`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
