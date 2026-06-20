# [CRIT] 400+ AUR Packages Hijacked: What the “Atomic Arch” Campaign Means for Supply-Chain Security

**Source:** StepSecurity
**Published:** 2026-06-18
**Article:** https://www.stepsecurity.io/blog/400-aur-packages-hijacked-atomic-arch-campaign

## Threat Profile

Back to Blog Threat Intel 400+ AUR Packages Hijacked: What the “Atomic Arch” Campaign Means for Supply-Chain Security On June 11th 2026, security researchers and the Arch Linux community disclosed a large-scale supply-chain attack against the Arch User Repository (AUR). Attackers hijacked more than 400 community packages and turned them into a malware delivery network. While the immediate blast radius is limited to Arch Linux systems, the campaign is a textbook example of how modern attackers co…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `temp.sh`
- **Domain (defanged):** `github.com/fardewoak/nodejs-argo`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1567.002** — Exfiltration to Cloud Storage
- **T1572** — Protocol Tunneling
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1014** — Rootkit
- **T1547.006** — Boot or Logon Autostart Execution: Kernel Modules and Extensions

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Atomic Arch malicious npm/bun dependency install via hijacked AUR PKGBUILD

`UC_71_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*" OR Processes.process="*lockfile-js*") AND (Processes.process="*npm*" OR Processes.process="*bun*" OR Processes.process="*npx*" OR Processes.process="*node*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest","lockfile-js")
| where ProcessCommandLine has_any ("npm","bun","npx","pnpm","yarn","node")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          ParentImage = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Node/bun build process reading SSH keys, Vault tokens & browser credential stores

`UC_71_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.process_name IN ("node","bun","npm","npx","pnpm","yarn")) AND (Filesystem.file_path="*/.ssh/*" OR Filesystem.file_path="*/.vault-token*" OR Filesystem.file_path="*known_hosts*" OR Filesystem.file_path="*/google-chrome/*" OR Filesystem.file_path="*/.mozilla/firefox/*" OR Filesystem.file_path="*/Slack/*" OR Filesystem.file_path="*/discord/*" OR Filesystem.file_path="*/.docker/config.json*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*/.npmrc*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node","bun","npm","npx","pnpm","yarn")
| where FolderPath has_any ("/.ssh/","/.vault-token","known_hosts","/google-chrome/","/.mozilla/firefox/","/Slack/","/discord/","/.docker/config.json","/.aws/credentials","/.npmrc","/.config/gh/")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FolderPath, FileName
| order by Timestamp desc
```

### Egress to Atomic Arch C2/exfil infrastructure (temp.sh, fardewoak/nodejs-argo)

`UC_71_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*temp.sh" OR DNS.query="*.temp.sh" OR DNS.query="*fardewoak*") by DNS.src DNS.query DNS.dest
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl endswith "temp.sh" or RemoteUrl has "fardewoak"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### Package-build process making unexpected public network egress during AUR install

`UC_71_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app IN ("makepkg","npm","bun","node","npx","pacman","yay","paru")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| where NOT (cidrmatch("10.0.0.0/8",dest) OR cidrmatch("172.16.0.0/12",dest) OR cidrmatch("192.168.0.0/16",dest) OR cidrmatch("127.0.0.0/8",dest))
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("makepkg","npm","bun","node","npx","pacman","yay","paru")
| where RemoteIPType == "Public"
| where not(RemoteUrl has_any ("registry.npmjs.org","registry.yarnpkg.com","github.com","githubusercontent.com","archlinux.org","mirror","cloudflare","fastly","jsdelivr","unpkg.com","ghcr.io"))
| summarize ConnCount=count(), Domains=make_set(RemoteUrl,10), DestIPs=make_set(RemoteIP,10), arg_min(Timestamp,*) by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Atomic Arch persistence: node/bun writing systemd unit or eBPF/kernel-module load

`UC_71_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.process_name IN ("node","bun","npm","npx","makepkg","bash","sh","python3")) AND (Filesystem.file_path="*/etc/systemd/system/*" OR Filesystem.file_path="*/usr/lib/systemd/system/*" OR Filesystem.file_path="*/.config/systemd/user/*") AND (Filesystem.file_name="*.service" OR Filesystem.file_name="*.timer") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath has_any ("/etc/systemd/system/","/usr/lib/systemd/system/","/etc/systemd/user/","/.config/systemd/user/")
| where FileName endswith ".service" or FileName endswith ".timer"
| where InitiatingProcessFileName in~ ("node","bun","npm","npx","makepkg","bash","sh","python3")
   or InitiatingProcessParentFileName in~ ("makepkg","npm","bun","node","pacman","yay","paru")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FolderPath, FileName, ActionType
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
  - IP / domain IOC(s): `temp.sh`, `github.com/fardewoak/nodejs-argo`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
