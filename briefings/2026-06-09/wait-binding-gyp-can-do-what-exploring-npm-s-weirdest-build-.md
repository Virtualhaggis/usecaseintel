# [CRIT] Wait, binding.gyp Can Do What? Exploring npm's Weirdest Build System

**Source:** Aikido
**Published:** 2026-06-09
**Article:** https://www.aikido.dev/blog/exploring-binding-gyp-npm-build-system

## Threat Profile

Blog Vulnerabilities & Threats Wait, binding.gyp Can Do What? Exploring npm's Weirdest Build System Wait, binding.gyp Can Do What? Exploring npm's Weirdest Build System Written by Ilyas Makari Published on: Jun 9, 2026 It has only been a couple of days since the Miasma attack hit 32 official Red Hat packages on npm. The worm added a malicious preinstall script to each compromised package, so that node index.js ran automatically the moment you installed the dependency, harvesting cloud credential…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90`
- **SHA256:** `288f26c2eadcb1a7923fe376d16f5404216cce15d9fc162a4a78574dc7df399a`
- **SHA256:** `e3dbe63aded45278f49c4746ab938ed9472b36def79b43e2dd2d7eff014481d1`
- **SHA256:** `ceff7c51d70832c3ec8dd2744b606a23b3c924ef664ae23439b9b742ea154108`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1505.005** — Server Software Component: Terminal Services DLL
- **T1567.001** — Exfiltration Over Web Service: Exfiltration to Code Repository
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Miasma Phantom Gyp: python.exe (gyp parser) spawning node index.js during npm install

`UC_345_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python.exe","python3.exe","python","python3") AND (Processes.parent_process="*gyp.py*" OR Processes.parent_process="*node-gyp*" OR Processes.parent_process="*binding.gyp*") AND (Processes.process_name IN ("node.exe","node","cmd.exe","sh","bash","dash","curl.exe","wget.exe","powershell.exe","pwsh.exe") OR Processes.process IN ("*index.js*","*__subclasses__*","*catch_warnings*","*/dev/null 2>&1*","*echo stub.c*")) AND NOT Processes.process_name IN ("cl.exe","link.exe","cmake.exe","msbuild.exe","gcc.exe","g++.exe","clang.exe","clang++.exe","make.exe","nmake.exe","ld.exe","tracker.exe","rc.exe","cvtres.exe","mt.exe") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.process_hash | `drop_dm_object_name(Processes)` | where user!="*$"
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","python","python3")
| where InitiatingProcessCommandLine has_any ("gyp.py","node-gyp","binding.gyp","gyp_main")
| where FileName !in~ ("cl.exe","link.exe","cmake.exe","msbuild.exe","gcc.exe","g++.exe","clang.exe","clang++.exe","make.exe","nmake.exe","ld.exe","tracker.exe","rc.exe","cvtres.exe","mt.exe","conhost.exe")
| where FileName in~ ("node.exe","node","cmd.exe","sh","bash","dash","curl.exe","wget.exe","powershell.exe","pwsh.exe")
   or ProcessCommandLine has_any ("index.js","__subclasses__","catch_warnings","echo stub.c","/dev/null 2>&1","__import__('os')","pymod_do_main")
| where AccountName !endswith "$"
| where InitiatingProcessFolderPath has_any ("node_modules","npm-cache","_npx","yarn","pnpm") or InitiatingProcessParentFileName in~ ("node.exe","npm.cmd","npx.cmd","yarn.cmd","pnpm.cmd")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Miasma-tainted package install: binding.gyp dropped into known-compromised npm package paths

`UC_345_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="binding.gyp" AND (Filesystem.file_path="*node_modules*@vapi-ai*server-sdk*" OR Filesystem.file_path="*node_modules*ai-sdk-ollama*" OR Filesystem.file_path="*node_modules*@redhat-cloud-services*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName =~ "binding.gyp"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (
    @"node_modules\@vapi-ai\server-sdk",
    "node_modules/@vapi-ai/server-sdk",
    @"node_modules\ai-sdk-ollama",
    "node_modules/ai-sdk-ollama",
    @"node_modules\@redhat-cloud-services",
    "node_modules/@redhat-cloud-services")
| where InitiatingProcessFileName !in~ ("git.exe","code.exe","explorer.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, FileSize, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Miasma payload SHA256 hash hit (published Phantom Gyp IOCs)

`UC_345_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90","288f26c2eadcb1a7923fe376d16f5404216cce15d9fc162a4a78574dc7df399a","e3dbe63aded45278f49c4746ab938ed9472b36def79b43e2dd2d7eff014481d1","ceff7c51d70832c3ec8dd2744b606a23b3c924ef664ae23439b9b742ea154108") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90","288f26c2eadcb1a7923fe376d16f5404216cce15d9fc162a4a78574dc7df399a","e3dbe63aded45278f49c4746ab938ed9472b36def79b43e2dd2d7eff014481d1","ceff7c51d70832c3ec8dd2744b606a23b3c924ef664ae23439b9b742ea154108") by Processes.dest Processes.user Processes.process Processes.process_hash Processes.parent_process | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
let MiasmaHashes = dynamic([
  "ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90",
  "288f26c2eadcb1a7923fe376d16f5404216cce15d9fc162a4a78574dc7df399a",
  "e3dbe63aded45278f49c4746ab938ed9472b36def79b43e2dd2d7eff014481d1",
  "ceff7c51d70832c3ec8dd2744b606a23b3c924ef664ae23439b9b742ea154108"
]);
union
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (MiasmaHashes)
    | project Timestamp, Source="FileEvent", DeviceName, AccountName=InitiatingProcessAccountName, Path=FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine ),
  ( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (MiasmaHashes)
    | project Timestamp, Source="ProcessEvent", DeviceName, AccountName, Path=FolderPath, FileName, SHA256, InitiatingProcessFileName=InitiatingProcessFileName, InitiatingProcessCommandLine=ProcessCommandLine )
| order by Timestamp desc
```

### Node child of node-gyp/python making outbound to GitHub dead-drop or anomalous web service during install

`UC_345_10` · phase: **exfil** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="node.exe" AND Processes.parent_process_name IN ("python.exe","python3.exe","cmd.exe","sh","bash") AND (Processes.parent_process="*gyp*" OR Processes.parent_process="*binding.gyp*" OR Processes.parent_process="*node-gyp*") by Processes.dest Processes.user Processes.process_id Processes.process_name Processes.parent_process Processes._time | `drop_dm_object_name(Processes)` | rename _time as proc_time process_id as suspect_pid | join type=inner dest suspect_pid [| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="api.github.com" OR All_Traffic.dest="raw.githubusercontent.com" OR All_Traffic.dest="*.workers.dev" OR All_Traffic.dest="*.webhook.site" OR All_Traffic.dest="*.ngrok.io" OR All_Traffic.dest="hooks.slack.com" OR All_Traffic.dest="discord.com") AND All_Traffic.app="node.exe" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | rename src as dest dest as net_dest app as suspect_pid]
```

**Defender KQL:**
```kql
let gyp_node_children = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "node.exe"
    | where InitiatingProcessFileName in~ ("python.exe","python3.exe","cmd.exe","sh","bash")
    | where InitiatingProcessCommandLine has_any ("gyp.py","binding.gyp","node-gyp")
        or InitiatingProcessParentFileName in~ ("python.exe","python3.exe")
    | where AccountName !endswith "$"
    | project ProcSpawnTime=Timestamp, DeviceId, DeviceName, AccountName, ProcessId, ProcessCommandLine, InitiatingProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where RemoteUrl has_any ("api.github.com","raw.githubusercontent.com","objects.githubusercontent.com",".workers.dev","webhook.site","ngrok.io","hooks.slack.com","discord.com/api/webhooks","transfer.sh","file.io","0x0.st")
   or RemoteIPType == "Public"
| join kind=inner gyp_node_children on DeviceId, $left.InitiatingProcessId == $right.ProcessId
| where Timestamp between (ProcSpawnTime .. ProcSpawnTime + 5m)
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort, ProcessCommandLine=InitiatingProcessCommandLine, GypParentCmd=InitiatingProcessCommandLine1
| order by Timestamp desc
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

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Wait, binding.gyp Can Do What? Exploring npm's Weirdest Build System

`UC_345_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Wait, binding.gyp Can Do What? Exploring npm's Weirdest Build System ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("index.js","node.js","evil.js","evil_script.js","malicious.js","evil.sh","cc-evil.sh","evil-wrapper.sh","cc-evil-wrapper.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/null*" OR Filesystem.file_path="*/usr/bin/cc*" OR Filesystem.file_name IN ("index.js","node.js","evil.js","evil_script.js","malicious.js","evil.sh","cc-evil.sh","evil-wrapper.sh","cc-evil-wrapper.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Wait, binding.gyp Can Do What? Exploring npm's Weirdest Build System
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("index.js", "node.js", "evil.js", "evil_script.js", "malicious.js", "evil.sh", "cc-evil.sh", "evil-wrapper.sh", "cc-evil-wrapper.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/null", "/usr/bin/cc") or FileName in~ ("index.js", "node.js", "evil.js", "evil_script.js", "malicious.js", "evil.sh", "cc-evil.sh", "evil-wrapper.sh", "cc-evil-wrapper.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90`, `288f26c2eadcb1a7923fe376d16f5404216cce15d9fc162a4a78574dc7df399a`, `e3dbe63aded45278f49c4746ab938ed9472b36def79b43e2dd2d7eff014481d1`, `ceff7c51d70832c3ec8dd2744b606a23b3c924ef664ae23439b9b742ea154108`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
