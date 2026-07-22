# [CRIT] SleeperGem: RubyGems supply chain attack targets dormant maintainer accounts

**Source:** Aikido
**Published:** 2026-07-19
**Article:** https://www.aikido.dev/blog/sleepergem-rubygems-supply-chain-attack

## Threat Profile

Blog Vulnerabilities & Threats SleeperGem: RubyGems supply chain attack targets dormant maintainer accounts SleeperGem: RubyGems supply chain attack targets dormant maintainer accounts Written by Charlie Eriksen Published on: Jul 19, 2026 It's not often we see a supply chain attack on RubyGems. But with summer vacations in full swing, perhaps we should have expected one. It was still a surprise when I opened the triage queue this morning and found a suspicious new package waiting.
A brand-new ge…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `git.disroot.org`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1105** — Ingress Tool Transfer
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059.004** — Unix Shell
- **T1053.003** — Scheduled Task/Job: Cron
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1543.001** — Create or Modify System Process: Launch Agent

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Ruby/gem process downloading payload from git.disroot.org (SleeperGem)

`UC_70_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="git.disroot.org" by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "git.disroot.org"
| where InitiatingProcessFileName in~ ("ruby.exe","ruby","gem","bundle","bundler","rake","irb")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Ruby interpreter spawning PowerShell -ExecutionPolicy bypass or /bin/sh (SleeperGem dropper)

`UC_70_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("ruby.exe","ruby","gem","bundle","bundler","rake","irb") AND Processes.process_name IN ("powershell.exe","pwsh.exe","sh","bash","dash","zsh")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.parent_process
| `drop_dm_object_name(Processes)`
| where match(process,"(?i)-ExecutionPolicy\s+bypass") OR process_name IN ("sh","bash","dash","zsh")
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("ruby.exe","ruby","gem","bundle","bundler","rake","irb")
| where FileName in~ ("powershell.exe","pwsh.exe","sh","bash","dash","zsh")
| where (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "ExecutionPolicy" and ProcessCommandLine has "bypass")
      or FileName in~ ("sh","bash","dash","zsh")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### SleeperGem malicious gem artifacts written to gems path (git_credential_manager / Dendreo / fastlane-plugin)

`UC_70_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*git_credential_manager*","*fastlane-plugin-run_tests_firebase_testlab*") OR Filesystem.file_path="*Dendreo-*") AND Filesystem.file_path IN ("*/gems/*","*\\gems\\*","*/specifications/*","*\\specifications\\*") by Filesystem.dest Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FolderPath has "gems" or FolderPath has "specifications")
| where FolderPath has_any ("git_credential_manager","fastlane-plugin-run_tests_firebase_testlab") or FolderPath matches regex @"(?i)[\\/]Dendreo-\d"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA256
| order by Timestamp desc
```

### SleeperGem Unix persistence: cron/systemd/LaunchAgent write by Ruby-descended shell

`UC_70_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/etc/systemd/system/*","/lib/systemd/system/*","/etc/cron.d/*","/var/spool/cron/*","/etc/crontab","/Library/LaunchAgents/*","/Library/LaunchDaemons/*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| where process_name IN ("ruby","sh","bash","dash","zsh","gem","bundle")
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any ("/etc/systemd/system/","/lib/systemd/system/","/etc/cron.d/","/var/spool/cron/","/etc/crontab","/Library/LaunchAgents/","/Library/LaunchDaemons/")
| where InitiatingProcessFileName in~ ("ruby","sh","bash","dash","zsh","gem","bundle")
   or InitiatingProcessParentFileName in~ ("ruby","gem","bundle")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FileName, FolderPath
| order by Timestamp desc
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

### Article-specific behavioural hunt — SleeperGem: RubyGems supply chain attack targets dormant maintainer accounts

`UC_70_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — SleeperGem: RubyGems supply chain attack targets dormant maintainer accounts ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/null*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — SleeperGem: RubyGems supply chain attack targets dormant maintainer accounts
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/null"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `git.disroot.org`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
