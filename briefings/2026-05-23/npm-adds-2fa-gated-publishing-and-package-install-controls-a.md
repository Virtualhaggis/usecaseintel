# [HIGH] npm Adds 2FA-Gated Publishing and Package Install Controls Against Supply Chain Attacks

**Source:** The Hacker News
**Published:** 2026-05-23
**Article:** https://thehackernews.com/2026/05/npm-adds-2fa-gated-publishing-and.html

## Threat Profile

Packagist Supply Chain Attack Infects 8 Packages Using GitHub-Hosted Linux Malware 
 Ravie Lakshmanan  May 23, 2026 Malware / DevSecOps 
A new "coordinated" supply chain attack campaign has impacted eight packages on Packagist including malicious code designed to run a Linux binary retrieved from a GitHub Releases URL.
"Although the affected packages were all Composer packages, the malicious code was not added to composer.json," Socket said . "Instead, it was inserted into package.json, target…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1546.016** — Event Triggered Execution: Installer Packages
- **T1204.003** — User Execution: Malicious Image
- **T1105** — Ingress Tool Transfer
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Packagist supply chain: Composer/npm postinstall fetching parikhpreyash4 GitHub payload

`UC_92_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_command_line="*parikhpreyash4*" OR Processes.process_command_line="*systemd-network-helper-aa5c751f*" OR Processes.process_command_line="*/tmp/.sshd*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_command_line Processes.process_path | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("parikhpreyash4", "systemd-network-helper-aa5c751f", "/tmp/.sshd")
   or InitiatingProcessCommandLine has_any ("parikhpreyash4", "systemd-network-helper-aa5c751f", "/tmp/.sshd")
| extend BuildParent = iff(InitiatingProcessFileName in~ ("node","npm","npx","yarn","pnpm","composer","composer.phar","php","sh","bash","dash","zsh"), true, false)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, BuildParent
| order by Timestamp desc
```

### [LLM] Linux dotfile drop at /tmp/.sshd masquerading as OpenSSH daemon

`UC_92_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="/tmp/.sshd" OR (Filesystem.file_path="/tmp" AND Filesystem.file_name=".sshd") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FolderPath has "/tmp" and FileName == ".sshd")
   or FolderPath has "/tmp/.sshd"
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] gvfsd-network binary executing from non-standard path (GNOME daemon masquerade)

`UC_92_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="gvfsd-network" AND NOT (Processes.process_path IN ("/usr/libexec/gvfsd-network","/usr/lib/gvfs/gvfsd-network") OR Processes.process_path="/usr/libexec/*" OR Processes.process_path="/usr/lib/gvfs/*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process_command_line Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "gvfsd-network"
| where not (FolderPath startswith "/usr/libexec" or FolderPath startswith "/usr/lib/gvfs" or FolderPath startswith "/usr/lib/x86_64-linux-gnu/gvfs")
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] Build tooling spawning curl/wget with TLS verification disabled

`UC_92_8` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("curl","wget") AND (Processes.process_command_line="*--insecure*" OR Processes.process_command_line="* -k *" OR Processes.process_command_line="*--no-check-certificate*") AND Processes.parent_process_name IN ("node","npm","npx","yarn","pnpm","composer","composer.phar","php","sh","bash","dash","zsh") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_command_line | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("curl","wget")
| where ProcessCommandLine has_any ("--insecure", " -k ", "--no-check-certificate")
| where InitiatingProcessFileName in~ ("node","npm","npx","yarn","pnpm","composer","composer.phar","php","sh","bash","dash","zsh")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### [LLM] Compromised Packagist Composer package vendor/ presence on hosts

`UC_92_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/vendor/moritz-sauer-13/silverstripe-cms-theme/*" OR Filesystem.file_path="*/vendor/crosiersource/crosierlib-base/*" OR Filesystem.file_path="*/vendor/devdojo/wave/*" OR Filesystem.file_path="*/vendor/devdojo/genesis/*" OR Filesystem.file_path="*/vendor/katanaui/katana/*" OR Filesystem.file_path="*/vendor/elitedevsquad/sidecar-laravel/*" OR Filesystem.file_path="*/vendor/r2luna/brain/*" OR Filesystem.file_path="*/vendor/baskarcm/tzi-chat-ui/*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CompromisedPaths = dynamic([
    "/vendor/moritz-sauer-13/silverstripe-cms-theme/",
    "/vendor/crosiersource/crosierlib-base/",
    "/vendor/devdojo/wave/",
    "/vendor/devdojo/genesis/",
    "/vendor/katanaui/katana/",
    "/vendor/elitedevsquad/sidecar-laravel/",
    "/vendor/r2luna/brain/",
    "/vendor/baskarcm/tzi-chat-ui/"
]);
DeviceFileEvents
| where Timestamp > ago(90d)
| where FolderPath has_any (CompromisedPaths)
| where FileName in~ ("package.json","composer.json","composer.lock")
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), WriteCount = count(), AnyInitiator = any(InitiatingProcessFileName), AnyCmd = any(InitiatingProcessCommandLine)
          by DeviceName, FolderPath, FileName
| order by FirstSeen desc
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
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

### Article-specific behavioural hunt — npm Adds 2FA-Gated Publishing and Package Install Controls Against Supply Chain

`UC_92_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — npm Adds 2FA-Gated Publishing and Package Install Controls Against Supply Chain ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/.sshd*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — npm Adds 2FA-Gated Publishing and Package Install Controls Against Supply Chain
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/.sshd"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
