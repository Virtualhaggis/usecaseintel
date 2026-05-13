# [HIGH] Sha1-Hulud: The Second Coming - Zapier, ENS Domains, and Other Prominent NPM Packages Compromised

**Source:** StepSecurity
**Published:** 2025-12-15
**Article:** https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised

## Threat Profile

Back to Blog Threat Intel Sha1-Hulud: The Second Coming - Zapier, ENS Domains, and Other Prominent NPM Packages Compromised The Shai-Hulud NPM Worm Returns as "Sha1-Hulud: The Second Coming" - Devastating Supply Chain Attack Compromises Zapier and ENS Ecosystems, Creates 22,000+ Malicious Repositories and counting Ashish Kurmi View LinkedIn November 23, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
The JavaScript ecosystem i…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1543** — Create or Modify System Process
- **T1053** — Scheduled Task/Job
- **T1554** — Compromise Host Software Binary
- **T1485** — Data Destruction
- **T1070.004** — Indicator Removal: File Deletion

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Sha1-Hulud: npm preinstall hook spawns bun.sh installer via curl/PowerShell

`UC_486_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","node","npm.exe","npm","npm-cli.js","yarn","yarn.exe","pnpm","pnpm.exe") OR Processes.parent_process IN ("*setup_bun.js*","*preinstall*")) AND (Processes.process IN ("*bun.sh/install*","*bun.sh\\install.ps1*","*irm bun.sh*","*iwr bun.sh*","*curl*-fsSL*bun.sh*")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node","npm.exe","npm-cli.js","yarn.exe","pnpm.exe","bash","sh","cmd.exe","powershell.exe")
     or InitiatingProcessCommandLine has_any ("setup_bun.js","preinstall")
| where ProcessCommandLine has_any ("bun.sh/install", @"bun.sh\install.ps1", "irm bun.sh", "iwr bun.sh", "curl -fsSL https://bun.sh")
| project Timestamp, DeviceName, AccountName,
          ParentFile = InitiatingProcessFileName,
          ParentCmd  = InitiatingProcessCommandLine,
          ChildFile  = FileName,
          ChildCmd   = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] Sha1-Hulud: self-hosted GitHub Actions runner registered with name "SHA1HULUD"

`UC_486_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*--name*SHA1HULUD*" OR Processes.process="*actions-runner-linux-x64-2.330.0*" OR Processes.process="*RUNNER_ALLOW_RUNASROOT=1*config.sh*" OR Processes.process="*.dev-env*config.sh*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Process side
let runner_proc = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where ProcessCommandLine has_any ("--name \"SHA1HULUD\"", "--name SHA1HULUD", "actions-runner-linux-x64-2.330.0", "RUNNER_ALLOW_RUNASROOT=1")
         or (ProcessCommandLine has "config.sh" and ProcessCommandLine has @".dev-env")
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              Signal="process";
// File side — runner tarball lands in $HOME/.dev-env
let runner_file = DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FolderPath has ".dev-env"
         and (FileName =~ "actions-runner-linux-x64-2.330.0.tar.gz"
           or FileName in~ ("config.sh","run.sh","runsvc.sh",".runner",".credentials"))
    | project Timestamp, DeviceName, FileName, FolderPath,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              AccountName = InitiatingProcessAccountName,
              Signal="file";
union runner_proc, runner_file
| order by Timestamp desc
```

### [LLM] Sha1-Hulud Stage-5 destructive home-directory shred via find | xargs shred -uvz

`UC_486_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*shred*-uvz*" OR Processes.process="*shred -u*-n 1*" OR (Processes.process="*find*$HOME*" AND Processes.process="*-writable*" AND Processes.process="*shred*") OR Processes.process="*xargs*-0*-r*shred*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName !endswith "$"
| where ProcessCommandLine has "shred"
     and (ProcessCommandLine has "-uvz"
       or ProcessCommandLine has_all ("shred","-u","-n 1"))
| where ProcessCommandLine has_any (@"$HOME", "/home/", "/root", "id -un", "-writable")
     or InitiatingProcessCommandLine has_any (@"$HOME", "-writable", "id -un")
| project Timestamp, DeviceName, AccountName,
          ParentFile = InitiatingProcessFileName,
          ParentCmd  = InitiatingProcessCommandLine,
          ChildFile  = FileName,
          ChildCmd   = ProcessCommandLine
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

### Article-specific behavioural hunt — Sha1-Hulud: The Second Coming - Zapier, ENS Domains, and Other Prominent NPM Pac

`UC_486_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Sha1-Hulud: The Second Coming - Zapier, ENS Domains, and Other Prominent NPM Pac ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("bun_environment.js","setup_bun.js","bun.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/src/app*" OR Filesystem.file_path="*/root/.bun/bin/bun*" OR Filesystem.file_name IN ("bun_environment.js","setup_bun.js","bun.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Sha1-Hulud: The Second Coming - Zapier, ENS Domains, and Other Prominent NPM Pac
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("bun_environment.js", "setup_bun.js", "bun.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/src/app", "/root/.bun/bin/bun") or FileName in~ ("bun_environment.js", "setup_bun.js", "bun.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 9 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
