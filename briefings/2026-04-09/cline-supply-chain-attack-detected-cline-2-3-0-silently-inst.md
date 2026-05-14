# [CRIT] Cline Supply Chain Attack Detected: cline@2.3.0 Silently Installs OpenClaw

**Source:** StepSecurity
**Published:** 2026-04-09
**Article:** https://www.stepsecurity.io/blog/cline-supply-chain-attack-detected-cline-2-3-0-silently-installs-openclaw

## Threat Profile

Back to Blog Threat Intel Cline Supply Chain Attack Detected: cline@2.3.0 Silently Installs OpenClaw StepSecurity' detected that cline@2.3.0 was published with a malicious post-install script that silently installs OpenClaw on any machine running npm install. Here's how the attack worked, how we caught it, and what you should do if you're affected. Sai Likhith View LinkedIn February 17, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-25253`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1546.016** — Installer Packages
- **T1059** — Command and Scripting Interpreter
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1543** — Create or Modify System Process
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1543.004** — Create or Modify System Process: Launch Daemon

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] cline@2.3.0 postinstall silently global-installs openclaw via npm

`UC_289_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm","npm.exe","npm-cli.js","node","node.exe") OR Processes.parent_process_name IN ("npm","npm.exe","npm-cli.js","node","node.exe")) AND (Processes.process="*openclaw*" OR Processes.process="*cline@2.3.0*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | where match(process, "(?i)(install\\s+(-g|--global)?\\s*openclaw|cline@2\\.3\\.0)") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("npm","npm.exe","node","node.exe","npm-cli.js") or FileName in~ ("npm","npm.exe","node","node.exe")
| where ProcessCommandLine has_any ("openclaw","cline@2.3.0")
| where ProcessCommandLine has "install"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] openclaw Gateway daemon listening on ws://127.0.0.1:18789

`UC_289_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.app) as app values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_port=18789 OR All_Traffic.src_port=18789) AND (All_Traffic.dest IN ("127.0.0.1","::1","localhost") OR All_Traffic.src IN ("127.0.0.1","::1","localhost")) by All_Traffic.dest All_Traffic.dest_port All_Traffic.transport host | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (LocalPort == 18789 and LocalIP in ("127.0.0.1","::1")) or (RemotePort == 18789 and RemoteIP in ("127.0.0.1","::1"))
| where ActionType in ("ListeningConnectionCreated","InboundConnectionAccepted","ConnectionSuccess")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Connections=count(), Processes=make_set(InitiatingProcessFileName,8), CmdLines=make_set(InitiatingProcessCommandLine,8) by DeviceName, LocalIP, LocalPort, ActionType
| order by FirstSeen desc
```

### [LLM] openclaw persistence daemon written to launchd / systemd

`UC_289_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/LaunchDaemons/*openclaw*" OR Filesystem.file_path="*/LaunchAgents/*openclaw*" OR Filesystem.file_path="*/systemd/system/*openclaw*" OR Filesystem.file_path="*/.config/systemd/user/*openclaw*" OR Filesystem.file_name="*openclaw*.plist" OR Filesystem.file_name="*openclaw*.service" OR Filesystem.file_path="*/.openclaw/credentials/*" OR Filesystem.file_path="*/.openclaw/config.json5") by Filesystem.dest Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has_any ("/LaunchDaemons/","/LaunchAgents/","/etc/systemd/system/","/.config/systemd/user/") and (FileName contains "openclaw" or FileName endswith ".plist" or FileName endswith ".service"))
   or (FolderPath has ".openclaw/credentials")
   or (FileName =~ "config.json5" and FolderPath has ".openclaw")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
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

### Article-specific behavioural hunt — Cline Supply Chain Attack Detected: cline@2.3.0 Silently Installs OpenClaw

`UC_289_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Cline Supply Chain Attack Detected: cline@2.3.0 Silently Installs OpenClaw ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("bun.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("bun.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Cline Supply Chain Attack Detected: cline@2.3.0 Silently Installs OpenClaw
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("bun.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("bun.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-25253`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
