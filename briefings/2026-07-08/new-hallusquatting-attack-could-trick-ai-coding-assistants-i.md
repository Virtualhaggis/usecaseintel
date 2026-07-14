# [HIGH] New HalluSquatting Attack Could Trick AI Coding Assistants Into Installing Botnet Malware

**Source:** The Hacker News
**Published:** 2026-07-08
**Article:** https://thehackernews.com/2026/07/new-hallusquatting-attack-could-trick.html

## Threat Profile

New HalluSquatting Attack Could Trick AI Coding Assistants Into Installing Botnet Malware 
 Swati Khandelwal  Jul 08, 2026 AI Security / Botnet 
AI coding assistants have a habit of making things up. Ask one to fetch a popular tool, and it will sometimes hand back a real-sounding name for a project that does not exist.
New research, which its authors call  HalluSquatting , turns that habit into an attack: work out the fake names an AI reliably invents, register them first, and wait for the ass…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `github.com/clever-utils/clever-utils`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AI coding assistant fetches known slopsquatted package/repo (react-codeshift, clever-utils)

`UC_102_7` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*react-codeshift*" OR Processes.process="*clever-utils*") AND Processes.process_name IN ("npm.exe","node.exe","npx.exe","yarn.exe","pnpm.exe","git.exe","pip.exe","pip3.exe","cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("react-codeshift","clever-utils")
| where FileName in~ ("npm.exe","node.exe","npx.exe","yarn.exe","pnpm.exe","git.exe","pip.exe","pip3.exe","cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### AI coding assistant clones/installs then auto-runs commands (HalluSquatting fetch→exec chain)

`UC_102_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where ((Processes.process_name="git.exe" AND Processes.process="*clone*") OR (Processes.process_name IN ("npm.exe","node.exe","npx.exe","yarn.exe","pnpm.exe","pip.exe","pip3.exe") AND Processes.process="*install*")) by _time span=1s Processes.dest Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| search parent_process_name IN ("cursor.exe","windsurf.exe","code.exe","node.exe","gemini.exe","claude.exe","openclaw.exe","zeroclaw.exe","nanoclaw.exe")
| rename _time as fetch_time, process as fetch_cmd
| join type=inner dest [
    | tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","python.exe","curl.exe","wget.exe") by _time span=1s Processes.dest Processes.parent_process_name Processes.process
    | `drop_dm_object_name(Processes)`
    | search parent_process_name IN ("cursor.exe","windsurf.exe","code.exe","node.exe","gemini.exe","claude.exe","openclaw.exe","zeroclaw.exe","nanoclaw.exe")
    | rename _time as exec_time, process as exec_cmd ]
| where exec_time>=fetch_time AND exec_time<=fetch_time+180
| table fetch_time exec_time dest parent_process_name fetch_cmd exec_cmd
```

**Defender KQL:**
```kql
let Window = 180s;
let Assistants = dynamic(["cursor.exe","windsurf.exe","code.exe","gemini.exe","claude.exe","openclaw.exe","zeroclaw.exe","nanoclaw.exe","node.exe"]);
let Fetch = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where (FileName =~ "git.exe" and ProcessCommandLine has "clone")
         or (FileName in~ ("npm.exe","node.exe","npx.exe","yarn.exe","pnpm.exe","pip.exe","pip3.exe") and ProcessCommandLine has "install")
    | where InitiatingProcessFileName in~ (Assistants)
         or InitiatingProcessParentFileName in~ (Assistants)
         or InitiatingProcessCommandLine has_any ("cline","gemini","claude","openclaw","zeroclaw","nanoclaw","windsurf","cursor","copilot")
    | project FetchTime = Timestamp, DeviceId, DeviceName, AccountName, FetchCmd = ProcessCommandLine, Assistant = InitiatingProcessFileName;
Fetch
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wsl.exe","python.exe","curl.exe","wget.exe")
    | where InitiatingProcessFileName in~ (Assistants)
         or InitiatingProcessCommandLine has_any ("cline","gemini","claude","openclaw","windsurf","cursor","copilot")
    | project ExecTime = Timestamp, DeviceId, ExecFile = FileName, ExecCmd = ProcessCommandLine
) on DeviceId
| where ExecTime between (FetchTime .. FetchTime + Window)
| project FetchTime, ExecTime, DelaySec = datetime_diff('second', ExecTime, FetchTime), DeviceName, AccountName, Assistant, FetchCmd, ExecFile, ExecCmd
| order by FetchTime desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `github.com/clever-utils/clever-utils`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
