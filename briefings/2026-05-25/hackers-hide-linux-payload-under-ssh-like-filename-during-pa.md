# [HIGH] Hackers Hide Linux Payload Under SSH-Like Filename During Package Installation

**Source:** Cyber Security News
**Published:** 2026-05-25
**Article:** https://cybersecuritynews.com/hackers-hide-linux-payload-under-ssh-like-filename/

## Threat Profile

Home Cyber Security News 
Hackers Hide Linux Payload Under SSH-Like Filename During Package Installation 
By Tushar Subhra Dutta 
May 25, 2026 
A new supply chain attack campaign is quietly targeting developers through a method most would never think to look for. 
Hidden inside software packages on GitHub, a malicious script downloads a Linux binary during installation and disguises it using a filename designed to look like a standard system process. The attack has now touched more than 700 repo…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1105** — Ingress Tool Transfer
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1564.001** — Hide Artifacts: Hidden Files and Directories

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Package postinstall curl downloads GitHub-Releases binary to /tmp/.sshd (supply-chain implant)

`UC_4_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=curl by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id | `drop_dm_object_name(Processes)` | where match(process,"(?i)/tmp/\.sshd") OR (match(process,"(?i)\-sk|\-skL|\-\-insecure") AND match(process,"(?i)github\.com/.+/releases/.+/download")) | search parent_process_name IN (sh,bash,dash,node,npm,php,composer,yarn,dash,zsh) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "curl"
| where ProcessCommandLine has "/tmp/.sshd"
   or (ProcessCommandLine has_any ("-sk","-skL","--insecure","-k ") and ProcessCommandLine has_all ("github.com","releases","download"))
   or ProcessCommandLine has_any ("fvbs.network","gvfsd-network")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Execution of dot-prefixed /tmp binary masquerading as SSH daemon (/tmp/.sshd)

`UC_4_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_path="/tmp/.sshd" OR Processes.process_name=".sshd" by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FolderPath =~ "/tmp/.sshd" or (FileName == ".sshd" and FolderPath startswith "/tmp/")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Hidden executable written to /tmp/.sshd by curl/package-manager (payload drop)

`UC_4_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="/tmp/.sshd" OR (Filesystem.file_name=".sshd" Filesystem.file_path="/tmp/*") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath =~ "/tmp/.sshd"
   or (FileName startswith "." and FolderPath startswith "/tmp/" and InitiatingProcessFileName in~ ("curl","wget","sh","bash","dash","node","php","composer"))
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
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

### Article-specific behavioural hunt — Hackers Hide Linux Payload Under SSH-Like Filename During Package Installation

`UC_4_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Hide Linux Payload Under SSH-Like Filename During Package Installation ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/.sshd*" OR Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Hide Linux Payload Under SSH-Like Filename During Package Installation
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/.sshd") or FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 7 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
