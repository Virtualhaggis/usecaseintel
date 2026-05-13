# [CRIT] "A Mini Shai-Hulud Has Appeared": Bun-Based Stealer Hits SAP @cap-js and mbt npm Packages

**Source:** Snyk
**Published:** 2026-04-29
**Article:** https://snyk.io/blog/bun-based-stealer-hits-sap-cap-js-mbt-npm-packages/

## Threat Profile

Snyk Blog In this article
Written by Stephen Thoemmes 
April 29, 2026
0 mins read On April 29, 2026, attackers published malicious versions of four npm packages in the SAP development ecosystem: mbt , @cap-js/db-service , @cap-js/sqlite , and @cap-js/postgres . Each compromised release ships a preinstall hook that downloads the Bun JavaScript runtime from GitHub Releases and uses it to execute an ~11.6 MB obfuscated credential stealer.
The payload tags itself with a hardcoded description, "A Min…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-28353`
- **SHA256:** `4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34`
- **SHA256:** `80a3d2877813968ef847ae73b5eeeb70b9435254e74d7f07d8cf4057f0a710ac`
- **SHA256:** `6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95`
- **SHA256:** `29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7`
- **SHA256:** `5012caa5847ae9261dfa16f91417042f367d6bed149c3b8af7a50b203a093007`
- **SHA256:** `fd4b0f07b27e8f41bc70b8e2b79d168fb3fe80d7e0b37f43c506136a3418b44d`
- **SHA1:** `0af7415d65753f6aede8c9c0f39be478666b9c12`
- **SHA1:** `4b04304f6d51392e3f43856c94ca95800518a694`
- **SHA1:** `7b6a28e92149637e5d7c7f4a2d3e54acd507c929`
- **SHA1:** `e80824a19f48d778a746571bb15279b5679fd61c`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546.016** — Event Triggered Execution: Installer Packages
- **T1105** — Ingress Tool Transfer
- **T1546** — Event Triggered Execution
- **T1554** — Compromise Host Software Binary
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Mini Shai-Hulud npm preinstall chain: node setup.mjs → bun execution.js

`UC_214_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.user) as user from datamodel=Endpoint.Processes where ( (Processes.process_name IN ("node.exe","node") AND Processes.process="*setup.mjs*" AND Processes.parent_process_name IN ("npm.cmd","npm","npm-cli.js","yarn.cmd","yarn","pnpm.cmd","pnpm","node.exe","node")) OR (Processes.process_name IN ("bun.exe","bun") AND Processes.process="*execution.js*") ) by Processes.dest Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.user _time | `drop_dm_object_name(Processes)` | sort - _time
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("node.exe","node") and ProcessCommandLine has "setup.mjs"
         and InitiatingProcessFileName in~ ("npm.cmd","npm","npm-cli.js","yarn.cmd","yarn","pnpm.cmd","pnpm","node.exe","node"))
   or (FileName in~ ("bun.exe","bun") and ProcessCommandLine has "execution.js")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          ChildSHA256 = SHA256,
          ChildPath = FolderPath
| order by Timestamp desc
```

### [LLM] Mini Shai-Hulud payload file drop: setup.mjs/execution.js by hash & size in node_modules

`UC_214_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash values(Filesystem.file_size) as file_size values(Filesystem.process_name) as writer_process from datamodel=Endpoint.Filesystem where ( Filesystem.file_hash IN ("4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34","80a3d2877813968ef847ae73b5eeeb70b9435254e74d7f07d8cf4057f0a710ac","6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95","29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7","5012caa5847ae9261dfa16f91417042f367d6bed149c3b8af7a50b203a093007","fd4b0f07b27e8f41bc70b8e2b79d168fb3fe80d7e0b37f43c506136a3418b44d") OR ( Filesystem.file_name="execution.js" AND Filesystem.file_size=11678349 AND Filesystem.file_path="*node_modules*" ) OR ( Filesystem.file_name="setup.mjs" AND Filesystem.file_path="*node_modules*" AND Filesystem.file_path IN ("*node_modules/mbt/*","*node_modules/@cap-js/*","*node_modules\\mbt\\*","*node_modules\\@cap-js\\*") ) ) by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.file_size Filesystem.process_name _time | `drop_dm_object_name(Filesystem)` | sort - _time
```

**Defender KQL:**
```kql
let _IOC_SHA256 = dynamic([
    "4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34",
    "80a3d2877813968ef847ae73b5eeeb70b9435254e74d7f07d8cf4057f0a710ac",
    "6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95",
    "29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7",
    "5012caa5847ae9261dfa16f91417042f367d6bed149c3b8af7a50b203a093007",
    "fd4b0f07b27e8f41bc70b8e2b79d168fb3fe80d7e0b37f43c506136a3418b44d"
  ]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where SHA256 in (_IOC_SHA256)
   or (FileName =~ "execution.js" and FileSize == 11678349 and FolderPath has "node_modules")
   or (FileName =~ "setup.mjs" and (FolderPath has @"node_modules\mbt" or FolderPath has "node_modules/mbt" or FolderPath has @"node_modules\@cap-js" or FolderPath has "node_modules/@cap-js"))
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, FileSize, SHA256,
          Writer = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          User = InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Mini Shai-Hulud post-compromise persistence artifacts in .claude/, .vscode/, .github/workflows/

`UC_214_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as writer values(Filesystem.process_path) as writer_path from datamodel=Endpoint.Filesystem where ( ( Filesystem.file_name="settings.json" AND Filesystem.file_path="*\.claude\settings.json" ) OR ( Filesystem.file_name="settings.json" AND Filesystem.file_path="*/.claude/settings.json" ) OR ( Filesystem.file_name="tasks.json" AND Filesystem.file_path="*\.vscode\tasks.json" ) OR ( Filesystem.file_name="tasks.json" AND Filesystem.file_path="*/.vscode/tasks.json" ) OR ( Filesystem.file_name="format-check.yml" AND Filesystem.file_path IN ("*\.github\workflows\format-check.yml","*/.github/workflows/format-check.yml") ) ) AND Filesystem.process_name IN ("node.exe","node","bun.exe","bun","python.exe","python","python3","powershell.exe","pwsh.exe") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.user _time | `drop_dm_object_name(Filesystem)` | sort - _time
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has @"\.claude\" and FileName =~ "settings.json")
   or (FolderPath has "/.claude/" and FileName =~ "settings.json")
   or (FolderPath has @"\.vscode\" and FileName =~ "tasks.json")
   or (FolderPath has "/.vscode/" and FileName =~ "tasks.json")
   or (FolderPath has @"\.github\workflows" and FileName =~ "format-check.yml")
   or (FolderPath has "/.github/workflows" and FileName =~ "format-check.yml")
| where InitiatingProcessFileName in~ ("node.exe","node","bun.exe","bun","python.exe","python","python3","powershell.exe","pwsh.exe")
| where InitiatingProcessAccountName !endswith "$"
| extend ArtifactKind = case(
      FileName =~ "settings.json" and FolderPath has ".claude", "claude_sessionstart_hook",
      FileName =~ "tasks.json" and FolderPath has ".vscode", "vscode_folderopen_task",
      FileName =~ "format-check.yml", "github_workflow_secret_dump",
      "unknown")
| project Timestamp, DeviceName, ActionType, ArtifactKind, FolderPath, FileName, SHA256,
          Writer = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          User = InitiatingProcessAccountName
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

### Article-specific behavioural hunt — "A Mini Shai-Hulud Has Appeared": Bun-Based Stealer Hits SAP @cap-js and mbt npm

`UC_214_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — "A Mini Shai-Hulud Has Appeared": Bun-Based Stealer Hits SAP @cap-js and mbt npm ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("execution.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/null*" OR Filesystem.file_path="*/etc/ssh/*" OR Filesystem.file_name IN ("execution.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — "A Mini Shai-Hulud Has Appeared": Bun-Based Stealer Hits SAP @cap-js and mbt npm
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("execution.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/null", "/etc/ssh/") or FileName in~ ("execution.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-28353`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34`, `80a3d2877813968ef847ae73b5eeeb70b9435254e74d7f07d8cf4057f0a710ac`, `6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95`, `29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7`, `5012caa5847ae9261dfa16f91417042f367d6bed149c3b8af7a50b203a093007`, `fd4b0f07b27e8f41bc70b8e2b79d168fb3fe80d7e0b37f43c506136a3418b44d`, `0af7415d65753f6aede8c9c0f39be478666b9c12`, `4b04304f6d51392e3f43856c94ca95800518a694` _(+2 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 11 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
