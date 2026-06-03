# [HIGH] Legitimate-Looking Codex Remote UI Secretly Steals Your AI Tokens

**Source:** Aikido
**Published:** 2026-05-27
**Article:** https://www.aikido.dev/blog/codex-remote-ui-steals-ai-tokens

## Threat Profile

Blog Vulnerabilities & Threats Legitimate-Looking Codex Remote UI Secretly Steals Your AI Tokens Legitimate-Looking Codex Remote UI Secretly Steals Your AI Tokens Written by Charlie Eriksen Published on: May 27, 2026 There's a new playbook in the supply chain threat landscape, where an someone builds something genuinely useful, growing a real user base. But all while stealing credentials.
codexui-android is a remote web UI for OpenAI Codex. Real GitHub repo. Active development. Polished enough t…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `sentry.anyclaw.store`
- **Domain (defanged):** `anyclaw.store`
- **Domain (defanged):** `gyx.com`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1567** — Exfiltration Over Web Service
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1083** — File and Directory Discovery
- **T1041** — Exfiltration Over C2 Channel
- **T1573** — Encrypted Channel
- **T1474.003** — Supply Chain Compromise: Compromise Hardware Supply Chain (Mobile)
- **T1456** — Drive-By Compromise (Mobile)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] DNS/HTTPS exfil to sentry.anyclaw.store (Codex token C2 masquerading as Sentry)

`UC_112_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.app) as proc values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest in ("sentry.anyclaw.store","anyclaw.store") OR All_Traffic.dest_host="sentry.anyclaw.store" OR All_Traffic.url="*anyclaw.store/startlog*" by All_Traffic.dest All_Traffic.dest_port All_Traffic.http_user_agent | `drop_dm_object_name("All_Traffic")` | where like(http_user_agent,"codexui/%") OR isnull(http_user_agent) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("sentry.anyclaw.store","anyclaw.store") or RemoteUrl endswith ".anyclaw.store"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### [LLM] npm/pnpm install of trojanized codexui-android package on developer endpoint

`UC_112_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.exe","npm-cli.js","pnpm.exe","pnpm","yarn.exe","node.exe") OR Processes.parent_process_name IN ("npm.exe","pnpm.exe","yarn.exe")) (Processes.process="*codexui-android*" OR Processes.process="*chunk-PUR7OUAG.js*") by host Processes.process_name Processes.parent_process_name | `drop_dm_object_name("Processes")` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union isfuzzy=true
  (DeviceProcessEvents
    | where Timestamp > ago(60d)
    | where (InitiatingProcessFileName in~ ("npm.exe","pnpm.exe","yarn.exe","node.exe") or FileName in~ ("npm.exe","pnpm.exe","yarn.exe"))
    | where ProcessCommandLine has "codexui-android" or InitiatingProcessCommandLine has "codexui-android"
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath),
  (DeviceFileEvents
    | where Timestamp > ago(60d)
    | where FolderPath has "codexui-android" or FileName == "chunk-PUR7OUAG.js"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine=InitiatingProcessCommandLine, FolderPath)
| order by Timestamp desc
```

### [LLM] Non-Codex-CLI node process reading ~/.codex/auth.json (Codex OAuth credential theft)

`UC_112_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as proc values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem where (Filesystem.file_name="auth.json" Filesystem.file_path="*\\.codex\\auth.json*" OR Filesystem.file_path="*/.codex/auth.json*") (Filesystem.process_name IN ("node.exe","node") OR Filesystem.process_path="*codexui-android*") by host Filesystem.action | `drop_dm_object_name("Filesystem")` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName == "auth.json"
| where FolderPath has_any ("\\.codex\\","/.codex/")
| where InitiatingProcessFileName in~ ("node.exe","node") or InitiatingProcessFolderPath has "codexui-android" or InitiatingProcessCommandLine has "codexui-android" or InitiatingProcessCommandLine has "chunk-PUR7OUAG.js" or InitiatingProcessCommandLine has "dist-cli/index.js"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FolderPath, FileName, ActionType
| order by Timestamp desc
```

### [LLM] HTTPS POST to /startlog with codexui User-Agent (Codex exfil over the wire)

`UC_112_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.user) as user values(Web.dest) as dest values(Web.http_method) as method from datamodel=Web.Web where Web.url="*/startlog*" Web.http_method="POST" (Web.http_user_agent="codexui/*" OR Web.dest="sentry.anyclaw.store" OR Web.dest="*.anyclaw.store") by Web.url Web.http_user_agent | `drop_dm_object_name("Web")` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "/startlog" or RemoteUrl has "anyclaw.store"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] Android device installed gptos.intelligence.assistant or codex.app (mobile delivery of Codex token stealer)

`UC_112_10` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
index=mdm OR index=intune (app_package_name="gptos.intelligence.assistant" OR app_package_name="codex.app" OR app_package="app.anyclaw.*" OR app_bundle_id="gptos.intelligence.assistant" OR app_bundle_id="codex.app") | stats earliest(_time) as firstSeen latest(_time) as lastSeen values(device_name) as device values(user) as user values(app_version) as version by app_package_name | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
DeviceInfo
| where Timestamp > ago(30d)
| where OSPlatform startswith "Android"
| join kind=inner (
    DeviceTvmSoftwareInventory
    | where SoftwareName in~ ("gptos.intelligence.assistant","codex.app","OpenClaw Codex Claude AI Agent","Codex")
         or SoftwareVendor has "anyclaw"
  ) on DeviceId
| project Timestamp, DeviceId, DeviceName, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion
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

### Article-specific behavioural hunt — Legitimate-Looking Codex Remote UI Secretly Steals Your AI Tokens

`UC_112_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Legitimate-Looking Codex Remote UI Secretly Steals Your AI Tokens ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("pur7ouag.js","node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_path="*/usr/local/lib/node_modules/codexui-android/dist-cli/index.js*" OR Filesystem.file_name IN ("pur7ouag.js","node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Legitimate-Looking Codex Remote UI Secretly Steals Your AI Tokens
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("pur7ouag.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/env", "/usr/local/lib/node_modules/codexui-android/dist-cli/index.js") or FileName in~ ("pur7ouag.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `sentry.anyclaw.store`, `anyclaw.store`, `gyx.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
