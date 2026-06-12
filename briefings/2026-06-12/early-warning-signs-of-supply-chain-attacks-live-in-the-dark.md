# [CRIT] Early Warning Signs of Supply-Chain Attacks Live in the Dark Web

**Source:** BleepingComputer
**Published:** 2026-06-12
**Article:** https://www.bleepingcomputer.com/news/security/early-warning-signs-of-supply-chain-attacks-live-in-the-dark-web/

## Threat Profile

Early Warning Signs of Supply-Chain Attacks Live in the Dark Web 
Sponsored by Flare 
June 12, 2026
10:01 AM
0 


Supply-chain attacks are usually discussed after they become visible: a malicious package, a compromised software update, a malicious extension, or a breach involving a trusted vendor. But before an incident reaches that stage, the early warning signs may look much less obvious.


In underground forums and marketplaces, supply-chain relevance does not always appear under a clear …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33634`
- **CVE:** `CVE-2026-48027`
- **Domain (defanged):** `scan.aquasecurtiy.org`
- **Domain (defanged):** `checkmarx.zone`
- **Domain (defanged):** `models.litellm.cloud`
- **Domain (defanged):** `git-tanstack.com`
- **Domain (defanged):** `t.m-kosche.com`
- **Domain (defanged):** `check.git-service.com`
- **Domain (defanged):** `nsa.cat`
- **SHA256:** `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`
- **SHA256:** `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`
- **SHA256:** `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068`
- **SHA256:** `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd`
- **SHA256:** `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059** — Command and Scripting Interpreter
- **T1552.001** — Credentials In Files
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound network to TeamPCP / Shai-Hulud / LiteLLM supply-chain C2 domains

`UC_3_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("scan.aquasecurtiy.org","checkmarx.zone","models.litellm.cloud","git-tanstack.com","t.m-kosche.com","check.git-service.com","nsa.cat") by All_Traffic.src host All_Traffic.dest All_Traffic.user | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let badDomains = dynamic(["scan.aquasecurtiy.org","checkmarx.zone","models.litellm.cloud","git-tanstack.com","t.m-kosche.com","check.git-service.com","nsa.cat"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (badDomains)
   or tostring(parse_url(strcat("http://", tostring(RemoteUrl)))["Host"]) in~ (badDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### Known TeamPCP / Shai-Hulud payload SHA256 observed on disk or executing

`UC_3_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_hash IN ("46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09","62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0","f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068","cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd","a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a") by Processes.dest Processes.user Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let badHashes = dynamic(["46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09","62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0","f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068","cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd","a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"]);
union isfuzzy=true
(DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA256 in~ (badHashes) or InitiatingProcessSHA256 in~ (badHashes)
  | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessSHA256),
(DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA256 in~ (badHashes)
  | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath, SHA256, ActionType)
| order by Timestamp desc
```

### npm/pip install lifecycle script spawning credential / token harvest

`UC_3_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("npm.exe","npm-cli.js","node.exe","yarn.exe","pnpm.exe","pip.exe","pip3.exe","pip3","poetry.exe","poetry") AND Processes.process_name IN ("node.exe","python.exe","python3.exe","sh","bash","cmd.exe","powershell.exe","curl.exe","wget.exe") AND (Processes.process="*GITHUB_TOKEN*" OR Processes.process="*NPM_TOKEN*" OR Processes.process="*PYPI_TOKEN*" OR Processes.process="*AWS_ACCESS_KEY*" OR Processes.process="*.npmrc*" OR Processes.process="*.pypirc*" OR Processes.process="*.aws/credentials*" OR Processes.process="*.git-credentials*" OR Processes.process="*id_rsa*" OR Processes.process="*preinstall*" OR Processes.process="*postinstall*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("npm.exe","npm","node.exe","node","yarn.exe","yarn","pnpm.exe","pnpm","pip.exe","pip","pip3.exe","pip3","poetry.exe","poetry")
   or InitiatingProcessCommandLine has_any ("npm install","npm ci","yarn install","pnpm install","pip install","poetry install")
| where FileName in~ ("node.exe","python.exe","python3.exe","sh.exe","bash.exe","cmd.exe","powershell.exe","pwsh.exe","curl.exe","wget.exe")
| where ProcessCommandLine has_any ("GITHUB_TOKEN","GH_TOKEN","NPM_TOKEN","PYPI_TOKEN","HF_TOKEN","OPENAI_API_KEY","ANTHROPIC_API_KEY","AWS_ACCESS_KEY","AWS_SECRET","GOOGLE_APPLICATION_CREDENTIALS",".npmrc",".pypirc",".aws/credentials",".git-credentials","id_rsa","id_ed25519","preinstall","postinstall","prepublish")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### VS Code extension host (Code.exe) child process reaching attacker C2

`UC_3_10` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process_name IN ("Code.exe","code","code-server","Cursor.exe","cursor","node.exe") OR All_Traffic.parent_process_name IN ("Code.exe","code","code-server","Cursor.exe","cursor")) AND All_Traffic.dest IN ("scan.aquasecurtiy.org","checkmarx.zone","models.litellm.cloud","git-tanstack.com","t.m-kosche.com","check.git-service.com","nsa.cat") by All_Traffic.src host All_Traffic.user All_Traffic.dest All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let badDomains = dynamic(["scan.aquasecurtiy.org","checkmarx.zone","models.litellm.cloud","git-tanstack.com","t.m-kosche.com","check.git-service.com","nsa.cat"]);
let codeHosts = dynamic(["code.exe","code","code-server","cursor.exe","cursor","codium.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ (codeHosts)
   or InitiatingProcessParentFileName in~ (codeHosts)
   or (InitiatingProcessFileName in~ ("node.exe","node") and InitiatingProcessParentFileName in~ (codeHosts))
| where RemoteUrl has_any (badDomains) or tostring(parse_url(strcat("http://", tostring(RemoteUrl)))["Host"]) in~ (badDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33634`, `CVE-2026-48027`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `scan.aquasecurtiy.org`, `checkmarx.zone`, `models.litellm.cloud`, `git-tanstack.com`, `t.m-kosche.com`, `check.git-service.com`, `nsa.cat`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`, `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`, `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068`, `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd`, `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 11 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
