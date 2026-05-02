# [CRIT] SAP-Related npm Packages Compromised in Credential-Stealing Supply Chain Attack

**Source:** The Hacker News
**Published:** 2026-04-29
**Article:** https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html

## Threat Profile

SAP-Related npm Packages Compromised in Credential-Stealing Supply Chain Attack 
 Ravie Lakshmanan  Apr 29, 2026 Supply Chain Attack / Malware 
Cybersecurity researchers are sounding the alarm about a new supply chain attack campaign targeting SAP-related npm Packages with credential-stealing malware.
According to reports from Aikido Security , Onapsis , OX Security ,  SafeDep , Socket , StepSecurity , and Google-owned Wiz , the campaign – calling itself the Mini  Shai-Hulud – has affected the…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33626`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-3854`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — JavaScript
- **T1546.016** — Installer Packages
- **T1102.002** — Bidirectional Communication: Web Service
- **T1567** — Exfiltration Over Web Service
- **T1102** — Web Service
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Compromised SAP CAP / mbt npm package preinstall dropping setup.mjs (Mini Shai-Hulud)

`UC_44_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","npm.exe","npm-cli.js","yarn.exe","pnpm.exe","bun.exe","corepack.exe") OR Processes.parent_process IN ("*npm*install*","*yarn*add*","*pnpm*install*")) AND (Processes.process IN ("*setup.mjs*","*execution.js*") OR Processes.process IN ("*\\node_modules\\@cap-js\\sqlite*","*\\node_modules\\@cap-js\\postgres*","*\\node_modules\\@cap-js\\db-service*","*\\node_modules\\mbt\\*","*/node_modules/@cap-js/sqlite*","*/node_modules/@cap-js/postgres*","*/node_modules/@cap-js/db-service*","*/node_modules/mbt/*")) by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | append [| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("setup.mjs","execution.js") AND (Filesystem.file_hash IN ("4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34","6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95","eb6eb4154b03ec73218727dc643d26f4e14dfda2438112926bb5daf37ae8bcdb","80a3d2877813968ef847ae73b5eeeb70b9435254e74d7f07d8cf4057f0a710ac","35baf8316645372eea40b91d48acb067")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
let bad_hashes = dynamic(["4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34","6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95","eb6eb4154b03ec73218727dc643d26f4e14dfda2438112926bb5daf37ae8bcdb","80a3d2877813968ef847ae73b5eeeb70b9435254e74d7f07d8cf4057f0a710ac"]);
let bad_md5 = dynamic(["35baf8316645372eea40b91d48acb067"]);
let bad_paths = dynamic(["@cap-js/sqlite","@cap-js/postgres","@cap-js/db-service","/mbt/","\\mbt\\"]);
DeviceProcessEvents
| where (ProcessCommandLine has_any ("setup.mjs","execution.js") and InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe","bun.exe","corepack.exe"))
   or (FolderPath has_any (bad_paths) and FileName in~ ("node.exe","bun.exe"))
   or SHA256 in (bad_hashes) or MD5 in (bad_md5)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| union (DeviceFileEvents | where (FileName in~ ("setup.mjs","execution.js") and FolderPath has_any (bad_paths)) or SHA256 in (bad_hashes) or MD5 in (bad_md5) | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine)
```

### [LLM] Mini Shai-Hulud GitHub commit-search dead-drop C2 ('OhNoWhatsGoingOnWithGitHub')

`UC_44_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*OhNoWhatsGoingOnWithGitHub*" OR Web.url="*api.github.com/search/commits*OhNoWhatsGoingOnWithGitHub*" OR Web.http_user_agent="*Bun/1.3.13*") by Web.src Web.user Web.dest Web.url Web.http_user_agent Web.http_method | `drop_dm_object_name(Web)` | where firstTime != ""
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("OhNoWhatsGoingOnWithGitHub", "api.github.com/search/commits")
| where RemoteUrl has "OhNoWhatsGoingOnWithGitHub"
   or (RemoteUrl has "api.github.com/search/commits" and InitiatingProcessFileName in~ ("bun.exe","node.exe"))
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| union (
DeviceEvents
| where ActionType == "BrowserLaunchedToOpenUrl" or ActionType == "NetworkConnectionEvents"
| where AdditionalFields has "OhNoWhatsGoingOnWithGitHub"
)
```

### [LLM] Bun v1.3.13 runtime fetched from npm/node install context (Mini Shai-Hulud dropper)

`UC_44_9` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*github.com/oven-sh/bun/releases/download/bun-v1.3.13*" by Web.src Web.user Web.url Web.http_user_agent Web.dest | `drop_dm_object_name(Web)` | join type=outer src [| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name="bun.exe" AND (Processes.process IN ("*execution.js*","*\\.claude\\*","*\\.vscode\\setup.mjs*")) by Processes.dest Processes.user Processes.parent_process Processes.process | rename Processes.dest as src | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
let bun_dl =
DeviceNetworkEvents
| where RemoteUrl has "github.com/oven-sh/bun/releases/download/bun-v1.3.13"
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","bun.exe","curl.exe","wget.exe","powershell.exe","pwsh.exe","cmd.exe")
| project NetTime=Timestamp, DeviceName, AccountName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName;
let bun_exec =
DeviceProcessEvents
| where FileName =~ "bun.exe" or ProcessCommandLine matches regex @"(?i)\bbun\b.*(execution\.js|\.claude\\|\.vscode\\setup\.mjs)"
| where ProcessCommandLine has_any ("execution.js",".claude\\",".vscode\\setup.mjs")
| project ExecTime=Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath;
bun_dl
| join kind=inner (bun_exec) on DeviceName
| where datetime_diff('minute', ExecTime, NetTime) between (-30 .. 30)
| project NetTime, ExecTime, DeviceName, AccountName, RemoteUrl, ProcessCommandLine, InitiatingProcessCommandLine
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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
| where FolderPath has_any ("\Google\Chrome\User Data\","\Microsoft\Edge\User Data\","\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — SAP-Related npm Packages Compromised in Credential-Stealing Supply Chain Attack

`UC_44_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — SAP-Related npm Packages Compromised in Credential-Stealing Supply Chain Attack ```
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
      AND (Filesystem.file_name IN ("execution.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — SAP-Related npm Packages Compromised in Credential-Stealing Supply Chain Attack
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
| where (FileName in~ ("execution.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
