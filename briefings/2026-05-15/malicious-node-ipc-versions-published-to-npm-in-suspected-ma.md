# [CRIT] Malicious node-ipc versions published to npm in suspected maintainer account compromise

**Source:** Snyk
**Published:** 2026-05-15
**Article:** https://snyk.io/blog/malicious-node-ipc-versions-published-npm/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
May 15, 2026
0 mins read On May 14, 2026, multiple malicious versions of the popular npm package node-ipc were published to the npm registry. Current public reporting identifies node-ipc@9.1.6 , node-ipc@9.2.3 , and node-ipc@12.0.1 as compromised versions containing an obfuscated credential-stealing payload. The malicious code was added to the CommonJS bundle, node-ipc.cjs, and is triggered when the package is loaded through require("node-ipc")…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `37.16.75.69`
- **Domain (defanged):** `azurestaticprovider.net`
- **Domain (defanged):** `sh.azurestaticprovider.net`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1568** — Dynamic Resolution
- **T1041** — Exfiltration Over C2 Channel
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1555** — Credentials from Password Stores
- **T1083** — File and Directory Discovery
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1480** — Execution Guardrails
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1074.001** — Local Data Staging

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] node-ipc stealer C2/exfil to azurestaticprovider[.]net or 37.16.75.69

`UC_32_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.app) as process values(All_Traffic.url) as url from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="37.16.75.69" OR All_Traffic.dest IN ("*azurestaticprovider.net","sh.azurestaticprovider.net") OR All_Traffic.url IN ("*azurestaticprovider.net*")) by All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.src_ip | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src from datamodel=Network_Resolution.DNS where DNS.query IN ("*azurestaticprovider.net","sh.azurestaticprovider.net") by DNS.query DNS.record_type | `drop_dm_object_name(DNS)`]
```

**Defender KQL:**
```kql
let _c2_domains = dynamic(["azurestaticprovider.net","sh.azurestaticprovider.net"]);
let _c2_ips = dynamic(["37.16.75.69"]);
union isfuzzy=true
  (DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP in (_c2_ips)
       or RemoteUrl has_any (_c2_domains)
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName, RemoteIP, RemoteUrl, RemotePort, Protocol,
              Signal="NetworkEvent"),
  (DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Query = tostring(parse_json(AdditionalFields).QueryName)
    | where Query has "azurestaticprovider.net"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName, RemoteIP="", RemoteUrl=Query, RemotePort=int(53), Protocol="Udp",
              Signal="DnsQuery")
| order by Timestamp desc
```

### [LLM] Node process bulk read of developer credential files (90+ category stealer harvest)

`UC_32_5` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true dc(Filesystem.file_path) as cred_files_touched values(Filesystem.file_path) as files min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("node.exe","node") AND (Filesystem.file_path IN ("*\\.ssh\\id_rsa*","*\\.ssh\\id_ed25519*","*\\.aws\\credentials*","*\\.aws\\config*","*\\.kube\\config*","*\\.config\\gh\\hosts.yml*","*\\.config\\gcloud\\*","*terraform.tfstate*","*\\.docker\\config.json*","*\\.npmrc*","*\\.netrc*","*\\.env","*\\.bash_history","*\\.zsh_history","*\\.cursor*","*\\.claude*","*\\.aider*") OR Filesystem.file_name IN ("id_rsa","id_ed25519","credentials","kubeconfig","config.json","terraform.tfstate","hosts.yml",".bash_history",".zsh_history",".env",".npmrc",".netrc")) by Filesystem.dest Filesystem.process_id Filesystem.user _time span=5m | `drop_dm_object_name(Filesystem)` | where cred_files_touched >= 5 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _cred_paths = dynamic([
  @"\.ssh\id_rsa", @"\.ssh\id_ed25519", @"\.aws\credentials", @"\.aws\config",
  @"\.kube\config", @"\.config\gh\hosts.yml", @"\.config\gcloud",
  @"terraform.tfstate", @"\.docker\config.json", @"\.npmrc", @"\.netrc",
  @"\.bash_history", @"\.zsh_history", @"\.cursor", @"\.claude", @"\.aider"]);
let _cred_names = dynamic([
  "id_rsa","id_ed25519","credentials","kubeconfig","config.json",
  "terraform.tfstate","hosts.yml",".bash_history",".zsh_history",
  ".env",".npmrc",".netrc"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where ActionType in ("FileAccessed","FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (_cred_paths)
   or FileName in~ (_cred_names)
   or FileName endswith ".pem" or FileName endswith ".env"
| summarize CredFileCount = dcount(strcat(FolderPath, "\\", FileName)),
            SampleFiles = make_set(strcat(FolderPath, "\\", FileName), 25),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, InitiatingProcessId, InitiatingProcessCommandLine,
               InitiatingProcessAccountName, bin(Timestamp, 5m)
| where CredFileCount >= 5     // 5+ distinct credential files touched by one node PID in 5m = stealer fan-out
| order by LastSeen desc
```

### [LLM] node-ipc stealer execution markers: __ntw=1 env flag and $TMPDIR/nt-* staging directory

`UC_32_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where ((Processes.process_name IN ("node.exe","node") OR Processes.parent_process_name IN ("node.exe","node")) AND (Processes.process="*__ntw=1*" OR Processes.parent_process="*__ntw=1*")) by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats summariesonly=true count values(Filesystem.file_path) as paths min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("node.exe","node") AND (Filesystem.file_path IN ("*/nt-*","*\\nt-*") OR Filesystem.file_name="nt-*") by Filesystem.dest Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
union isfuzzy=true
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("node.exe","node")
       or InitiatingProcessFileName in~ ("node.exe","node")
    | where ProcessCommandLine has "__ntw=1" or InitiatingProcessCommandLine has "__ntw=1"
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine, Signal="ntw_env_marker"),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("node.exe","node")
    | where ActionType in ("FileCreated","FileModified","FileRenamed")
    | where FolderPath matches regex @"(?i)(?:[\\/])nt-[a-z0-9]{4,}(?:[\\/])"
       or FileName startswith "nt-"
    | project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName, AccountName="", ProcessCommandLine="",
              Signal="nt_staging_dir")
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

### Article-specific behavioural hunt — Malicious node-ipc versions published to npm in suspected maintainer account com

`UC_32_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Malicious node-ipc versions published to npm in suspected maintainer account com ```
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
      AND (Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Malicious node-ipc versions published to npm in suspected maintainer account com
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
| where (FolderPath has_any ("/dev/null") or FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `37.16.75.69`, `azurestaticprovider.net`, `sh.azurestaticprovider.net`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 7 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
