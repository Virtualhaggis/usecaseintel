# [CRIT] Malicious Polymarket Bot Hides in Hijacked dev-protocol GitHub Org and Steals Wallet Keys

**Source:** StepSecurity
**Published:** 2026-03-26
**Article:** https://www.stepsecurity.io/blog/malicious-polymarket-bot-hides-in-hijacked-dev-protocol-github-org-and-steals-wallet-keys

## Threat Profile

Back to Blog Threat Intel Malicious Polymarket Bot Hides in Hijacked dev-protocol GitHub Org and Steals Wallet Keys The StepSecurity threat intelligence team discovered that dev-protocol — a verified GitHub organization with 568 followers belonging to a legitimate Japanese DeFi project — has been hijacked and is now being used to distribute malicious Polymarket trading bots. Varun Sharma View LinkedIn March 15, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
T…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `cloudflareguard.vercel.app`
- **Domain (defanged):** `cloudflareinsights.vercel.app`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1567** — Exfiltration Over Web Service
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1546.016** — Event Triggered Execution: Installer Packages
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1562.004** — Impair Defenses: Disable or Modify System Firewall
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1608.001** — Stage Capabilities: Upload Malware

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] C2 beaconing to Vercel-hosted Cloudflare-impersonating domains (cloudflareguard / cloudflareinsights)

`UC_328_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as http_method from datamodel=Web where Web.url IN ("*cloudflareguard.vercel.app*","*cloudflareinsights.vercel.app*") OR Web.dest IN ("cloudflareguard.vercel.app","cloudflareinsights.vercel.app") by Web.src Web.dest Web.user | `drop_dm_object_name(Web)` | appendpipe [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where Network_Resolution.DNS.query IN ("cloudflareguard.vercel.app","cloudflareinsights.vercel.app","*.cloudflareguard.vercel.app","*.cloudflareinsights.vercel.app") by Network_Resolution.DNS.src Network_Resolution.DNS.query | `drop_dm_object_name("Network_Resolution.DNS")`] | appendpipe [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where Network_Traffic.All_Traffic.dest_host IN ("cloudflareguard.vercel.app","cloudflareinsights.vercel.app") OR Network_Traffic.All_Traffic.app IN ("cloudflareguard.vercel.app","cloudflareinsights.vercel.app") by Network_Traffic.All_Traffic.src Network_Traffic.All_Traffic.dest_host | `drop_dm_object_name("Network_Traffic.All_Traffic")`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let C2Domains = dynamic(["cloudflareguard.vercel.app","cloudflareinsights.vercel.app"]);
let C2UriPaths = dynamic(["/api/scan-patterns","/api/block-patterns","/api/v1"]);
union isfuzzy=true
(
  DeviceNetworkEvents
  | where Timestamp > ago(7d)
  | where RemoteUrl has_any (C2Domains)
     or (RemoteUrl has_any (C2UriPaths) and RemoteUrl has ".vercel.app")
  | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort, ActionType
),
(
  DeviceEvents
  | where Timestamp > ago(7d)
  | where ActionType == "DnsQueryResponse"
  | extend Q = tostring(parse_json(AdditionalFields).QueryName)
  | where Q has_any (C2Domains)
  | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, Q
)
| order by Timestamp desc
```

### [LLM] npm postinstall SSH-backdoor chain: node spawning sudo ufw allow 22/tcp + chown ~/.ssh

`UC_328_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.process_path) as path values(Processes.parent_process) as parent_cmd values(Processes.parent_process_name) as parent_name from datamodel=Endpoint.Processes where Processes.os IN ("Linux","macOS") AND (
  (Processes.process_name IN ("ufw","sudo") AND Processes.process="*ufw*allow*22*")
  OR (Processes.process_name IN ("chown","sudo") AND Processes.process="*chown*" AND Processes.process IN ("*/.ssh*","*/home/*/.ssh*"))
  OR (Processes.process_name IN ("ufw","sudo") AND Processes.process="*ufw*enable*")
) AND (Processes.parent_process_name IN ("node","sh","bash","npm","sudo") OR Processes.parent_process IN ("*node*test.js*","*lint-builder*","*node_modules*")) by host Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | where match(parent_cmd,"(?i)(node|lint-builder|node_modules|test\.js)") OR match(parent_name,"(?i)^(node|sh|bash|sudo|npm)$")
```

**Defender KQL:**
```kql
let SuspectChildCmd = dynamic(["ufw allow 22","ufw allow 22/tcp","ufw enable"]);
let SshChownTokens = dynamic(["/.ssh","/home/runner/.ssh","authorized_keys"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (ProcessCommandLine has_any (SuspectChildCmd))
    or (ProcessCommandLine has "chown" and ProcessCommandLine has_any (SshChownTokens) and ProcessCommandLine has "-R")
| where InitiatingProcessFileName in~ ("node","sh","bash","sudo","npm","dash")
    or InitiatingProcessCommandLine has_any ("node test.js","lint-builder","node_modules")
    or InitiatingProcessParentFileName =~ "node"
    or InitiatingProcessFolderPath has "node_modules"
| project Timestamp, DeviceName, AccountName,
          ChildFile = FileName, ChildCmd = ProcessCommandLine,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine, ParentPath = InitiatingProcessFolderPath,
          GrandparentFile = InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Malicious typosquat npm packages installed on disk (ts-bign / big-nunber / levex-refa / lint-builder)

`UC_328_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*node_modules/ts-bign/*","*node_modules/big-nunber/*","*node_modules/levex-refa/*","*node_modules/lint-builder/*","*\\node_modules\\ts-bign\\*","*\\node_modules\\big-nunber\\*","*\\node_modules\\levex-refa\\*","*\\node_modules\\lint-builder\\*") by host Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MaliciousPkgs = dynamic(["ts-bign","big-nunber","levex-refa","lint-builder"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has "node_modules"
| where FolderPath has_any (MaliciousPkgs)
| extend PkgName = case(
    FolderPath has "node_modules/ts-bign" or FolderPath has @"node_modules\ts-bign", "ts-bign",
    FolderPath has "node_modules/big-nunber" or FolderPath has @"node_modules\big-nunber", "big-nunber",
    FolderPath has "node_modules/levex-refa" or FolderPath has @"node_modules\levex-refa", "levex-refa",
    FolderPath has "node_modules/lint-builder" or FolderPath has @"node_modules\lint-builder", "lint-builder",
    "other")
| where PkgName != "other"
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            FileCount = count(), Samples = make_set(FileName, 10),
            CreatingProcess = make_set(InitiatingProcessFileName, 5),
            CreatingCmd = make_set(InitiatingProcessCommandLine, 5)
            by DeviceName, PkgName
| order by FirstSeen desc
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

### Article-specific behavioural hunt — Malicious Polymarket Bot Hides in Hijacked dev-protocol GitHub Org and Steals Wa

`UC_328_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Malicious Polymarket Bot Hides in Hijacked dev-protocol GitHub Org and Steals Wa ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("big.js","bignumber.js","test.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/home/runner/.ssh*" OR Filesystem.file_path="*/usr/sbin/ufw*" OR Filesystem.file_name IN ("big.js","bignumber.js","test.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Malicious Polymarket Bot Hides in Hijacked dev-protocol GitHub Org and Steals Wa
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("big.js", "bignumber.js", "test.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/home/runner/.ssh", "/usr/sbin/ufw") or FileName in~ ("big.js", "bignumber.js", "test.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `cloudflareguard.vercel.app`, `cloudflareinsights.vercel.app`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
