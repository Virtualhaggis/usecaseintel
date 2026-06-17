# [HIGH] 144 Mastra npm Packages Compromised via Hijacked Contributor Account

**Source:** The Hacker News, Cyber Security News, Aikido, StepSecurity
**Published:** 2026-06-17
**Article:** https://thehackernews.com/2026/06/144-mastra-npm-packages-compromised-via.html

## Threat Profile

Back to Blog Threat Intel @mastra npm Packages Compromised On 2026-06-17, an attacker with access to the @mastra npm organization published malicious new versions of 13 packages across the Mastra AI framework ecosystem. Each infected package adds easy-day-js — a newly created typosquat of the popular dayjs date library — as a production dependency. The easy-day-js@1.11.22 package contains a postinstall hook that runs a heavily obfuscated setup.cjs file, which downloads and executes a second-stag…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `23.254.164.92`
- **IPv4 (defanged):** `23.254.164.123`
- **Domain (defanged):** `hwsrv-1327786.hostwindsdns.com`
- **Domain (defanged):** `hwsrv-1327785.hostwindsdns.com`
- **SHA256:** `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf`
- **SHA256:** `4a8860240e4231c3a74c81949be655a28e096a7d72f38fbe84e5b37636b98417`
- **SHA256:** `ae70dd4f6bc0d1c8c2848e4e6b51934626c4818dcb5af99d080ddbd7dc337185`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546.016** — Event Triggered Execution: Installer Packages
- **T1195.002** — Compromise Software Supply Chain
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1571** — Non-Standard Port
- **T1041** — Exfiltration Over C2 Channel
- **T1564.003** — Hidden Window
- **T1199** — Trusted Relationship
- **T1083** — File and Directory Discovery
- **T1005** — Data from Local System
- **T1552.001** — Unsecured Credentials: Credentials in Files
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### easy-day-js postinstall hook running node setup.cjs --no-warnings

`UC_17_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image values(Processes.parent_process_name) as parent values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where (Processes.process_name=node.exe OR Processes.process_name=node) Processes.process="*setup.cjs*" Processes.process="*--no-warnings*" by Processes.dest Processes.user | `drop_dm_object_name(Processes)` | where parent IN ("npm.exe","npm-cli.js","node.exe","npx.exe","yarn.exe","pnpm.exe","cmd.exe","bash","sh") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe","node")
| where ProcessCommandLine has "setup.cjs" and ProcessCommandLine has "--no-warnings"
| where InitiatingProcessFileName in~ ("npm.exe","npm","npm-cli.js","npx.exe","npx","node.exe","yarn.exe","pnpm.exe","cmd.exe","bash","sh")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Outbound HTTPS to Mastra supply-chain C2 23.254.164.92:8000 and 23.254.164.123:443

`UC_17_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app sum(All_Traffic.bytes_out) as bytes_out sum(All_Traffic.bytes_in) as bytes_in from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("23.254.164.92","23.254.164.123")) (All_Traffic.dest_port IN (8000,443)) by All_Traffic.src All_Traffic.user All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badIPs = dynamic(["23.254.164.92","23.254.164.123"]);
let badDomains = dynamic(["hwsrv-1327786.hostwindsdns.com","hwsrv-1327785.hostwindsdns.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (badIPs)
   or RemoteUrl has_any (badDomains)
   or RemoteUrl has "/update/49890878"
| extend Stage = case(RemoteIP == "23.254.164.92" or RemoteUrl has "hwsrv-1327786", "Stage1-Download",
                     RemoteIP == "23.254.164.123" or RemoteUrl has "hwsrv-1327785", "Stage2-Exfil", "Unknown")
| project Timestamp, DeviceName, Stage, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Node spawning detached script from %TEMP% with 24-hex filename and host:port argv (stage-2)

`UC_17_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where (Processes.process_name=node.exe OR Processes.process_name=node) by Processes.dest Processes.user Processes.process | `drop_dm_object_name(Processes)` | regex process="(?i)(?:[\\\/]Temp[\\\/]|AppData[\\\/]Local[\\\/]Temp[\\\/]|\/tmp\/)[a-f0-9]{24}\.js\s+\S+:\d{2,5}" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe","node")
| where ProcessCommandLine matches regex @"(?i)(?:\\Temp\\|AppData\\Local\\Temp\\|/tmp/)[a-f0-9]{24}\.js\s+\S+:\d{2,5}"
| extend Stage2Target = extract(@"([a-zA-Z0-9\.\-]+:\d{2,5})\s*$", 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, Stage2Target, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### npm install referencing compromised @mastra packages or easy-day-js dependency

`UC_17_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.exe","npm","npx.exe","yarn.exe","pnpm.exe","node.exe")) by Processes.dest Processes.user Processes.process | `drop_dm_object_name(Processes)` | search cmdline="*easy-day-js*" OR cmdline="*@mastra/core*" OR cmdline="*@mastra/deployer*" OR cmdline="*@mastra/server*" OR cmdline="*@mastra/memory*" OR cmdline="*@mastra/schema-compat*" OR cmdline="*@mastra/mcp*" OR cmdline="*@mastra/pg*" OR cmdline="*@mastra/libsql*" OR cmdline="*@mastra/evals*" OR cmdline="*@mastra/datadog*" OR cmdline="*@mastra/rag*" OR cmdline="*@mastra/deployer-vercel*" OR cmdline="*@mastra/redis*" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let compromised = dynamic(["easy-day-js","@mastra/schema-compat","@mastra/core","@mastra/memory","@mastra/server","@mastra/deployer","@mastra/pg","@mastra/mcp","@mastra/libsql","@mastra/evals","@mastra/datadog","@mastra/rag","@mastra/deployer-vercel","@mastra/redis"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm.exe","npm","npx.exe","yarn.exe","pnpm.exe","node.exe") or InitiatingProcessFileName in~ ("npm.exe","npm","npx.exe","yarn.exe","pnpm.exe")
| where ProcessCommandLine has_any (compromised) or InitiatingProcessCommandLine has_any (compromised)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Mastra dropper beacon file .pkg_history/.pkg_logs created by node in temp directory

`UC_17_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.file_path) as path from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN (".pkg_history",".pkg_logs")) Filesystem.action=created by Filesystem.dest Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)` | search path="*\\Temp\\*" OR path="*/tmp/*" OR path="*AppData\\Local\\Temp*" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where FileName in~ (".pkg_history",".pkg_logs")
| where FolderPath has_any (@"\Temp\", "/tmp/", @"AppData\Local\Temp")
| where InitiatingProcessFileName in~ ("node.exe","node")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### node.exe reading developer credential files shortly after npm install (Mastra stage-2)

`UC_17_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where Filesystem.process_name=node.exe (Filesystem.file_path="*\\.aws\\credentials*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*\\.config\\gh\\hosts.yml*" OR Filesystem.file_path="*/.config/gh/hosts.yml*" OR Filesystem.file_path="*\\.ssh\\id_rsa*" OR Filesystem.file_path="*/.ssh/id_rsa*" OR Filesystem.file_path="*Runner.Worker*secret*" OR Filesystem.file_path="*_temp\\_runner_file_commands*") by Filesystem.dest Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CredentialReads = DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where (FolderPath has @"\.aws\" and FileName == "credentials")
    or (FolderPath has "/.aws/" and FileName == "credentials")
    or (FolderPath has @"\.config\gh\" and FileName == "hosts.yml")
    or (FolderPath has "/.config/gh/" and FileName == "hosts.yml")
    or (FolderPath has @"\.ssh\" and FileName matches regex @"^id_(rsa|ed25519|ecdsa)$")
    or (FolderPath has "Runner.Worker" and FolderPath has "_temp")
    or FileName =~ ".npmrc";
let RecentNpmInstall = DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "npm" and ProcessCommandLine has "install"
| project NpmTime = Timestamp, DeviceId, NpmUser = AccountName;
CredentialReads
| join kind=inner RecentNpmInstall on DeviceId
| where Timestamp between (NpmTime .. NpmTime + 10m)
| project Timestamp, DeviceName, NpmTime, DelaySec = datetime_diff('second', Timestamp, NpmTime), InitiatingProcessAccountName, FolderPath, FileName, InitiatingProcessCommandLine
| order by Timestamp desc
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

### Article-specific behavioural hunt — 144 Mastra npm Packages Compromised via Hijacked Contributor Account

`UC_17_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — 144 Mastra npm Packages Compromised via Hijacked Contributor Account ```
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
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — 144 Mastra npm Packages Compromised via Hijacked Contributor Account
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
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `23.254.164.92`, `23.254.164.123`, `hwsrv-1327786.hostwindsdns.com`, `hwsrv-1327785.hostwindsdns.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf`, `4a8860240e4231c3a74c81949be655a28e096a7d72f38fbe84e5b37636b98417`, `ae70dd4f6bc0d1c8c2848e4e6b51934626c4818dcb5af99d080ddbd7dc337185`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
