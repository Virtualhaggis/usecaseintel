# [CRIT] Introducing Secure Registry: install-time defense for the npm supply chain

**Source:** StepSecurity
**Published:** 2026-05-19
**Article:** https://www.stepsecurity.io/blog/introducing-secure-registry-install-time-defense-for-the-npm-supply-chain

## Threat Profile

Back to Blog Product Introducing Secure Registry: install-time defense for the npm supply chain Introducing Secure Registry by StepSecurity: install-time defense for the npm supply chain. Block malicious packages, enforce package cooldowns, and protect CI/CD pipelines, developer machines, and artifact managers from modern software supply chain attacks. Sai Likhith View LinkedIn May 12, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading n…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45321`
- **IPv4 (defanged):** `83.142.209.194`
- **Domain (defanged):** `git-tanstack.com`
- **Domain (defanged):** `api.masscan.cloud`
- **SHA256:** `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
- **SHA256:** `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- **SHA256:** `2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df`
- **SHA256:** `1e8538c6e0563d50da0f2e097e979ebd5294ce1defe01d0b9fe361ba3bed1898`
- **SHA1:** `e7d582b98ca80690883175470e96f703ef6dc497`
- **SHA1:** `12f35b1081b17d21815b35feb57ab03d02482116`
- **SHA1:** `820fa07a7328b6cf2b417078e103721d4d8f2e79`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1567.002** — Exfiltration to Cloud Storage / Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] npm/node postinstall spawning network egress tool or referencing Shai-Hulud payload strings

`UC_133_4` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","npm.cmd","npx.cmd","yarn.cmd","pnpm.cmd","node","npm","npx") AND (Processes.process_name IN ("curl.exe","wget.exe","gh.exe","curl","wget","gh") OR Processes.process="*trufflehog*" OR Processes.process="*bundle.js*" OR Processes.process="*git-tanstack.com*" OR Processes.process="*webhook.site*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("node.exe","node","npm.cmd","npm","npx.cmd","npx","yarn","pnpm")
| where (FileName has_any ("curl.exe","curl","wget.exe","wget","gh.exe","gh")
     or ProcessCommandLine has_any ("trufflehog","bundle.js","git-tanstack.com","webhook.site"))
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] TruffleHog secret scanner spawned by npm/node during package install (Mini Shai-Hulud credential harvest)

`UC_133_5` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*trufflehog*" AND Processes.parent_process_name IN ("node.exe","npm.cmd","npx.cmd","node","npm","npx","yarn.cmd","pnpm.cmd","sh","bash") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has "trufflehog" or ProcessCommandLine has "trufflehog"
| where InitiatingProcessFileName has_any ("node.exe","node","npm.cmd","npm","npx.cmd","npx","yarn","pnpm","sh","bash")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] Outbound connection/DNS to Mini Shai-Hulud exfil domain git-tanstack.com

`UC_133_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*git-tanstack.com*" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "git-tanstack.com"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] Mini Shai-Hulud persistence: shai-hulud-workflow.yml / shai-hulud GitHub Actions workflow dropped on disk

`UC_133_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("shai-hulud-workflow.yml","shai-hulud.yaml","shai-hulud.yml") OR Filesystem.file_path="*shai-hulud*") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName has_any ("shai-hulud-workflow.yml","shai-hulud.yaml","shai-hulud.yml") or FolderPath has "shai-hulud"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA256
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-45321`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `83.142.209.194`, `git-tanstack.com`, `api.masscan.cloud`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`, `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`, `2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df`, `1e8538c6e0563d50da0f2e097e979ebd5294ce1defe01d0b9fe361ba3bed1898`, `e7d582b98ca80690883175470e96f703ef6dc497`, `12f35b1081b17d21815b35feb57ab03d02482116`, `820fa07a7328b6cf2b417078e103721d4d8f2e79`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
