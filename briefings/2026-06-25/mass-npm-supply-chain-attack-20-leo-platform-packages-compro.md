# [HIGH] Mass npm Supply Chain Attack: 20 Leo Platform Packages Compromised

**Source:** StepSecurity
**Published:** 2026-06-25
**Article:** https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised

## Threat Profile

Back to Blog Threat Intel Mass npm Supply Chain Attack: 20 Leo Platform Packages Compromised On June 24, 2026, an attacker published malicious versions of 20 npm packages belonging to the Leo Platform ecosystem in a coordinated burst spanning less than three seconds. All 20 packages carry an identical CI/CD attack toolkit that steals secrets from GitHub Actions runners, cloud credential stores, package registries, and password managers, then exfiltrates them via the victim's own GitHub token. To…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `24a0d9e496ec07ca978fab602d5f5e0b39fa03a0`
- **SHA1:** `d45ad3cffbcc7c4b354ebe9d71d002fa585379ec`
- **SHA1:** `1dcc0a39e1cd7293a9058cfc41e1afe8b397c943`
- **SHA1:** `ed9a17d6567101fa4f9f552a4a52cfcca88fa662`
- **SHA1:** `effa8576594fdd59907b5c5c07293ce28a9a3393`
- **SHA1:** `47d73156df1c767bb168c4309fd17b92324d587d`
- **SHA1:** `5e75c14b8acd5752819ab7a10874ddd6389f5238`
- **SHA1:** `809ce3680adfdb8f0746189b68b6b5a6888a960f`
- **SHA1:** `68a1cd589b2ce322f5f03fe7f85dc3f176a759d4`
- **SHA1:** `be3b1f7f1b50f5d53b164a72fb3a9845f4734325`
- **SHA1:** `f03a3e0dca9ef402352ce61cad59e5d850744960`
- **SHA1:** `888094a9b842cfe98e8e24c8f729be1fb6384563`
- **SHA1:** `d7224b6b1f5d2f9403f1cebc8f82518c20b4d0f7`
- **SHA1:** `e973173fb757d2dab9c6424b440dd9f7cbe4f14a`
- **SHA1:** `92221eb202e9f2ac577e5c33658c8a05c6d67556`
- **SHA1:** `be6bb1cf88c46e9e4a6f1a68ed001b77769d58de`
- **SHA1:** `1a5a1445fcd73133f22a0e7895993ac0a42b56da`
- **SHA1:** `a8cb86b78ca56befe90dc466642cb04b98079909`
- **SHA1:** `ef8bf6dd92cbc29ef8d23f3f0fa786ed20a856b1`
- **SHA1:** `9be49287057cd6a54ef4a70a8d541a7259efbd2d`
- **MD5:** `ad9f0ecdbf6075f8cc4ca8bdd62bd27c`
- **MD5:** `54089e0f368fa9a7e2050de9b0db121a`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1105** — Ingress Tool Transfer
- **T1003.007** — OS Credential Dumping: Proc Filesystem
- **T1212** — Exploitation for Credential Access
- **T1548.003** — Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- **T1098** — Account Manipulation
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Bun v1.3.13 runtime pulled from GitHub Releases during npm install (Phantom Gyp staging)

`UC_24_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*oven-sh/bun/releases/download/bun-v1.3.13*" OR Web.url="*bun-v1.3.13*") by Web.src Web.dest Web.url Web.http_user_agent Web.site
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("oven-sh/bun/releases/download/bun-v1.3.13", "bun-v1.3.13")
| where InitiatingProcessFileName in~ ("node","npm","node-gyp","bun","yarn","pnpm")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### GitHub Actions Runner.Worker memory read via /proc/<pid>/mem (CI secret unmasking)

`UC_24_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.Processes.process="*/proc/*" AND Endpoint.Processes.process="*/mem*" by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.process_name Endpoint.Processes.process Endpoint.Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| regex process="/proc/[0-9]+/mem"
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine matches regex @"/proc/[0-9]+/mem"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Passwordless sudo backdoor written for runner account (runner ALL=(ALL) NOPASSWD:ALL)

`UC_24_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.Processes.process="*NOPASSWD:ALL*" AND Endpoint.Processes.process="*runner*" by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.process_name Endpoint.Processes.process Endpoint.Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine contains "NOPASSWD:ALL" and ProcessCommandLine has "runner"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Bun executes dropped temp payload /tmp/p*.js (Miasma stealer launch)

`UC_24_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.Processes.process_name="bun" AND Endpoint.Processes.process="*/tmp/p*.js*" by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.process_name Endpoint.Processes.process Endpoint.Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "bun"
| where ProcessCommandLine matches regex @"/tmp/p[^/ ]*\.js"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
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

### Article-specific behavioural hunt — Mass npm Supply Chain Attack: 20 Leo Platform Packages Compromised

`UC_24_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Mass npm Supply Chain Attack: 20 Leo Platform Packages Compromised ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Mass npm Supply Chain Attack: 20 Leo Platform Packages Compromised
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/null") or FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `24a0d9e496ec07ca978fab602d5f5e0b39fa03a0`, `d45ad3cffbcc7c4b354ebe9d71d002fa585379ec`, `1dcc0a39e1cd7293a9058cfc41e1afe8b397c943`, `ed9a17d6567101fa4f9f552a4a52cfcca88fa662`, `effa8576594fdd59907b5c5c07293ce28a9a3393`, `47d73156df1c767bb168c4309fd17b92324d587d`, `5e75c14b8acd5752819ab7a10874ddd6389f5238`, `809ce3680adfdb8f0746189b68b6b5a6888a960f` _(+14 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
