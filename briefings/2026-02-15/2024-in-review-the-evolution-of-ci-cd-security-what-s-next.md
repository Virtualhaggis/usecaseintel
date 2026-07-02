# [HIGH] 2024 in Review: The Evolution of CI/CD Security & What's Next

**Source:** StepSecurity
**Published:** 2026-02-15
**Article:** https://www.stepsecurity.io/blog/2024-in-review-the-evolution-of-ci-cd-security-whats-next

## Threat Profile

Back to Blog Resources 2024 in Review: The Evolution of CI/CD Security & What's Next How StepSecurity achieved 5X ARR growth while securing over 5,000 open-source repositories in 2024 Varun Sharma View LinkedIn December 30, 2024
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Introduction As 2024 comes to a close, we've been reflecting on the state of CI/CD security—an area that continues to face growing challenges and opportunitie…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-3094`
- **SHA256:** `319feb5a9cddd81955d915b5632b4a5f8f9080281fb46e2f6d69d53f693c23ae`
- **SHA256:** `605861f833fc181c7cdcabd5577ddb8989bea332648a8f498b4eef89b8f85ad4`
- **SHA256:** `8fa641c454c3e0f76de73b7cc3446096b9c8b9d33d406d38b8ac76090b0344fd`
- **SHA256:** `b418bfd34aa246b2e7b5cb5d263a640e5d080810f767370c4d2c24662a274963`
- **SHA256:** `cbeef92e67bf41ca9c015557d81f39adaba67ca9fb3574139754999030b83537`
- **SHA256:** `5448850cdc3a7ae41ff53b433c2adbd0ff492515012412ee63a40d2685db3049`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1140** — Deobfuscate/Decode Files or Information
- **T1496** — Resource Hijacking
- **T1195.001** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### XZ Utils (CVE-2024-3094) build-time backdoor extraction from disguised test corpus

`UC_577_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*build-to-host.m4*" OR Processes.process="*bad-3-corrupt_lzma2.xz*" OR Processes.process="*good-large_compressed.lzma*" OR Processes.process="*[[:alnum:]]{5}*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine contains "build-to-host.m4"
    or ProcessCommandLine contains "bad-3-corrupt_lzma2.xz"
    or ProcessCommandLine contains "good-large_compressed.lzma"
    or ProcessCommandLine contains "[[:alnum:]]{5}"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Ultralytics PyPI supply-chain XMRig coinminer execution from /tmp/ultralytics_runner

`UC_577_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_path="/tmp/ultralytics_runner" OR Processes.process="*/tmp/ultralytics_runner*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath =~ "/tmp/ultralytics_runner"
    or ProcessCommandLine contains "/tmp/ultralytics_runner"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### Ultralytics coinminer C2 — Stratum to connect.consrensys.com:8080 mining pool

`UC_577_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="connect.consrensys.com" OR DNS.query="*.consrensys.com") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl =~ "connect.consrensys.com" or RemoteUrl endswith ".consrensys.com"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
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
  - CVE(s): `CVE-2024-3094`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `319feb5a9cddd81955d915b5632b4a5f8f9080281fb46e2f6d69d53f693c23ae`, `605861f833fc181c7cdcabd5577ddb8989bea332648a8f498b4eef89b8f85ad4`, `8fa641c454c3e0f76de73b7cc3446096b9c8b9d33d406d38b8ac76090b0344fd`, `b418bfd34aa246b2e7b5cb5d263a640e5d080810f767370c4d2c24662a274963`, `cbeef92e67bf41ca9c015557d81f39adaba67ca9fb3574139754999030b83537`, `5448850cdc3a7ae41ff53b433c2adbd0ff492515012412ee63a40d2685db3049`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
