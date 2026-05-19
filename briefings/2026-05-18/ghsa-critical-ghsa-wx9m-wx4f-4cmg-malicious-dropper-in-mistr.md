# [CRIT] [GHSA / CRITICAL] GHSA-wx9m-wx4f-4cmg: Malicious dropper in mistralai 2.4.6 PyPI package

**Source:** GitHub Security Advisories
**Published:** 2026-05-18
**Article:** https://github.com/advisories/GHSA-wx9m-wx4f-4cmg

## Threat Profile

Malicious dropper in mistralai 2.4.6 PyPI package

The `mistralai` PyPI package version `2.4.6` contains a malicious dropper that executes on import on Linux. No `v2.4.6` tag, commit, or release workflow run exists in this repository, the legitimate latest version before the upload was `2.4.5`, and the upload bypassed this repository's normal release pipeline (which uses PyPI Trusted Publishing).

The `mistralai` PyPI project is currently quarantined.

## Affected

- `mistralai==2.4.6` on PyPI.
…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `83.142.209.194`
- **SHA256:** `6dbaa43bf2f3c0d3cddbca74967e952da563fb974c1ef9d4ecbb2e58e41fe81b`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1105** — Ingress Tool Transfer
- **T1195.002** — Compromise Software Supply Chain
- **T1573.002** — Asymmetric Cryptography (-k TLS verify disabled)
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1564.001** — Hide Artifacts: Hidden Files and Directories (/tmp drop)
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Curl download of transformers.pyz from mistralai 2.4.6 dropper C2 IP 83.142.209.194

`UC_6_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=curl Processes.process="*83.142.209.194*" Processes.process="*transformers.pyz*" by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "curl"
| where ProcessCommandLine has "83.142.209.194"
   and ProcessCommandLine has "transformers.pyz"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Python interpreter executing /tmp/transformers.pyz (mistralai 2.4.6 second stage)

`UC_6_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*/tmp/transformers.pyz*" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "/tmp/transformers.pyz"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Outbound connection to mistralai 2.4.6 dropper C2 IP 83.142.209.194

`UC_6_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime sum(All_Traffic.bytes_in) as bytes_in sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="83.142.209.194" by All_Traffic.src All_Traffic.user All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "83.142.209.194"
| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] Malicious mistralai 2.4.6 sdist on disk by SHA256

`UC_6_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash="6dbaa43bf2f3c0d3cddbca74967e952da563fb974c1ef9d4ecbb2e58e41fe81b" by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "6dbaa43bf2f3c0d3cddbca74967e952da563fb974c1ef9d4ecbb2e58e41fe81b"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, FileOriginUrl
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-wx9m-wx4f-4cmg: Malicious dropper in mistralai 2.4.6 PyPI

`UC_6_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-wx9m-wx4f-4cmg: Malicious dropper in mistralai 2.4.6 PyPI ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("setup.py","__init__.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/transformers.pyz*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("setup.py","__init__.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-wx9m-wx4f-4cmg: Malicious dropper in mistralai 2.4.6 PyPI
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("setup.py", "__init__.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/transformers.pyz", "/dev/null") or FileName in~ ("setup.py", "__init__.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `83.142.209.194`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `6dbaa43bf2f3c0d3cddbca74967e952da563fb974c1ef9d4ecbb2e58e41fe81b`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
