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
- **T1573.001** — Symmetric Cryptography (TLS verification disabled)
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1106** — Native API (Popen start_new_session)
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1036.005** — Match Legitimate Name or Location (transformers — masquerades as HF library)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] mistralai 2.4.6 dropper: curl downloading transformers.pyz from 83.142.209.194

`UC_239_3` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.parent_process_name) as parent_process_name values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name="curl" (Processes.process="*83.142.209.194*" OR Processes.process="*transformers.pyz*") by Processes.dest Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where (match(parent_process_name, "^python[0-9.]*$") OR like(process, "%-k%-L%-s%")) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "curl"
| where ProcessCommandLine has "83.142.209.194"
     or (ProcessCommandLine has "transformers.pyz" and ProcessCommandLine has "/tmp/")
| extend TlsVerifyDisabled = ProcessCommandLine has " -k" or ProcessCommandLine has "--insecure"
| project Timestamp, DeviceName, AccountName,
          ProcessCommandLine,
          ParentImage = InitiatingProcessFolderPath,
          ParentFile = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          TlsVerifyDisabled, FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] mistralai 2.4.6 dropper: Python interpreter executing /tmp/transformers.pyz as detached session

`UC_239_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.parent_process_name) as parent_process_name values(Processes.user) as user values(Processes.process_id) as pid from datamodel=Endpoint.Processes where Processes.process_name="python*" (Processes.process="*/tmp/transformers.pyz*" OR Processes.process="*/tmp/*.pyz*") by Processes.dest Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName matches regex @"^python[0-9.]*$"
| where ProcessCommandLine has "/tmp/transformers.pyz"
     or (ProcessCommandLine matches regex @"/tmp/[^\s]+\.pyz(\s|$)")
| extend ParentIsPython = InitiatingProcessFileName matches regex @"^python[0-9.]*$"
| project Timestamp, DeviceName, AccountName,
          ProcessCommandLine, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          ParentIsPython
| order by Timestamp desc
```

### [LLM] Outbound network connection to mistralai 2.4.6 dropper C2 (83.142.209.194)

`UC_239_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.bytes_in) as bytes_in values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="83.142.209.194" by All_Traffic.src All_Traffic.user All_Traffic.transport | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "83.142.209.194"
| project Timestamp, DeviceName, LocalIP, LocalPort,
          RemoteIP, RemotePort, RemoteUrl, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessFolderPath,
          InitiatingProcessParentFileName
| order by Timestamp asc
```

### [LLM] Drop of /tmp/transformers.pyz on Linux endpoint

`UC_239_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name values(Filesystem.user) as user values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_path="/tmp/transformers.pyz" OR (Filesystem.file_name="transformers.pyz" Filesystem.file_path="/tmp/*") by Filesystem.dest Filesystem.action | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FileName =~ "transformers.pyz"
| where FolderPath in~ ("/tmp", "/tmp/") or FolderPath startswith "/tmp/"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, FileSize,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName,
          FileOriginIP, FileOriginUrl
| order by Timestamp asc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-wx9m-wx4f-4cmg: Malicious dropper in mistralai 2.4.6 PyPI

`UC_239_2` · phase: **exploit** · confidence: **High**

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
