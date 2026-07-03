# [HIGH] Fetch the Flag CTF 2022 writeup: Treasure Trove

**Source:** Snyk
**Published:** 2022-11-10
**Article:** https://snyk.io/blog/fetch-the-flag-ctf-2022-writeup-treasure-trove/

## Threat Profile

Snyk Blog In this article
Written by Assaf Ben Josef 
November 10, 2022
0 mins read Thanks for playing Fetch with us! Congrats to the thousands of players who joined us for Fetch the Flag CTF . And a huge thanks to the Snykers that built, tested, and wrote up the challenges! 
In this post, we’ll take a look at how our team tackled the pay-attention challenge of Snyk’s 2022 Fetch the Flag CTF. This challenge simulates a case where a popular package has likely been hijacked and turned malicious — …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `pay-attention.c.ctf-snyk.io`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Python interpreter relaunching itself to execute a NamedTemporaryFile stager

`UC_1884_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","pythonw.exe","python3.exe","python3") AND Processes.process_name IN ("python.exe","pythonw.exe","python3.exe","python3") AND (Processes.process="*\\Temp\\tmp*" OR Processes.process="*/tmp/tmp*")) by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process_id | `drop_dm_object_name(Processes)` | search NOT process IN ("*multiprocessing*","*spawn_main*","*resource_tracker*","*-m pip*","*setuptools*","*pyinstaller*") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","python3.exe")
| where FileName in~ ("python.exe","pythonw.exe","python3.exe")
| where ProcessCommandLine has_any (@"\Temp\", "/tmp/")
| where ProcessCommandLine matches regex @"(?i)(\\Temp\\|/tmp/)tmp[a-z0-9_]{4,}"
| where not(ProcessCommandLine has_any ("multiprocessing","spawn_main","resource_tracker","-m pip","setuptools","_pytest","pyinstaller"))
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCommandLine, InitiatingProcessFolderPath, FolderPath, SHA256
| order by Timestamp desc
```

### Python child-of-python making download-and-exec egress to non-PyPI host

`UC_1884_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where (Network_Resolution.query="pay-attention.c.ctf-snyk.io" OR Network_Resolution.query="*.ctf-snyk.io") by Network_Resolution.src Network_Resolution.query Network_Resolution.answer | `drop_dm_object_name(Network_Resolution)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","python3.exe")
| where InitiatingProcessParentFileName in~ ("python.exe","pythonw.exe","python3.exe")
| where RemoteIPType == "Public"
| where isnotempty(RemoteUrl)
| where not(RemoteUrl has_any ("pypi.org","pythonhosted.org","python.org","anaconda.com","anaconda.org","pypi.python.org"))
| extend KnownStagerIOC = iff(RemoteUrl has "pay-attention.c.ctf-snyk.io", "yes", "no")
| summarize FirstSeen=min(Timestamp), Connections=count(), Urls=make_set(RemoteUrl, 25) by DeviceName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, KnownStagerIOC
| order by KnownStagerIOC desc, FirstSeen desc
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

### Article-specific behavioural hunt — Fetch the Flag CTF 2022 writeup: Treasure Trove

`UC_1884_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Fetch the Flag CTF 2022 writeup: Treasure Trove ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("fixtures.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("fixtures.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Fetch the Flag CTF 2022 writeup: Treasure Trove
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("fixtures.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("fixtures.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `pay-attention.c.ctf-snyk.io`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
