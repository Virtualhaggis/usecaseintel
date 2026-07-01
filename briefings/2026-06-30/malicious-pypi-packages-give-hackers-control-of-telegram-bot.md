# [HIGH] Malicious PyPI packages give hackers control of Telegram bot servers

**Source:** BleepingComputer
**Published:** 2026-06-30
**Article:** https://www.bleepingcomputer.com/news/security/malicious-pypi-packages-give-hackers-control-of-telegram-bot-servers/

## Threat Profile

Malicious PyPI packages give hackers control of Telegram bot servers 
By Bill Toulas 
June 30, 2026
05:02 PM
0 
A campaign active since last November has been targeting Python developers building Telegram bots with trojanized Pyrogram forks that allow attackers to read arbitrary files on compromised servers.
At least eight packages have been published on the Python Package Index (PyPI) with a hidden backdoor that is activated by helper modules when importing Pyrogram or when the bot starts.
Alth…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `tokowann.t.me`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Compromise Software Supply Chain
- **T1554** — Compromise Host Software Binary
- **T1059.004** — Unix Shell
- **T1059.006** — Python
- **T1552.001** — Credentials In Files
- **T1552** — Unsecured Credentials

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Operation Navy Ghost: pip install of trojanized Pyrogram fork packages

`UC_32_2` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*install*") AND (Processes.process IN ("*vlifegram*","*vlife-gram*","*kelragram*","*pyrogram-navy*","*pyrogram-styled*","*pyrogram-zeeb*","*pyrogram-kelra*","*sepgram*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("pip install", "pip3 install", "-m pip install", "pip download", "uv pip install", "poetry add")
| where ProcessCommandLine has_any ("vlifegram", "vlife-gram", "kelragram", "pyrogram-navy", "pyrogram-styled", "pyrogram-zeeb", "pyrogram-kelra", "sepgram")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Operation Navy Ghost: hidden secret.py backdoor dropped in Pyrogram helpers

`UC_32_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="secret.py" AND Filesystem.file_path="*pyrogram*helpers*" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName =~ "secret.py"
| where FolderPath has "pyrogram" and FolderPath has "helpers"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Operation Navy Ghost: Python bot spawning /bin/bash -c shell handler

`UC_32_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3","python3.10","python3.11","python3.12") AND Processes.process_name IN ("bash","sh","dash") AND Processes.process="*-c*" by Processes.dest Processes.user Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has "python"
| where FileName in~ ("bash", "sh", "dash")
| where ProcessCommandLine has "-c"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Operation Navy Ghost: bot harvesting /etc/passwd, .env and cloud credentials

`UC_32_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3","python3.10","python3.11","python3.12","bash","sh") AND (Processes.process IN ("*/etc/passwd*","*/etc/shadow*","*.aws/credentials*","*.env*","*printenv*","*/proc/self/environ*","*id_rsa*","*.docker/config.json*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("python", "bash", "sh", "dash")
| where ProcessCommandLine has_any ("/etc/passwd", "/etc/shadow", ".aws/credentials", "/proc/self/environ", "printenv", "os.environ", "id_rsa", ".docker/config.json", "/.env")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Article-specific behavioural hunt — Malicious PyPI packages give hackers control of Telegram bot servers

`UC_32_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Malicious PyPI packages give hackers control of Telegram bot servers ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("secret.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_name IN ("secret.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Malicious PyPI packages give hackers control of Telegram bot servers
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("secret.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/passwd") or FileName in~ ("secret.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `tokowann.t.me`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
