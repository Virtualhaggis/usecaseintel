# [CRIT] [GHSA / CRITICAL] GHSA-29w3-p9w9-wc47: PraisonAI: Arbitrary File Read/Write via `multiedit` Tool Without Path Validation

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-29w3-p9w9-wc47

## Threat Profile

PraisonAI: Arbitrary File Read/Write via `multiedit` Tool Without Path Validation

## Summary

The `multiedit` tool in `src/praisonai/praisonai/tools/multiedit.py` allows LLM-controlled arbitrary file read and write without any path validation, workspace boundary check, or protected path guard. This enables an attacker who can influence agent tool arguments (via crafted prompts, user input in chat bots, or malicious YAML workflow configs) to read sensitive files (e.g., `/etc/shadow`, `~/.ssh/id_…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
- **T1190** — Exploit Public-Facing Application
- **T1059.006** — Command and Scripting Interpreter: Python

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI multiedit arbitrary write to SSH/shell/cloud-cred files by python process

`UC_87_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.action IN ("created","modified","write")) (Filesystem.file_path="*/.ssh/authorized_keys" OR Filesystem.file_path="*/.bashrc" OR Filesystem.file_path="*/.bash_profile" OR Filesystem.file_path="*/.profile" OR Filesystem.file_path="*/.zshrc" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.ssh/id_rsa" OR Filesystem.file_name=".env") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.action | `drop_dm_object_name(Filesystem)` | search process_name=*python* | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName has "python" or InitiatingProcessCommandLine has_any ("praisonai","multiedit")
| where (FileName =~ "authorized_keys" and FolderPath has "/.ssh/")
     or FileName in~ (".bashrc",".bash_profile",".profile",".zshrc",".bash_aliases")
     or (FileName =~ "credentials" and FolderPath has "/.aws/")
     or FileName =~ ".env"
     or (FileName in~ ("id_rsa","id_ed25519","authorized_keys") and FolderPath has "/.ssh/")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, ActionType, SHA256
| order by Timestamp desc
```

### PraisonAI multiedit secret-file read (/etc/shadow, id_rsa, .aws/credentials, .env) by python

`UC_87_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.action IN ("read","accessed","open")) (Filesystem.file_path="/etc/shadow" OR Filesystem.file_path="*/.ssh/id_rsa" OR Filesystem.file_path="*/.ssh/id_ed25519" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_name=".env") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.action | `drop_dm_object_name(Filesystem)` | search process_name=*python* | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

### Vulnerable PraisonAI install/upgrade activity (verify version >= 4.6.61)

`UC_87_3` · phase: **weapon** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*praisonai*") (Processes.process="*install*" OR Processes.process="*upgrade*" OR Processes.process="* add *") (Processes.process_name IN ("pip","pip3","python","python3","uv","poetry")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("pip","pip3","python","python3","uv","poetry")
| where ProcessCommandLine has "praisonai"
| where ProcessCommandLine has_any ("install","upgrade","-U"," add ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-29w3-p9w9-wc47: PraisonAI: Arbitrary File Read/Write via

`UC_87_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-29w3-p9w9-wc47: PraisonAI: Arbitrary File Read/Write via ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("file_tools.py","edit_tools.py","skill_tools.py","write_file.py","read_file.py","apply_diff.py","search_replace.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/shadow*" OR Filesystem.file_path="*/etc/hostname*" OR Filesystem.file_path="*/tmp/victim_file.txt*" OR Filesystem.file_name IN ("file_tools.py","edit_tools.py","skill_tools.py","write_file.py","read_file.py","apply_diff.py","search_replace.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-29w3-p9w9-wc47: PraisonAI: Arbitrary File Read/Write via
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("file_tools.py", "edit_tools.py", "skill_tools.py", "write_file.py", "read_file.py", "apply_diff.py", "search_replace.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/shadow", "/etc/hostname", "/tmp/victim_file.txt") or FileName in~ ("file_tools.py", "edit_tools.py", "skill_tools.py", "write_file.py", "read_file.py", "apply_diff.py", "search_replace.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
