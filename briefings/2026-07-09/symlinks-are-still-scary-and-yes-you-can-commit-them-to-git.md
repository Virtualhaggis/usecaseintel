# [CRIT] Symlinks Are Still Scary (And Yes, You Can Commit Them to Git)

**Source:** Snyk
**Published:** 2026-07-09
**Article:** https://snyk.io/blog/symlinks-are-still-scary/

## Threat Profile

Snyk Blog In this article
Written by Randall Degges 
July 9, 2026
0 mins read Here's a genuinely unsettling way to lose control of your laptop in 2026. You clone a normal-looking repo, ask your AI coding assistant to "set it up," and it writes an attacker's SSH key into your ~/.ssh/authorized_keys -- without ever really telling you that's what it did. No memory corruption, no zero-day, nothing clever. Just a file in the repo that wasn't the file it claimed to be.
That attack is real, it's this w…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-12958`
- **CVE:** `CVE-2026-50549`
- **CVE:** `CVE-2024-32002`
- **CVE:** `CVE-2024-21626`
- **CVE:** `CVE-2021-32803`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SSH authorized_keys written by non-SSH tooling (symlink repo payload)

`UC_142_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*/.ssh/authorized_keys" Filesystem.action IN ("created","modified","renamed") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.action Filesystem.process_guid
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)` `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath endswith "/.ssh/authorized_keys" or (FileName == "authorized_keys" and FolderPath has "/.ssh")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName !in~ ("sshd","ssh","ssh-keygen","ssh-copy-id","cloud-init","useradd","adduser","ansible","puppet","chef-client","salt-minion")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Git-spawned hook execution during recursive clone (CVE-2024-32002)

`UC_142_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="git" OR Processes.parent_process_name="git.exe" OR Processes.parent_process_name="bash" OR Processes.parent_process_name="sh") (Processes.process_path="*/.git/hooks/*" OR Processes.process_path="*\\.git\\hooks\\*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process process_name=Processes.process_name Processes.process_path Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FolderPath has_any ("/.git/hooks/", "\\.git\\hooks\\")
| where InitiatingProcessFileName in~ ("git","git.exe","git-remote-https","git-remote-https.exe","bash","sh","dash")
| where InitiatingProcessCommandLine has_any ("clone","submodule","--recurse-submodules") or FolderPath has_any ("post-checkout","post-clone","post-update")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
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

### Article-specific behavioural hunt — Symlinks Are Still Scary (And Yes, You Can Commit Them to Git)

`UC_142_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Symlinks Are Still Scary (And Yes, You Can Commit Them to Git) ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_path="*/home/rdegges/.ssh/authorized_keys*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Symlinks Are Still Scary (And Yes, You Can Commit Them to Git)
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/passwd", "/home/rdegges/.ssh/authorized_keys"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-12958`, `CVE-2026-50549`, `CVE-2024-32002`, `CVE-2024-21626`, `CVE-2021-32803`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
