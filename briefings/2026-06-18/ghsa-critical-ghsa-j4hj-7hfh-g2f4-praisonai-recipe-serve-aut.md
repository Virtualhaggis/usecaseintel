# [CRIT] [GHSA / CRITICAL] GHSA-j4hj-7hfh-g2f4: praisonai: recipe serve auth middleware silently disables itself when no secret is set

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-j4hj-7hfh-g2f4

## Threat Profile

praisonai: recipe serve auth middleware silently disables itself when no secret is set

# praisonai: `recipe serve` authentication middleware silently disables itself when no secret is set

**Researcher:** Kai Aizen — SnailSploit (@SnailSploit), Adversarial & Offensive Security Research
**Target:** https://github.com/MervinPraison/PraisonAI

---

**Package:** `praisonai` on PyPI
**Version tested:** 4.6.48.
**File:** `praisonai/recipe/serve.py` (sha256 `491bf8f29e399418260810ba4bf0f6802c6e4aa6756…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `491bf8f29e399418260810ba4bf0f6802c6e4aa675628e2be68a9726c15d9b23`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1078** — Valid Accounts
- **T1059** — Command and Scripting Interpreter
- **T1505.003** — Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unauthenticated POST to PraisonAI /runs endpoint (recipe-serve auth bypass exploitation)

`UC_37_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_user_agent) as ua values(Web.status) as status from datamodel=Web where Web.http_method=POST (Web.url="*/runs*" OR Web.url="*/recipes*" OR Web.url="*/invoke*") (Web.status=200 OR Web.status=201 OR Web.status=202) by Web.dest Web.src Web.user Web.http_method
| `drop_dm_object_name(Web)`
| where user="-" OR isnull(user) OR user=""
| where dest_port=8000 OR dest_port=8080 OR match(url, "(?i)/runs($|\\?|/)")
| sort -firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","python","python3","uvicorn.exe","gunicorn")
| where InitiatingProcessCommandLine has_any ("praisonai","recipe serve","recipe/serve.py","recipe.serve")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalPort,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### PraisonAI recipe-serve Python process spawning shell/code-exec child (post-bypass RCE)

`UC_37_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd values(Processes.parent_process_name) as parent_name from datamodel=Endpoint.Processes where (Processes.parent_process="*praisonai*recipe*serve*" OR Processes.parent_process="*recipe/serve.py*" OR Processes.parent_process="*recipe.serve*" OR Processes.parent_process="*-m praisonai*") (Processes.process_name IN (sh,bash,dash,cmd.exe,powershell.exe,pwsh.exe,curl,curl.exe,wget,wget.exe,nc,nc.exe,ncat) OR Processes.process="*/bin/sh *" OR Processes.process="*-c *" OR Processes.process="*Invoke-Expression*" OR Processes.process="*IEX *") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| sort -firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","python","python3","uvicorn.exe","gunicorn")
| where InitiatingProcessCommandLine has_any ("praisonai","recipe serve","recipe/serve.py","recipe.serve","-m praisonai")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","curl.exe","curl","wget.exe","wget","nc.exe","ncat.exe","certutil.exe","bitsadmin.exe")
    or ProcessCommandLine has_any ("/bin/sh -c","/bin/bash -c","Invoke-Expression","IEX (","DownloadString","base64 -d","python -c")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-j4hj-7hfh-g2f4: praisonai: recipe serve auth middleware s

`UC_37_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-j4hj-7hfh-g2f4: praisonai: recipe serve auth middleware s ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("serve.py","poc.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("serve.py","poc.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-j4hj-7hfh-g2f4: praisonai: recipe serve auth middleware s
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("serve.py", "poc.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("serve.py", "poc.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `491bf8f29e399418260810ba4bf0f6802c6e4aa675628e2be68a9726c15d9b23`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
