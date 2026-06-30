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
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable PraisonAI recipe-serve module (fail-open auth middleware) present on host

`UC_134_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash="491bf8f29e399418260810ba4bf0f6802c6e4aa675628e2be68a9726c15d9b23" OR Filesystem.file_path="*\\praisonai\\recipe\\serve.py" OR Filesystem.file_path="*/praisonai/recipe/serve.py") by Filesystem.dest Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "491bf8f29e399418260810ba4bf0f6802c6e4aa675628e2be68a9726c15d9b23"
    or (FileName =~ "serve.py" and FolderPath has @"\praisonai\recipe\")
    or (FileName =~ "serve.py" and FolderPath has "/praisonai/recipe/")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Unauthenticated POST to PraisonAI recipe-serve /runs execution endpoint

`UC_134_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/runs*" OR Web.uri_path="/runs") Web.http_method=POST by Web.src Web.dest Web.url Web.http_method Web.status Web.user | `drop_dm_object_name(Web)` | where user="-" OR user="" OR isnull(user) | convert ctime(firstTime) ctime(lastTime) | sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where InitiatingProcessCommandLine has "praisonai"
    or (InitiatingProcessCommandLine has "recipe" and InitiatingProcessCommandLine has "serve")
| where RemoteIPType == "Public"
| summarize Connections=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Ports=make_set(LocalPort)
          by DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Connections desc
```

### PraisonAI recipe-serve agent process spawning command/script interpreter (post-bypass RCE)

`UC_134_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="python.exe" OR Processes.parent_process_name="python3" OR Processes.parent_process_name="pythonw.exe" OR Processes.parent_process_name="uvicorn.exe") (Processes.parent_process="*praisonai*" OR (Processes.parent_process="*recipe*" AND Processes.parent_process="*serve*")) (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="bash" OR Processes.process_name="sh" OR Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("python.exe","python3.exe","python3","python","pythonw.exe","uvicorn.exe")
| where InitiatingProcessCommandLine has "praisonai"
    or (InitiatingProcessCommandLine has "recipe" and InitiatingProcessCommandLine has "serve")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","bash","sh","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-j4hj-7hfh-g2f4: praisonai: recipe serve auth middleware s

`UC_134_1` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: IOCs present, 5 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
