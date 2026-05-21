# [HIGH] Max-severity flaw in ChromaDB for AI apps allows server hijacking

**Source:** BleepingComputer
**Published:** 2026-05-19
**Article:** https://www.bleepingcomputer.com/news/security/max-severity-flaw-in-chromadb-for-ai-apps-allows-server-hijacking/

## Threat Profile

Max-severity flaw in ChromaDB for AI apps allows server hijacking 
By Bill Toulas 
May 19, 2026
06:25 PM
0 
A max-severity vulnerability in the latest Python FastAPI version of the ChromaDB project allows unauthenticated attackers to run arbitrary code on exposed servers.
The flaw is tracked as CVE-2026-45829 and was reported to ChromaDB on February 17. It received the maximum severity score from HiddenLayer, the company that discovered it.
ChromaDB is an open-source vector database and AI retri…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45829`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059** — Command and Scripting Interpreter
- **T1059.006** — Python
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Suspicious child process spawned by ChromaDB / uvicorn Python worker

`UC_40_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime, values(Processes.process) as child_cmd, values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","python3.exe","pythonw.exe","uvicorn.exe") AND Processes.parent_process IN ("*chromadb*","*chroma_db*","*uvicorn*")) AND (Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","bash.exe","sh.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","mshta.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe")) by host, user, Processes.parent_process_name, Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "pythonw.exe", "uvicorn.exe")
| where InitiatingProcessCommandLine has_any ("chromadb", "chroma_db", "uvicorn")
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "bash.exe", "sh.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "curl.exe", "wget.exe", "certutil.exe", "bitsadmin.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ParentImage = InitiatingProcessFolderPath, ParentCmd = InitiatingProcessCommandLine, ChildImage = FolderPath, ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] ChromaDB Python worker contacts Hugging Face for first time on host (CVE-2026-45829 model fetch)

`UC_40_2` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime, values(All_Traffic.dest) as dest, values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("python.exe","python3.exe","pythonw.exe","uvicorn.exe") AND All_Traffic.dest IN ("*huggingface.co","*hf.co") by host, All_Traffic.app, All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime), ctime(lastTime) | where firstTime > relative_time(now(), "-1d")
```

**Defender KQL:**
```kql
let LookbackDays = 30d;
let RecentHours = 24h;
let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(LookbackDays) .. ago(RecentHours))
    | where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "pythonw.exe", "uvicorn.exe")
    | where RemoteUrl has_any ("huggingface.co", "hf.co")
    | summarize by DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(RecentHours)
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "pythonw.exe", "uvicorn.exe")
| where InitiatingProcessCommandLine has_any ("chromadb", "chroma_db", "uvicorn")
| where RemoteUrl has_any ("huggingface.co", "hf.co")
| join kind=leftanti Baseline on DeviceName
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-45829`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
