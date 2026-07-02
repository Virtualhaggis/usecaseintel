# [HIGH] OpenClaw: risks for the users and how to mitigate them

**Source:** Securelist (Kaspersky)
**Published:** 2026-07-01
**Article:** https://securelist.com/openclaw-security/120484/

## Threat Profile

Table of Contents
OpenClaw skills 
OpenClaw vulnerabilities 
Malicious skills 
Authors
Kaspersky 
OpenClaw, which was previously known as Clawdbot and Moltbot, is today one of the most successful and fast‑growing ecosystems for AI agents, recognized worldwide. The project quickly became popular with users because of its flexibility and ability to solve fairly complex tasks that previously required a lot of time for automation and execution. A dedicated marketplace appeared quickly after the proj…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1567** — Exfiltration Over Web Service
- **T1102.002** — Web Service: Bidirectional Communication
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### OpenClaw agent runtime exfiltrating to Telegram Bot API

`UC_33_1` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="api.telegram.org" OR DNS.query="*.telegram.org" OR DNS.query="t.me") by DNS.src DNS.query DNS.dest
| `drop_dm_object_name(DNS)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "api.telegram.org" or RemoteUrl has "t.me"
| where InitiatingProcessFileName in~ ("node.exe","python.exe","pythonw.exe","deno.exe","bun.exe","curl.exe","powershell.exe","pwsh.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### OpenClaw agent runtime spawning shell to harvest credential/token files

`UC_33_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","python.exe","pythonw.exe","deno.exe","bun.exe")) AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","curl.exe")) AND (Processes.process="*.env*" OR Processes.process="*credentials*" OR Processes.process="*id_rsa*" OR Processes.process="*.ssh*" OR Processes.process="*.npmrc*" OR Processes.process="*ANTHROPIC_API_KEY*" OR Processes.process="*OPENAI_API_KEY*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| search user!="*$"
| sort - count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","python.exe","pythonw.exe","deno.exe","bun.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wsl.exe","curl.exe")
| where ProcessCommandLine has_any (".env","credentials","id_rsa",".ssh",".npmrc","ANTHROPIC_API_KEY","OPENAI_API_KEY","TELEGRAM_BOT_TOKEN")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
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


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
