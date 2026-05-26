# [HIGH] 280+ Leaky Skills: How OpenClaw & ClawHub Are Exposing API Keys and PII

**Source:** Snyk
**Published:** 2026-02-05
**Article:** https://snyk.io/blog/openclaw-skills-credential-leaks-research/

## Threat Profile

Snyk Blog In this article
Written by Luca Beurer-Kellner 
Aleksei Kudrinskii 
Marco Milanta 
Kristian Bonde Nielsen 
Hemang Sarkar 
Liran Tal 
February 5, 2026
0 mins read On Monday, February 3rd, Snyk Staff Senior Engineer Luca Beurer-Kellner and Senior Incubation Engineer Hemang Sarkar uncovered a massive systemic vulnerability in the ClawHub ecosystem (clawhub.ai). Unlike the malware campaign we reported yesterday involving specific malicious actors, this new finding reveals a broader, perhap…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1059.004** — Unix Shell
- **T1552.001** — Credentials In Files
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1005** — Data from Local System
- **T1213** — Data from Information Repositories

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Installation of credential-leaking ClawHub skills (moltyverse-email, buy-anything, prompt-log, youtube-data)

`UC_462_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="npm.exe" OR Processes.process_name="node.exe" OR Processes.process_name="clawhub.exe" OR Processes.process_name="bash.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="powershell.exe") AND (Processes.process="*clawhub install moltyverse-email*" OR Processes.process="*clawhub install buy-anything*" OR Processes.process="*clawhub install prompt-log*" OR Processes.process="*clawhub install youtube-data*" OR Processes.process="*npm install -g clawhub*") by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "clawhub"
| where ProcessCommandLine has_any ("clawhub install moltyverse-email","clawhub install buy-anything","clawhub install prompt-log","clawhub install youtube-data","npm install -g clawhub")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] AI agent skill leaks Stripe key or card PAN/CVC verbatim in curl command line

`UC_462_1` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*api.stripe.com/v1/tokens*" OR Processes.process="*moltyverse.email/inbox*" OR Processes.process="*api.moltyverse.email*") AND (Processes.process="*card[number]=*" OR Processes.process="*card[cvc]=*" OR Processes.process="*pk_live_*" OR Processes.process="*sk_live_*") by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("api.stripe.com/v1/tokens","moltyverse.email/inbox","api.moltyverse.email")
| where ProcessCommandLine has_any ("card[number]=","card[cvc]=","pk_live_","sk_live_")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] AI session-log harvest via prompt-log extract.sh writing markdown with embedded secrets

`UC_462_2` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*extract.sh*" AND (Processes.process="*.codex/sessions*" OR Processes.process="*.claude/projects*" OR Processes.process="*.clawdbot/agents*" OR Processes.process="*.prompt-log*" OR Processes.process="*.jsonl*") by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let SessionAnchors = dynamic([".codex/sessions",".claude/projects",".clawdbot/agents",".jsonl",".prompt-log"]);
let ProcHits = DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "extract.sh"
| where ProcessCommandLine has_any (SessionAnchors)
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
let FileHits = DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath has ".prompt-log" and FileName endswith ".md"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
ProcHits
| union FileHits
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
