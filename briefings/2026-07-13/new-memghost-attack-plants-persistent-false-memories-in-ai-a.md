# [CRIT] New MemGhost Attack Plants Persistent False Memories in AI Agents Through One Email

**Source:** The Hacker News
**Published:** 2026-07-13
**Article:** https://thehackernews.com/2026/07/new-memghost-attack-plants-persistent.html

## Threat Profile

New MemGhost Attack Plants Persistent False Memories in AI Agents Through One Email 
 Swati Khandelwal  Jul 13, 2026 AI Security / Data Integrity 
Give an AI assistant a memory and access to your inbox, and you hand an attacker a way to rewrite what it thinks it knows about you. A single email can trick that agent into saving a false "fact" about the user, hide the change, and quietly steer its answers in later sessions.
When it works, the person reads an ordinary-looking reply and never learn…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-32711`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1565.001** — Data Manipulation: Stored Data Manipulation
- **T1566** — Phishing

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Writes to AI-agent persistent memory/instruction files (AGENTS.md, MEMORY.md) — MemGhost poisoning artifact

`UC_58_1` · phase: **install** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="MEMORY.md" OR Filesystem.file_name="AGENTS.md") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.process_id 
| `drop_dm_object_name(Filesystem)` 
| where user!="" AND NOT match(user,"\$$") 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileModified","FileCreated")
| where FileName in~ ("MEMORY.md","AGENTS.md")
| where InitiatingProcessAccountName !endswith "$"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Writes=count(), Paths=make_set(FolderPath,5)
    by DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName
| order by LastSeen desc
```

### Inbound email followed within minutes by agent memory-file write (MemGhost one-email chain)

`UC_58_2` · phase: **delivery** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_name="MEMORY.md" OR Filesystem.file_name="AGENTS.md") by _time Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path 
| `drop_dm_object_name(Filesystem)` 
| join type=inner user [ | tstats `summariesonly` min(_time) as mailTime from datamodel=Email.All_Email where All_Email.direction="inbound" by All_Email.recipient All_Email.src 
| `drop_dm_object_name(All_Email)` 
| rename recipient as user ] 
| where _time>=mailTime AND _time<=(mailTime+1800) 
| eval delay_min=round((_time-mailTime)/60,1) 
| table _time delay_min dest user file_name file_path src 
| sort - _time
```

**Defender KQL:**
```kql
let Window = 30m;
let Mail = EmailEvents
    | where Timestamp > ago(14d)
    | where EmailDirection == "Inbound"
    | project MailTime=Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, NetworkMessageId;
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileModified","FileCreated")
| where FileName in~ ("MEMORY.md","AGENTS.md")
| where InitiatingProcessAccountName !endswith "$"
| where isnotempty(InitiatingProcessAccountUpn)
| join kind=inner Mail on $left.InitiatingProcessAccountUpn == $right.RecipientEmailAddress
| where Timestamp between (MailTime .. MailTime + Window)
| project MailTime, WriteTime=Timestamp,
          DelayMin=datetime_diff('minute', Timestamp, MailTime),
          DeviceName, InitiatingProcessAccountUpn, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          SenderFromAddress, Subject, NetworkMessageId
| order by WriteTime desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-32711`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
