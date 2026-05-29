# [HIGH] Malicious MCP Server on npm postmark-mcp Harvests Emails

**Source:** Snyk
**Published:** 2025-09-25
**Article:** https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
September 25, 2025
0 mins read On September 25, 2025 , the npm package postmark-mcp , an MCP (Model Context Protocol) server intended to let AI assistants send emails via Postmark, was reportedly modified to secretly exfiltrate email contents by adding a blind-copy (BCC) to an external domain.
Current analysis suggests the behavior began around 1.0.16 and persisted in later versions. 
TL;DR If you have installed or used postmark-mcp since mid-Septe…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `giftshop.club`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1567** — Exfiltration Over Web Service
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Outbound email BCC'd to giftshop.club exfil domain (postmark-mcp backdoor)

`UC_746_3` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Email.src_user) as sender values(All_Email.subject) as subject from datamodel=Email.All_Email where All_Email.recipient="*@giftshop.club" OR All_Email.message_info="*giftshop.club*" by All_Email.src All_Email.recipient All_Email.message_id | `drop_dm_object_name(All_Email)`
```

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(30d)
| where RecipientEmailAddress endswith "@giftshop.club"
   or AdditionalFields has "giftshop.club"
| project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress, Subject, EmailDirection, DeliveryAction, DeliveryLocation, SenderIPv4
| order by Timestamp desc
```

### [LLM] DNS or HTTP egress to giftshop.club exfil domain

`UC_746_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as resolved_ip from datamodel=Network_Resolution.DNS where DNS.query="*giftshop.club" OR DNS.query="giftshop.club" by DNS.query DNS.src | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=true count from datamodel=Web.Web where Web.url="*giftshop.club*" by Web.src Web.url Web.http_user_agent | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
union
( DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has "giftshop.club"
  | project Timestamp, DeviceName, DeviceId, ActionType, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName
),
( DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | where AdditionalFields has "giftshop.club" or RemoteUrl has "giftshop.club"
  | project Timestamp, DeviceName, DeviceId, ActionType, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, AdditionalFields
)
| order by Timestamp desc
```

### [LLM] Installation or presence of malicious postmark-mcp npm package (v1.0.16+)

`UC_746_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*node_modules*postmark-mcp*" OR Filesystem.file_name="postmark-mcp") by Filesystem.dest Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | append [| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name IN ("npm","npm.cmd","npm.exe","yarn","yarn.cmd","pnpm","pnpm.exe") AND Processes.process="*postmark-mcp*" by Processes.dest Processes.user Processes.process | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
union
( DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FolderPath has @"\node_modules\postmark-mcp\" or FolderPath has "/node_modules/postmark-mcp/"
  | where FileName in~ ("index.js","package.json","package-lock.json")
  | project Timestamp, DeviceName, DeviceId, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
),
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where InitiatingProcessFileName in~ ("npm.exe","npm.cmd","node.exe","yarn.cmd","yarn.exe","pnpm.exe","npx.cmd","npx.exe")
     or FileName in~ ("npm.exe","npm.cmd","yarn.cmd","pnpm.exe","npx.cmd","npx.exe")
  | where ProcessCommandLine has "postmark-mcp" or InitiatingProcessCommandLine has "postmark-mcp"
  | project Timestamp, DeviceName, DeviceId, AccountName, ProcessCommandLine, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
)
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

### Article-specific behavioural hunt — Malicious MCP Server on npm postmark-mcp Harvests Emails

`UC_746_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Malicious MCP Server on npm postmark-mcp Harvests Emails ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_name IN ("index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Malicious MCP Server on npm postmark-mcp Harvests Emails
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/env") or FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `giftshop.club`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
