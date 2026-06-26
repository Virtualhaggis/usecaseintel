# [HIGH] How “Clinejection” Turned an AI Bot into a Supply Chain Attack

**Source:** Snyk
**Published:** 2026-02-19
**Article:** https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/

## Threat Profile

Snyk Blog In this article
Written by Stephen Thoemmes 
February 19, 2026
0 mins read On February 9, 2026, security researcher Adnan Khan publicly disclosed a vulnerability chain (dubbed "Clinejection") in the Cline repository that turned the popular AI coding tool's own issue triage bot into a supply chain attack vector. Eight days later, an unknown actor exploited the same flaw to publish an unauthorized version of the Cline CLI to npm , installing the OpenClaw AI agent on every developer machi…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `attacker.oastify.com`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546** — Event Triggered Execution
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1059** — Command and Scripting Interpreter
- **T1546.016** — Event Triggered Execution: Installer Packages

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Installation of unauthorized cline@2.3.0 npm package on developer endpoints

`UC_545_2` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*cline@2.3.0*" OR Processes.parent_process="*cline@2.3.0*") (Processes.process_name IN ("npm.exe","npm.cmd","node.exe","yarn.exe","pnpm.exe","pnpm.cmd","npx.exe","npx.cmd") OR Processes.parent_process_name IN ("npm.exe","npm.cmd","node.exe","yarn.exe","pnpm.exe","pnpm.cmd")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where NOT match(user,"\\$$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(90d)
| where ProcessCommandLine has "cline@2.3.0" or InitiatingProcessCommandLine has "cline@2.3.0"
| where FileName in~ ("npm.exe","npm.cmd","node.exe","yarn.exe","pnpm.exe","pnpm.cmd","npx.exe","npx.cmd")
    or InitiatingProcessFileName in~ ("npm.exe","npm.cmd","node.exe","yarn.exe","pnpm.exe","pnpm.cmd","cmd.exe","powershell.exe","pwsh.exe","bash.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Secondary payload install: 'npm install -g openclaw' postinstall hook execution

`UC_545_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*openclaw*" (Processes.process_name IN ("npm.exe","npm.cmd","node.exe","yarn.exe","pnpm.exe","pnpm.cmd","npx.exe","npx.cmd") OR Processes.parent_process_name IN ("npm.exe","npm.cmd","node.exe","yarn.exe","pnpm.exe","pnpm.cmd")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where NOT match(user,"\\$$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let ProcSig = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has "openclaw" or InitiatingProcessCommandLine has "openclaw"
    | where FileName in~ ("npm.exe","npm.cmd","node.exe","yarn.exe","pnpm.exe","pnpm.cmd","npx.exe","npx.cmd")
        or InitiatingProcessFileName in~ ("npm.exe","npm.cmd","node.exe","yarn.exe","pnpm.exe","pnpm.cmd","cmd.exe","powershell.exe","pwsh.exe","bash.exe")
    | where AccountName !endswith "$"
    | project Timestamp, DeviceName, AccountName, Source="Process", Detail=ProcessCommandLine, Parent=InitiatingProcessFileName;
let FileSig = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has @"\node_modules\openclaw"
    | where InitiatingProcessAccountName !endswith "$"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source="FileDrop", Detail=FolderPath, Parent=InitiatingProcessFileName;
union ProcSig, FileSig
| order by Timestamp desc
```

### Outbound traffic to *.oastify.com (BurpSuite Collaborator) from corporate endpoint

`UC_545_4` · phase: **exfiltration** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*.oastify.com" OR DNS.query="*.burpcollaborator.net") by DNS.src DNS.query | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host="*.oastify.com" OR All_Traffic.dest_host="*.burpcollaborator.net") by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)`]
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl endswith "oastify.com" or RemoteUrl endswith "burpcollaborator.net"
    or RemoteUrl has ".oastify.com/" or RemoteUrl has ".burpcollaborator.net/"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### npm install referencing GitHub commit SHA (github:owner/repo#sha) — dangling-commit supply chain hunt

`UC_545_5` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.exe","npm.cmd","node.exe","yarn.exe","pnpm.exe","pnpm.cmd","npx.exe","npx.cmd") OR Processes.parent_process_name IN ("npm.exe","npm.cmd","node.exe","yarn.exe","pnpm.exe","pnpm.cmd")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | regex process="(?i)github:[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+#[A-Fa-f0-9]{6,40}" | where NOT match(user,"\\$$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine matches regex @"(?i)github:[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+#[A-Fa-f0-9]{6,40}"
    or InitiatingProcessCommandLine matches regex @"(?i)github:[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+#[A-Fa-f0-9]{6,40}"
| where FileName in~ ("npm.exe","npm.cmd","node.exe","yarn.exe","pnpm.exe","pnpm.cmd","npx.exe","npx.cmd")
    or InitiatingProcessFileName in~ ("npm.exe","npm.cmd","node.exe","yarn.exe","pnpm.exe","pnpm.cmd")
| where AccountName !endswith "$"
| extend GitRef = extract(@"(?i)(github:[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+#[A-Fa-f0-9]{6,40})", 1, strcat(ProcessCommandLine, " ", InitiatingProcessCommandLine))
| project Timestamp, DeviceName, AccountName, FileName, GitRef, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `attacker.oastify.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
