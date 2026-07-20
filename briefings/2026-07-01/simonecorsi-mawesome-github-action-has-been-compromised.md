# [HIGH] simonecorsi/mawesome GitHub Action has been compromised

**Source:** StepSecurity
**Published:** 2026-07-01
**Article:** https://www.stepsecurity.io/blog/simonecorsi-mawesome-github-action-has-been-compromised

## Threat Profile

Back to Blog Threat Intel simonecorsi/mawesome GitHub Action has been compromised On June 24, 2026, an attacker compromised the simonecorsi/mawesome GitHub repository. They force-pushed malicious commits and repointed several version tags to that commit. As a result, any workflow running against those tags after that time executed the attacker's code inside its GitHub Actions runner. Varun Sharma View LinkedIn June 24, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `9f93d77d32833a515bc406c46da477142bb1ac2babeecb6aa42f98669a6db015`
- **SHA1:** `5792aba0e2180b9b80b77644370a6889d5817456`
- **SHA1:** `bcb6b1d409144318e8fad2171d6fe06d02299d1a`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1059** — Command and Scripting Interpreter
- **T1003.007** — OS Credential Dumping: Proc Filesystem
- **T1552** — Unsecured Credentials
- **T1567** — Exfiltration Over Web Service
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Compromised simonecorsi/mawesome GitHub Action payload by known hash

`UC_198_1` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("9f93d77d32833a515bc406c46da477142bb1ac2babeecb6aa42f98669a6db015","5792aba0e2180b9b80b77644370a6889d5817456","bcb6b1d409144318e8fad2171d6fe06d02299d1a") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badSHA256 = dynamic(["9f93d77d32833a515bc406c46da477142bb1ac2babeecb6aa42f98669a6db015"]);
let badSHA1 = dynamic(["5792aba0e2180b9b80b77644370a6889d5817456","bcb6b1d409144318e8fad2171d6fe06d02299d1a"]);
union DeviceProcessEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in (badSHA256) or SHA1 in (badSHA1) or InitiatingProcessSHA256 in (badSHA256) or InitiatingProcessSHA1 in (badSHA1)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Runner.Worker process memory scrape via /proc on self-hosted GitHub Actions runner

`UC_198_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="Runner.Worker" Processes.process="*/proc/*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where match(process,"(?i)/proc/[0-9a-z]+/(maps|mem)") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has "Runner.Worker"
| where ProcessCommandLine has "/proc/" and ProcessCommandLine has_any ("maps","mem")
| where FileName in~ ("python3","python","node","perl","ruby","sh","bash","cat","dd","gcore")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### First-seen external egress from GitHub Actions Runner.Worker child process

`UC_198_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` earliest(_time) as firstSeen count from datamodel=Network_Traffic.All_Traffic where Network_Traffic.process_name IN ("curl","wget","python3","python","node","bash","sh") NOT (Network_Traffic.dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8")) by Network_Traffic.src Network_Traffic.dest Network_Traffic.dest_port Network_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | convert ctime(firstSeen)
```

**Defender KQL:**
```kql
let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where InitiatingProcessParentFileName has "Runner.Worker"
    | summarize by RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessParentFileName has "Runner.Worker"
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("curl","wget","python3","python","node","sh","bash")
| join kind=leftanti Baseline on RemoteUrl
| project Timestamp, DeviceName, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9f93d77d32833a515bc406c46da477142bb1ac2babeecb6aa42f98669a6db015`, `5792aba0e2180b9b80b77644370a6889d5817456`, `bcb6b1d409144318e8fad2171d6fe06d02299d1a`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
