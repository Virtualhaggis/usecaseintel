# [HIGH] Malicious remote code execution backdoor discovered in the popular bootstrap-sass Ruby gem

**Source:** Snyk
**Published:** 2019-04-04
**Article:** https://snyk.io/blog/malicious-remote-code-execution-backdoor-discovered-in-the-popular-bootstrap-sass-ruby-gem/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
April 4, 2019
0 mins read On March 26, 2019, a malicious version of the popular bootstrap-sass package, that has been downloaded a total of 28 million times to date, was published to the official RubyGems repository. Version 3.2.0.3 includes a stealthy backdoor that gives attackers remote command execution on server-side Rails applications.
We have already added the vulnerability to our database, and if your project is being monitored by Snyk, you …

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `366d6162fe36fc81dadc114558b43c6c8890c8bcc7e90e2949ae6344d0785dc0`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1505.003** — Web Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Malicious bootstrap-sass 3.2.0.3 gem implant on disk (middleware.rb backdoor / SHA256)

`UC_3528_1` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash="366d6162fe36fc81dadc114558b43c6c8890c8bcc7e90e2949ae6344d0785dc0" OR (Filesystem.file_path="*bootstrap-sass-3.2.0.3*" AND Filesystem.file_path="*active-controller*middleware.rb")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "366d6162fe36fc81dadc114558b43c6c8890c8bcc7e90e2949ae6344d0785dc0"
   or (FolderPath has "bootstrap-sass-3.2.0.3" and FolderPath has "active-controller" and FileName =~ "middleware.rb")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### bootstrap-sass RCE trigger: base64 Ruby payload smuggled in ___cfduid cookie

`UC_3528_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web.Web where Web.http_method=* by Web.src Web.dest Web.url Web.cookie _time
| `drop_dm_object_name(Web)`
| where match(cookie, "___cfduid=")
| rex field=cookie "___cfduid=(?<cfduid>[^;]+)"
| eval cfstd=replace(replace(cfduid,"-","+"),"_","/")
| eval decoded=base64decode(cfstd)
| where match(decoded, "(?i)(system|eval|exec|`|IO\.|open\(|Net::|%x|spawn|Kernel|/bin/)")
| table _time src dest url cfduid decoded
```

### Rails/Ruby app worker (puma/unicorn/passenger) spawning a shell — post-eval RCE

`UC_3528_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("ruby","puma","unicorn","passenger","rails","bundle") AND Processes.process_name IN ("sh","bash","dash","zsh","ksh","python","python3","perl","nc","ncat","curl","wget")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("ruby","puma","unicorn","passenger","rails","bundle")
| where FileName in~ ("sh","bash","dash","zsh","ksh","python","python3","perl","nc","ncat","curl","wget")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `366d6162fe36fc81dadc114558b43c6c8890c8bcc7e90e2949ae6344d0785dc0`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
