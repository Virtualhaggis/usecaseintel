# [CRIT] Snyk’s Fetch the Flag CTF is More Than Just a CTF

**Source:** Snyk
**Published:** 2025-02-20
**Article:** https://snyk.io/blog/snyks-fetch-the-flag-ctf/

## Threat Profile

Snyk Blog In this article
Written by John Hammond 
February 20, 2025
0 mins read Since 2023, Snyk has partnered with John Hammond to host ‘Fetch the Flag,’ a 12-hour CTF event for thousands of security professionals, practitioners, and members of the DevOps community!
Register for Fetch the Flag Snyk’s Annual Fetch the Flag CTF competition is on February 27 at 9 a.m. EST!
Register here But Capture the Flag sometimes gets a bad rap… with the occasional scrutiny that these exercises aren’t “real w…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-33891`
- **CVE:** `CVE-2022-24439`
- **CVE:** `CVE-2023-40267`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1105** — Ingress Tool Transfer
- **T1078.001** — Valid Accounts: Default Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Apache Spark UI doAs= shell command injection (CVE-2022-33891)

`UC_1002_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.dest_port IN (4040,7077,6066,8080,18080) OR Web.url="*spark*") by Web.src, Web.dest, Web.dest_port, Web.http_method, Web.url, Web.uri_query, Web.user_agent
| `drop_dm_object_name(Web)`
| where match(uri_query, "(?i)doAs=.*([`$;|&].*|%60|%24%28|%3B|%7C)") OR match(url, "(?i)doAs=.*([`$;|&]|%60|%24%28|%3B|%7C)")
| stats min(firstTime) as firstTime max(lastTime) as lastTime values(uri_query) as uri_query values(user_agent) as user_agent values(http_method) as http_method sum(count) as hits by src, dest, dest_port
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Defender lacks raw HTTP query telemetry; pivot to the Spark JVM shell-child evidence instead.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("java.exe","java","spark-class","spark-submit","spark-shell")
   or InitiatingProcessCommandLine has_any ("org.apache.spark","SparkSubmit","HistoryServer","Master")
| where FileName in~ ("bash","sh","dash","zsh","cmd.exe","powershell.exe","pwsh.exe","id","whoami","uname","curl","wget","nc","ncat")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          Parent=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine,
          Child=FileName, ChildCmd=ProcessCommandLine, SHA256
| order by Timestamp desc
```

### GitPython ext:: protocol RCE via crafted clone URL (CVE-2022-24439)

`UC_1002_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("git","git.exe") AND Processes.parent_process_name IN ("python","python3","python.exe","python3.exe","pytest","pytest.exe") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| where match(process, "(?i)ext::\s*(sh|bash|cmd|powershell|/bin/|c:\\\\)") OR match(parent_process, "(?i)ext::\s*(sh|bash|cmd|powershell|/bin/|c:\\\\)")
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("git","git.exe")
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","python","python3","pytest","pytest.exe")
     or InitiatingProcessCommandLine has_any ("gitpython","git.Repo","clone_from","GitPython")
| where ProcessCommandLine matches regex @"(?i)ext::\s*(sh|bash|cmd|powershell|/bin/|c:\\)"
     or ProcessCommandLine has "ext::sh"
     or ProcessCommandLine matches regex @"(?i)--upload-pack[= ].*[;|&`$].*"
| project Timestamp, DeviceName, AccountName,
          Parent=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine,
          Child=FileName, ChildCmd=ProcessCommandLine,
          GrandparentFile=InitiatingProcessParentFileName
| order by Timestamp desc
```

### Spark service user spawning post-exploit recon / download tools

`UC_1002_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.user IN ("spark","sparkuser","hadoop","yarn") AND Processes.process_name IN ("curl","wget","nc","ncat","socat","perl","python","python3","bash","sh","dash","chmod","base64","id","whoami","uname","hostname","ifconfig","ip") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| where parent_process_name IN ("java","spark-class","spark-submit","spark-shell","bash","sh")
| stats min(firstTime) as firstTime max(lastTime) as lastTime values(process) as cmds dc(process_name) as distinctTools count by dest, user, parent_process_name
| where distinctTools >= 2 OR count >= 3
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let SparkUsers = dynamic(["spark","sparkuser","hadoop","yarn"]);
let ReconTools = dynamic(["curl","wget","nc","ncat","socat","perl","python","python3","bash","sh","dash","chmod","base64","id","whoami","uname","hostname","ifconfig","ip"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName in~ (SparkUsers)
| where FileName in~ (ReconTools)
| where InitiatingProcessFileName has_any ("java","spark-class","spark-submit","spark-shell","bash","sh","dash")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), DistinctTools=dcount(FileName), Cmds=make_set(ProcessCommandLine, 25), Tools=make_set(FileName) by DeviceName, AccountName, InitiatingProcessFileName
| where DistinctTools >= 2
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-33891`, `CVE-2022-24439`, `CVE-2023-40267`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
