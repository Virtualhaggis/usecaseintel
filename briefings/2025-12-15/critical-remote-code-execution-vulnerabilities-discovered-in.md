# [HIGH] Critical Remote Code Execution Vulnerabilities Discovered in React Server Components and Next.js

**Source:** StepSecurity
**Published:** 2025-12-15
**Article:** https://www.stepsecurity.io/blog/critical-remote-code-execution-vulnerabilities-discovered-in-react-server-components-and-next-js

## Threat Profile

Back to Blog Resources Critical Remote Code Execution Vulnerabilities Discovered in React Server Components and Next.js Security researchers have uncovered severe unauthenticated remote code execution vulnerabilities in React Server Components and Next.js App Router that achieve near 100% exploitation success rates. With 39% of cloud environments running vulnerable versions and 44% having publicly exposed Next.js instances, immediate patching is critical. Organizations should upgrade to patched …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-55182`
- **CVE:** `CVE-2025-66478`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059** — Command and Scripting Interpreter
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Node.js process downloads payload via curl/wget (React2Shell SNOWLIGHT/VShell deployment)

`UC_713_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node") AND Processes.process_name IN ("curl.exe","wget.exe","bitsadmin.exe","certutil.exe","powershell.exe","pwsh.exe","cmd.exe","bash.exe","sh.exe") AND (Processes.process="*http://*" OR Processes.process="*https://*" OR Processes.process="*ftp://*" OR Processes.process="*tftp://*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where FileName in~ ("curl.exe","wget.exe","bitsadmin.exe","certutil.exe","powershell.exe","pwsh.exe","cmd.exe","bash.exe","sh.exe")
| where ProcessCommandLine has_any ("http://","https://","ftp://","tftp://")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Vulnerable React Server Components or Next.js App Router versions present in inventory

`UC_713_4` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| inputlookup vulnerability_lookup where (cve="CVE-2025-55182" OR cve="CVE-2025-66478") OR (product="react" AND (version="19.0" OR version="19.0.0" OR version="19.1" OR version="19.1.0" OR version="19.1.1" OR version="19.2" OR version="19.2.0")) OR (product="next" AND (version="14.3.0-canary*" OR version="15.0.*" OR version="15.1.*" OR version="15.2.*" OR version="15.3.*" OR version="15.4.*" OR version="15.5.*" OR version="16.0.0" OR version="16.0.1" OR version="16.0.2" OR version="16.0.3" OR version="16.0.4" OR version="16.0.5" OR version="16.0.6")) | table host product version cve severity recommended_fix
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2025-55182","CVE-2025-66478")
| project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| union (
    DeviceTvmSoftwareInventory
    | where SoftwareName has_any ("react-server-dom-parcel","react-server-dom-webpack","react-server-dom-turbopack","react","next")
    | where (SoftwareName == "react" and SoftwareVersion has_any ("19.0.0","19.1.0","19.1.1","19.2.0"))
         or (SoftwareName startswith "react-server-dom-" and SoftwareVersion has_any ("19.0.0","19.1.0","19.1.1","19.2.0"))
         or (SoftwareName == "next" and (SoftwareVersion startswith "14.3.0-canary." or SoftwareVersion startswith "15.0." or SoftwareVersion startswith "15.1." or SoftwareVersion startswith "15.2." or SoftwareVersion startswith "15.3." or SoftwareVersion startswith "15.4." or SoftwareVersion startswith "15.5." or SoftwareVersion startswith "16.0."))
    | project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId="CVE-2025-55182/CVE-2025-66478", VulnerabilitySeverityLevel="Critical", RecommendedSecurityUpdate="Upgrade to React 19.0.1/19.1.2/19.2.1 or Next.js patched version per StepSecurity advisory"
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

### Article-specific behavioural hunt — Critical Remote Code Execution Vulnerabilities Discovered in React Server Compon

`UC_713_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Critical Remote Code Execution Vulnerabilities Discovered in React Server Compon ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Critical Remote Code Execution Vulnerabilities Discovered in React Server Compon
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-55182`, `CVE-2025-66478`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 5 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
