# [CRIT] [GHSA / CRITICAL] GHSA-4mpj-78p6-rj59: Duplicate Advisory: PickleScan's profile.run blocklist mismatch allows exec() bypass

**Source:** GitHub Security Advisories
**Published:** 2026-06-17
**Article:** https://github.com/advisories/GHSA-4mpj-78p6-rj59

## Threat Profile

Duplicate Advisory: PickleScan's profile.run blocklist mismatch allows exec() bypass

## Duplicate Advisory

This advisory has been withdrawn because it is a duplicate of GHSA-7wx9-6375-f5wh. This link is maintained to preserve external references.

## Original Description
picklescan before 1.0.4 contains an incomplete blocklist for the profile module that fails to block the module-level profile.run() function, allowing attackers to achieve arbitrary code execution via exec(). Attackers can craf…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1588.006** — Obtain Capabilities: Vulnerabilities
- **T1027** — Obfuscated Files or Information
- **T1059.006** — Command and Scripting Interpreter: Python

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable picklescan (<1.0.4 / CVE-2025-1889) present in software inventory

`UC_60_0` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities where (Vulnerabilities.cve="CVE-2025-1889" OR Vulnerabilities.signature="*picklescan*") by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.category 
| `drop_dm_object_name(Vulnerabilities)` 
| where like(signature,"%picklescan%") OR cve="CVE-2025-1889" 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// CVE-2025-1889 — picklescan <1.0.4 misses module-level profile.run() — exec() bypass
let VulnByCve = DeviceTvmSoftwareVulnerabilities
    | where Timestamp > ago(7d)
    | where CveId =~ "CVE-2025-1889"
    | project Timestamp, DeviceId, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate;
let VulnByVersion = DeviceTvmSoftwareInventory
    | where Timestamp > ago(7d)
    | where SoftwareName has "picklescan"
    | extend Parts = split(SoftwareVersion, ".")
    | extend Major = toint(Parts[0]), Minor = toint(Parts[1]), Patch = toint(Parts[2])
    | where Major < 1 or (Major == 1 and Minor == 0 and Patch < 4)
    | project Timestamp, DeviceId, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, CveId="CVE-2025-1889", VulnerabilitySeverityLevel="Critical", RecommendedSecurityUpdate="Upgrade picklescan to >=1.0.4";
union VulnByCve, VulnByVersion
| summarize arg_max(Timestamp, *) by DeviceId, SoftwareName, SoftwareVersion
| order by Timestamp desc
```

### Python deserialising a pickle/model file spawns shell or LOLBin (CVE-2025-1889 exec() outcome)

`UC_60_1` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process) as parent_process values(Processes.process) as process from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","pythonw.exe","python3.exe","python3.11.exe","python3.12.exe") AND (Processes.parent_process="*.pkl*" OR Processes.parent_process="*.pickle*" OR Processes.parent_process="*.pt*" OR Processes.parent_process="*.ckpt*" OR Processes.parent_process="*.safetensors*" OR Processes.parent_process="*pickle.load*" OR Processes.parent_process="*torch.load*" OR Processes.parent_process="*joblib.load*")) AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bash.exe","sh.exe","wsl.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe") AND NOT Processes.user="*$" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// CVE-2025-1889 — exec() outcome from a profile.run() pickle that cleared picklescan <1.0.4
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","python3.exe","python3.11.exe","python3.12.exe","python3.13.exe")
| where InitiatingProcessCommandLine has_any (".pkl",".pickle",".pt",".ckpt",".safetensors","pickle.load","torch.load","joblib.load","profile.run")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bash.exe","sh.exe","wsl.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
