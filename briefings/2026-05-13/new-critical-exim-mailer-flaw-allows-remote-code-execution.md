# [HIGH] New critical Exim mailer flaw allows remote code execution

**Source:** BleepingComputer
**Published:** 2026-05-13
**Article:** https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/

## Threat Profile

New critical Exim mailer flaw allows remote code execution 
By Bill Toulas 
May 13, 2026
04:23 PM
0 
A critical vulnerability affecting certain configurations of the Exim open-source mail transfer agent could be exploited by an unauthenticated remote attacker to execute arbitrary code.
Identified as CVE-2026-45185 , the security issue impacts some Exim versions before 4.99.3 that use the default GNU Transport Layer Security (GnuTLS) library for secure communication. It is a user-after-free (UAF)…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45185`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1203** — Exploitation for Client Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Exim MTA spawns shell/network LOLBin — post-exploit RCE indicator for CVE-2026-45185 (Dead.Letter)

`UC_23_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("exim","exim4") OR Processes.parent_process_exec IN ("/usr/sbin/exim","/usr/sbin/exim4","/usr/exim/bin/exim")) AND Processes.process_name IN ("sh","bash","dash","zsh","ksh","python","python2","python3","perl","ruby","php","node","wget","curl","nc","ncat","netcat","socat","openssl","base64","whoami","id","uname","hostname","chmod","chown","tar","ssh","ssh-keygen") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
// CVE-2026-45185 (Dead.Letter) — Exim parent → shell/LOLBin child on Linux
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("exim","exim4") or InitiatingProcessFolderPath endswith "/exim" or InitiatingProcessFolderPath endswith "/exim4"
| where FileName in~ (
    "sh","bash","dash","zsh","ksh",
    "python","python2","python3","perl","ruby","php","node",
    "wget","curl","nc","ncat","netcat","socat","openssl","base64",
    "whoami","id","uname","hostname","chmod","chown","tar","ssh","ssh-keygen")
// Known-good Exim pipe-transport deliveries — drop in your org's allowlist here
| where FileName !in~ ("procmail","dovecot-lda","sendmail")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] Inventory: Linux hosts running Exim 4.97-4.99.2 with GnuTLS (CVE-2026-45185 exposure)

`UC_23_2` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2026-45185" by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.vendor_product Vulnerabilities.url | `drop_dm_object_name(Vulnerabilities)` | rename dest as host | sort - severity
```

**Defender KQL:**
```kql
// Hosts vulnerable to CVE-2026-45185 (Dead.Letter — Exim BDAT/GnuTLS UAF)
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2026-45185"
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform, OSDistribution, IsInternetFacing, PublicIP) by DeviceId
  ) on DeviceId
| project DeviceName, OSPlatform, OSDistribution, IsInternetFacing, PublicIP,
          SoftwareVendor, SoftwareName, SoftwareVersion,
          VulnerabilitySeverityLevel, RecommendedSecurityUpdate, RecommendedSecurityUpdateId
| order by IsInternetFacing desc, DeviceName asc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-45185`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
